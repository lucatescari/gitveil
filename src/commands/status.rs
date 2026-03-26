use std::io::Write;
use std::process::{Command, Stdio};

use colored::Colorize;

use crate::constants::ENCRYPTED_FILE_HEADER;
use crate::error::GitVeilError;

/// Display the encryption status of tracked files.
/// Uses `git check-attr -z --stdin` to batch-check all files in a single subprocess,
/// with NUL-delimited output to avoid ambiguity with special filenames.
pub fn status(encrypted_only: bool, unencrypted_only: bool, fix: bool) -> Result<(), GitVeilError> {
    // Get all tracked files
    let ls_output = Command::new("git")
        .args(["ls-files"])
        .output()
        .map_err(|e| GitVeilError::Git(format!("failed to run git ls-files: {}", e)))?;

    if !ls_output.status.success() {
        return Err(GitVeilError::Git("git ls-files failed".into()));
    }

    let all_files_str = String::from_utf8_lossy(&ls_output.stdout);
    let all_files: Vec<&str> = all_files_str.lines().filter(|l| !l.is_empty()).collect();

    if all_files.is_empty() {
        return Ok(());
    }

    // Batch check attributes using -z --stdin (NUL-delimited, single subprocess)
    let git_crypt_files = get_git_crypt_files(&all_files)?;

    let mut files_to_fix = Vec::new();

    for file in &git_crypt_files {
        // Check if the blob in the index is actually encrypted
        let is_encrypted = check_blob_encrypted(file)?;

        if is_encrypted {
            if !unencrypted_only {
                println!("  {} {}", "encrypted:".green(), file);
            }
        } else {
            if !encrypted_only {
                println!("{} {}", "not encrypted:".yellow(), file);
            }
            if fix {
                files_to_fix.push(file.clone());
            }
        }
    }

    if fix && !files_to_fix.is_empty() {
        eprintln!("{} {} file(s)...", "Fixing".cyan().bold(), files_to_fix.len());
        for file in &files_to_fix {
            let status = Command::new("git")
                .args(["add", "--", file])
                .status()
                .map_err(|e| GitVeilError::Git(format!("failed to stage {}: {}", file, e)))?;

            if !status.success() {
                eprintln!("{} failed to stage {}", "warning:".yellow().bold(), file);
            }
        }
        eprintln!("{} Run '{}' to save the re-encrypted files.", "Done.".green().bold(), "git commit".bold());
    }

    Ok(())
}

/// Batch-check which files have a git-crypt filter attribute.
/// Uses NUL-delimited output (-z) to handle filenames with special characters.
fn get_git_crypt_files(files: &[&str]) -> Result<Vec<String>, GitVeilError> {
    let mut child = Command::new("git")
        .args(["check-attr", "-z", "filter", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| GitVeilError::Git(format!("failed to run git check-attr: {}", e)))?;

    if let Some(ref mut stdin) = child.stdin {
        for file in files {
            writeln!(stdin, "{}", file).map_err(|e| {
                GitVeilError::Git(format!("failed to write to git check-attr stdin: {}", e))
            })?;
        }
    }
    drop(child.stdin.take());

    let output = child
        .wait_with_output()
        .map_err(|e| GitVeilError::Git(format!("failed to wait for git check-attr: {}", e)))?;

    if !output.status.success() {
        return Err(GitVeilError::Git("git check-attr -z --stdin failed".into()));
    }

    // NUL-delimited output format: path\0attr\0value\0 (repeating triplets)
    let fields: Vec<&[u8]> = output.stdout.split(|&b| b == 0).collect();
    let mut result = Vec::new();

    // Process in triplets: (path, attribute_name, value)
    let mut i = 0;
    while i + 2 < fields.len() {
        let path = String::from_utf8_lossy(fields[i]);
        let value = String::from_utf8_lossy(fields[i + 2]);

        if value.starts_with("git-crypt") {
            result.push(path.to_string());
        }

        i += 3;
    }

    Ok(result)
}

/// Check if a file's blob in the git index starts with the encrypted file header.
fn check_blob_encrypted(file: &str) -> Result<bool, GitVeilError> {
    let output = Command::new("git")
        .args(["show", &format!(":{}", file)])
        .output()
        .map_err(|e| GitVeilError::Git(format!("failed to read blob: {}", e)))?;

    if !output.status.success() {
        // File might not be staged yet
        return Ok(false);
    }

    Ok(output.stdout.starts_with(ENCRYPTED_FILE_HEADER))
}
