use std::process::Command;

use crate::constants::ENCRYPTED_FILE_HEADER;
use crate::error::GitVeilError;

/// Display the encryption status of tracked files.
pub fn status(encrypted_only: bool, unencrypted_only: bool, fix: bool) -> Result<(), GitVeilError> {
    // Get all tracked files
    let output = Command::new("git")
        .args(["ls-files"])
        .output()
        .map_err(|e| GitVeilError::Git(format!("failed to run git ls-files: {}", e)))?;

    if !output.status.success() {
        return Err(GitVeilError::Git("git ls-files failed".into()));
    }

    let all_files = String::from_utf8_lossy(&output.stdout);
    let mut files_to_fix = Vec::new();

    for file in all_files.lines() {
        if file.is_empty() {
            continue;
        }

        // Check if this file has a git-crypt filter attribute
        let attr_output = Command::new("git")
            .args(["check-attr", "filter", "--", file])
            .output()
            .map_err(|e| GitVeilError::Git(format!("failed to check attributes: {}", e)))?;

        if !attr_output.status.success() {
            continue;
        }

        let attr_str = String::from_utf8_lossy(&attr_output.stdout);
        let should_encrypt = attr_str.contains("git-crypt");

        if !should_encrypt {
            continue;
        }

        // Check if the blob in the index is actually encrypted
        let is_encrypted = check_blob_encrypted(file)?;

        if is_encrypted {
            if !unencrypted_only {
                println!("    encrypted: {}", file);
            }
        } else {
            if !encrypted_only {
                println!("not encrypted: {}", file);
            }
            if fix {
                files_to_fix.push(file.to_string());
            }
        }
    }

    if fix && !files_to_fix.is_empty() {
        eprintln!("Fixing {} file(s)...", files_to_fix.len());
        for file in &files_to_fix {
            let status = Command::new("git")
                .args(["add", "--", file])
                .status()
                .map_err(|e| GitVeilError::Git(format!("failed to stage {}: {}", file, e)))?;

            if !status.success() {
                eprintln!("Warning: failed to stage {}", file);
            }
        }
        eprintln!("Done. Run 'git commit' to save the re-encrypted files.");
    }

    Ok(())
}

/// Check if a file's blob in the git index starts with the encrypted file header.
fn check_blob_encrypted(file: &str) -> Result<bool, GitVeilError> {
    let output = Command::new("git")
        .args(["show", &format!(":{}", file)])
        .output()
        .map_err(|e| GitVeilError::Git(format!("failed to read blob for {}: {}", file, e)))?;

    if !output.status.success() {
        // File might not be staged yet
        return Ok(false);
    }

    Ok(output.stdout.starts_with(ENCRYPTED_FILE_HEADER))
}
