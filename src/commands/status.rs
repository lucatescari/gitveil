use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::thread;

use colored::Colorize;

use crate::constants::{ENCRYPTED_FILE_HEADER, ENCRYPTED_FILE_HEADER_LEN};
use crate::error::GitVeilError;

/// Display the encryption status of tracked files.
///
/// Performance: uses only 3 subprocesses regardless of repo size:
/// 1. `git ls-files` — list all tracked files
/// 2. `git check-attr -z --stdin` — batch-check filter attributes
/// 3. `git cat-file --batch` — batch-check blob headers for encryption
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

    if git_crypt_files.is_empty() {
        return Ok(());
    }

    // Batch check which blobs are actually encrypted (single subprocess)
    let encrypted_flags = batch_check_blobs_encrypted(&git_crypt_files)?;

    let mut files_to_fix = Vec::new();

    for (file, is_encrypted) in git_crypt_files.iter().zip(encrypted_flags.iter()) {
        if *is_encrypted {
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
        eprintln!(
            "{} {} file(s)...",
            "Fixing".cyan().bold(),
            files_to_fix.len()
        );
        for file in &files_to_fix {
            let status = Command::new("git")
                .args(["add", "--", file])
                .status()
                .map_err(|e| GitVeilError::Git(format!("failed to stage {}: {}", file, e)))?;

            if !status.success() {
                eprintln!("{} failed to stage {}", "warning:".yellow().bold(), file);
            }
        }
        eprintln!(
            "{} Run '{}' to save the re-encrypted files.",
            "Done.".green().bold(),
            "git commit".bold()
        );
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

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| GitVeilError::Git("failed to open check-attr stdin".into()))?;

    // Write paths on a separate thread to avoid pipe deadlock when the
    // number of files is large enough to overflow the OS pipe buffer.
    let paths: Vec<String> = files.iter().map(|f| f.to_string()).collect();
    let writer_thread = thread::spawn(move || {
        let mut stdin = stdin;
        for file in &paths {
            if write!(stdin, "{}\0", file).is_err() {
                break;
            }
        }
    });

    let output = child
        .wait_with_output()
        .map_err(|e| GitVeilError::Git(format!("failed to wait for git check-attr: {}", e)))?;

    let _ = writer_thread.join();

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

/// Batch-check whether blobs in the index are encrypted using a single
/// `git cat-file --batch` subprocess instead of spawning one per file.
///
/// The cat-file batch protocol:
///   Input:  `:<path>\n` (index entry for path)
///   Output: `<sha> blob <size>\n<content>\n`  — or `:<path> missing\n`
///
/// We only need the first 10 bytes of each blob to check for the
/// `\0GITCRYPT\0` header. Remaining blob bytes are drained to `io::sink()`
/// so large files don't consume memory.
fn batch_check_blobs_encrypted(files: &[String]) -> Result<Vec<bool>, GitVeilError> {
    let mut child = Command::new("git")
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| GitVeilError::Git(format!("failed to run git cat-file --batch: {}", e)))?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| GitVeilError::Git("failed to open cat-file stdin".into()))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| GitVeilError::Git("failed to open cat-file stdout".into()))?;

    // Write queries on a separate thread to avoid pipe deadlock.
    // If we wrote all queries before reading, the stdout pipe could fill up
    // (e.g. large blobs), blocking cat-file, which in turn blocks our writes.
    let queries: Vec<String> = files.iter().map(|f| format!(":{}", f)).collect();
    let writer_thread = thread::spawn(move || {
        let mut stdin = stdin;
        for query in &queries {
            if writeln!(stdin, "{}", query).is_err() {
                break;
            }
        }
        // stdin is dropped here, signaling EOF to cat-file
    });

    let mut reader = BufReader::new(stdout);
    let mut results = Vec::with_capacity(files.len());

    for _ in files {
        // Read the response header line: "<sha> blob <size>\n" or ":<path> missing\n"
        let mut header_line = String::new();
        reader
            .read_line(&mut header_line)
            .map_err(|e| GitVeilError::Git(format!("failed to read cat-file header: {}", e)))?;

        let header_line = header_line.trim_end_matches('\n');

        if header_line.ends_with(" missing") {
            // File not in index
            results.push(false);
            continue;
        }

        // Parse "<sha> blob <size>"
        let size: usize = header_line
            .rsplit_once(' ')
            .and_then(|(_, s)| s.parse().ok())
            .ok_or_else(|| {
                GitVeilError::Git(format!("unexpected cat-file header: {}", header_line))
            })?;

        if size < ENCRYPTED_FILE_HEADER_LEN {
            // Too small to contain the header — not encrypted
            // Drain the content + trailing newline
            drain_bytes(&mut reader, size + 1)?;
            results.push(false);
            continue;
        }

        // Read just the header bytes we need
        let mut header_buf = [0u8; ENCRYPTED_FILE_HEADER_LEN];
        reader
            .read_exact(&mut header_buf)
            .map_err(|e| GitVeilError::Git(format!("failed to read blob header: {}", e)))?;

        let is_encrypted = header_buf == ENCRYPTED_FILE_HEADER;

        // Drain the remaining blob bytes + trailing newline
        let remaining = size - ENCRYPTED_FILE_HEADER_LEN + 1;
        drain_bytes(&mut reader, remaining)?;

        results.push(is_encrypted);
    }

    // Wait for the writer thread to finish
    let _ = writer_thread.join();

    // Wait for cat-file to exit
    let _ = child.wait();

    Ok(results)
}

/// Drain `count` bytes from a reader by copying to sink.
/// Avoids allocating a buffer for large blobs.
fn drain_bytes(reader: &mut impl Read, count: usize) -> Result<(), GitVeilError> {
    std::io::copy(&mut reader.take(count as u64), &mut std::io::sink())
        .map_err(|e| GitVeilError::Git(format!("failed to drain cat-file output: {}", e)))?;
    Ok(())
}
