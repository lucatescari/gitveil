use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::error::GitVeilError;
use crate::git::config::get_git_config;

/// Get the GPG program to use (respects git config gpg.program).
pub fn get_gpg_program() -> String {
    get_git_config("gpg.program")
        .ok()
        .flatten()
        .unwrap_or_else(|| "gpg".to_string())
}

/// Get the fingerprint(s) for a GPG user ID.
pub fn gpg_get_fingerprints(user_id: &str) -> Result<Vec<String>, GitVeilError> {
    let gpg = get_gpg_program();

    let output = Command::new(&gpg)
        .args([
            "--with-colons",
            "--fingerprint",
            "--batch",
            "--list-keys",
            user_id,
        ])
        .output()
        .map_err(|e| GitVeilError::Gpg(format!("failed to run {}: {}", gpg, e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GitVeilError::Gpg(format!(
            "gpg --list-keys failed for '{}': {}",
            user_id, stderr
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut fingerprints = Vec::new();

    for line in stdout.lines() {
        if line.starts_with("fpr:") {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() > 9 {
                fingerprints.push(parts[9].to_string());
            }
        }
    }

    if fingerprints.is_empty() {
        return Err(GitVeilError::Gpg(format!(
            "no fingerprints found for '{}'",
            user_id
        )));
    }

    Ok(fingerprints)
}

/// Encrypt data to a GPG recipient and write to a file.
pub fn gpg_encrypt_to_file(
    data: &[u8],
    fingerprint: &str,
    output_path: &Path,
    trusted: bool,
) -> Result<(), GitVeilError> {
    let gpg = get_gpg_program();

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut cmd = Command::new(&gpg);
    cmd.args(["--batch", "--yes"]);

    if trusted {
        cmd.args(["--trust-model", "always"]);
    }

    cmd.args([
        "-e",
        "-r",
        &format!("0x{}", fingerprint),
        "-o",
    ]);
    cmd.arg(output_path);
    cmd.stdin(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| GitVeilError::Gpg(format!("failed to run {}: {}", gpg, e)))?;

    if let Some(ref mut stdin) = child.stdin {
        stdin
            .write_all(data)
            .map_err(|e| GitVeilError::Gpg(format!("failed to write to gpg stdin: {}", e)))?;
    }

    let status = child
        .wait()
        .map_err(|e| GitVeilError::Gpg(format!("failed to wait for gpg: {}", e)))?;

    if !status.success() {
        return Err(GitVeilError::Gpg(format!(
            "gpg encryption failed for fingerprint {}",
            fingerprint
        )));
    }

    Ok(())
}

/// Decrypt a GPG-encrypted file and return the plaintext.
pub fn gpg_decrypt_from_file(path: &Path) -> Result<Vec<u8>, GitVeilError> {
    let gpg = get_gpg_program();

    let output = Command::new(&gpg)
        .args(["--batch", "--yes", "-q", "-d"])
        .arg(path)
        .output()
        .map_err(|e| GitVeilError::Gpg(format!("failed to run {}: {}", gpg, e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GitVeilError::Gpg(format!(
            "gpg decryption failed for {}: {}",
            path.display(),
            stderr
        )));
    }

    Ok(output.stdout)
}
