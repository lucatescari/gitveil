use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

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

    // Validate all fingerprints are hex-only and of expected length
    for fp in &fingerprints {
        validate_fingerprint(fp)?;
    }

    Ok(fingerprints)
}

/// Validate that a GPG fingerprint is a hex string of expected length.
/// Prevents path traversal and command injection via crafted fingerprints.
pub fn validate_fingerprint(fingerprint: &str) -> Result<(), GitVeilError> {
    if !fingerprint.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(GitVeilError::Gpg(format!(
            "invalid fingerprint (non-hex characters): {}",
            fingerprint
        )));
    }
    // SHA-1 fingerprints are 40 chars, SHA-256 are 64 chars
    if fingerprint.len() < 40 || fingerprint.len() > 64 {
        return Err(GitVeilError::Gpg(format!(
            "invalid fingerprint length ({} chars, expected 40-64): {}",
            fingerprint.len(),
            fingerprint
        )));
    }
    Ok(())
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

    cmd.args(["-e", "-r", &format!("0x{}", fingerprint), "-o"]);
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

/// Build the gpg command line for decrypting a single file.
///
/// This intentionally does NOT pass `--batch`: decrypting a collaborator's
/// key requires the user's private GPG key, which is often passphrase-
/// protected. With `--batch`, gpg-agent refuses to launch pinentry and
/// decryption fails with "Inappropriate ioctl for device". Matching
/// git-crypt's behavior, the caller is responsible for connecting stdin
/// and stderr to the user's terminal so pinentry can prompt.
fn build_decrypt_command(gpg: &str, path: &Path) -> Command {
    let mut cmd = Command::new(gpg);
    cmd.args(["--yes", "-q", "-d"]);
    cmd.arg(path);
    cmd
}

/// Decrypt a GPG-encrypted file and return the plaintext.
///
/// Mirrors git-crypt: stdin and stderr are inherited from the parent so
/// pinentry (terminal or graphical) can prompt the user for a passphrase
/// when the secret key is protected. Stdout is piped so the decrypted
/// bytes can be collected.
///
/// The returned buffer is wrapped in `Zeroizing` to ensure key material
/// is scrubbed from memory when dropped.
pub fn gpg_decrypt_from_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, GitVeilError> {
    let gpg = get_gpg_program();
    let mut cmd = build_decrypt_command(&gpg, path);
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    let mut child = cmd
        .spawn()
        .map_err(|e| GitVeilError::Gpg(format!("failed to run {}: {}", gpg, e)))?;

    let mut buf = Vec::new();
    if let Some(mut stdout) = child.stdout.take() {
        stdout
            .read_to_end(&mut buf)
            .map_err(|e| GitVeilError::Gpg(format!("failed to read gpg stdout: {}", e)))?;
    }

    let status = child
        .wait()
        .map_err(|e| GitVeilError::Gpg(format!("failed to wait for gpg: {}", e)))?;

    if !status.success() {
        return Err(GitVeilError::Gpg(format!(
            "gpg decryption failed for {}",
            path.display()
        )));
    }

    Ok(Zeroizing::new(buf))
}

/// List the primary fingerprints of all secret keys in the local GPG keyring.
///
/// Used by `unlock` to skip `.gpg` files we obviously cannot decrypt, so
/// pinentry only fires once (for our own key) and gpg doesn't spam stderr
/// with "no secret key" messages for every other collaborator.
pub fn gpg_list_secret_key_fingerprints() -> Result<Vec<String>, GitVeilError> {
    let gpg = get_gpg_program();

    let output = Command::new(&gpg)
        .args(["--batch", "--with-colons", "--list-secret-keys"])
        .output()
        .map_err(|e| GitVeilError::Gpg(format!("failed to run {}: {}", gpg, e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GitVeilError::Gpg(format!(
            "gpg --list-secret-keys failed: {}",
            stderr.trim()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut fingerprints = Vec::new();
    // Colon-format primary fingerprints follow a `sec:` record; subkey
    // fingerprints follow `ssb:`. We only want primaries because
    // `add-gpg-user` stores collaborator files keyed by primary fingerprint.
    let mut expect_primary_fpr = false;

    for line in stdout.lines() {
        if line.starts_with("sec:") {
            expect_primary_fpr = true;
        } else if line.starts_with("ssb:") {
            expect_primary_fpr = false;
        } else if expect_primary_fpr && line.starts_with("fpr:") {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() > 9 {
                let fp = parts[9].to_string();
                if validate_fingerprint(&fp).is_ok() {
                    fingerprints.push(fp);
                }
            }
            expect_primary_fpr = false;
        }
    }

    Ok(fingerprints)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypt_command_does_not_use_batch() {
        let cmd = build_decrypt_command("gpg", Path::new("dummy.gpg"));
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert!(
            !args.iter().any(|a| a == "--batch"),
            "decrypt must not use --batch (it suppresses the pinentry passphrase prompt). Args: {:?}",
            args,
        );
    }

    #[test]
    fn decrypt_command_includes_decrypt_and_path() {
        let cmd = build_decrypt_command("gpg", Path::new("some/file.gpg"));
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert!(
            args.iter().any(|a| a == "-d" || a == "--decrypt"),
            "decrypt must request decryption. Args: {:?}",
            args,
        );
        assert!(
            args.iter().any(|a| a.ends_with("file.gpg")),
            "decrypt must include the file path. Args: {:?}",
            args,
        );
    }
}
