use std::io::{self, BufRead, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use colored::Colorize;

use crate::error::GitVeilError;
use crate::gpg::operations::get_gpg_program;

/// Information about a GPG public key file.
pub struct GpgKeyInfo {
    /// Path to the key file on disk.
    pub path: std::path::PathBuf,
    /// User ID string (e.g., "Alice Mueller <alice@company.com>").
    pub uid: String,
    /// Key fingerprint (hex string).
    pub fingerprint: String,
}

/// Scan a directory for GPG public key files (.asc, .gpg, .pub, .key)
/// and return metadata for each valid key found.
pub fn scan_key_directory(dir: &Path) -> Result<Vec<GpgKeyInfo>, GitVeilError> {
    if !dir.is_dir() {
        return Err(GitVeilError::Other(format!(
            "'{}' is not a directory",
            dir.display()
        )));
    }

    let mut keys = Vec::new();
    scan_dir_recursive(dir, &mut keys)?;

    if keys.is_empty() {
        return Err(GitVeilError::Gpg(format!(
            "no GPG public key files found in '{}'",
            dir.display()
        )));
    }

    Ok(keys)
}

/// Preview a single key file without importing it.
/// Returns key info if the file contains a valid GPG public key.
pub fn preview_key_file(path: &Path) -> Result<GpgKeyInfo, GitVeilError> {
    let gpg = get_gpg_program();

    let output = Command::new(&gpg)
        .args(["--with-colons", "--import-options", "show-only", "--import"])
        .arg(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| GitVeilError::Gpg(format!("failed to run {}: {}", gpg, e)))?;

    if !output.status.success() {
        return Err(GitVeilError::Gpg(format!(
            "not a valid GPG key file: {}",
            path.display()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut uid = String::new();
    let mut fingerprint = String::new();

    for line in stdout.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.is_empty() {
            continue;
        }
        // First uid line we find
        if uid.is_empty() && parts[0] == "uid" && parts.len() > 9 {
            uid = parts[9].to_string();
        }
        // First fingerprint line we find
        if fingerprint.is_empty() && parts[0] == "fpr" && parts.len() > 9 {
            fingerprint = parts[9].to_string();
        }
    }

    if fingerprint.is_empty() {
        return Err(GitVeilError::Gpg(format!(
            "no fingerprint found in key file: {}",
            path.display()
        )));
    }

    if uid.is_empty() {
        uid = "(no UID)".to_string();
    }

    Ok(GpgKeyInfo {
        path: path.to_path_buf(),
        uid,
        fingerprint,
    })
}

/// Import a GPG public key from a file into the local keyring.
/// Returns the fingerprint of the imported key.
pub fn import_key_file(path: &Path) -> Result<String, GitVeilError> {
    let gpg = get_gpg_program();

    let output = Command::new(&gpg)
        .args(["--batch", "--import"])
        .arg(path)
        .output()
        .map_err(|e| GitVeilError::Gpg(format!("failed to run {}: {}", gpg, e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GitVeilError::Gpg(format!(
            "failed to import GPG key from '{}': {}",
            path.display(),
            stderr
        )));
    }

    // Get the fingerprint of the imported key
    let info = preview_key_file(path)?;
    Ok(info.fingerprint)
}

/// Display an interactive picker for GPG keys and return the selected ones.
/// User enters comma-separated numbers (e.g., "1,3") or "all".
pub fn pick_keys(keys: &[GpgKeyInfo]) -> Result<Vec<usize>, GitVeilError> {
    let stderr = io::stderr();
    let mut out = stderr.lock();

    writeln!(out).ok();
    writeln!(
        out,
        "  {} GPG public keys found:\n",
        keys.len().to_string().cyan().bold()
    )
    .ok();

    for (i, key) in keys.iter().enumerate() {
        let num = format!("  {:>3})", i + 1).cyan().bold();
        let uid = key.uid.bold();
        let fp_short = if key.fingerprint.len() >= 16 {
            &key.fingerprint[..16]
        } else {
            &key.fingerprint
        };
        let fp = format!("({}...)", fp_short).dimmed();
        let file = key
            .path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default()
            .dimmed();
        writeln!(out, "{}  {}  {}  {}", num, uid, fp, file).ok();
    }

    writeln!(out).ok();
    write!(
        out,
        "  {} ",
        "Select user(s) [1-N, comma-separated, or 'all']:".yellow()
    )
    .ok();
    out.flush().ok();

    let stdin = io::stdin();
    let mut input = String::new();
    stdin
        .lock()
        .read_line(&mut input)
        .map_err(|e| GitVeilError::Other(format!("failed to read input: {}", e)))?;

    let input = input.trim();

    if input.eq_ignore_ascii_case("all") {
        return Ok((0..keys.len()).collect());
    }

    let mut selected = Vec::new();
    for part in input.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let n: usize = part
            .parse()
            .map_err(|_| GitVeilError::Other(format!("invalid selection: '{}'", part)))?;
        if n == 0 || n > keys.len() {
            return Err(GitVeilError::Other(format!(
                "selection {} out of range (1-{})",
                n,
                keys.len()
            )));
        }
        selected.push(n - 1);
    }

    if selected.is_empty() {
        return Err(GitVeilError::Other("no keys selected".into()));
    }

    Ok(selected)
}

/// Recursively scan a directory for GPG key files.
fn scan_dir_recursive(dir: &Path, keys: &mut Vec<GpgKeyInfo>) -> Result<(), GitVeilError> {
    let entries = std::fs::read_dir(dir)?;

    for entry in entries.filter_map(|e| e.ok()) {
        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        let path = entry.path();

        if ft.is_dir() {
            scan_dir_recursive(&path, keys)?;
        } else if ft.is_file() && is_key_file_extension(&path) {
            match preview_key_file(&path) {
                Ok(info) => keys.push(info),
                Err(_) => continue, // Skip files that aren't valid GPG keys
            }
        }
    }

    Ok(())
}

/// Check if a file has a GPG key file extension.
fn is_key_file_extension(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("asc" | "gpg" | "pub" | "key")
    )
}
