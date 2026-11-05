use std::io::{self, BufRead, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use colored::Colorize;

use crate::error::GitVeilError;
use crate::gpg::display::sanitize_for_display;
use crate::gpg::operations::{get_gpg_program, validate_fingerprint};

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
        .args([
            "--batch",
            "--with-colons",
            "--import-options",
            "show-only",
            "--import",
            "--",
        ])
        .arg(path)
        .stdin(Stdio::null())
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
    let mut info = parse_key_info(&stdout)
        .map_err(|e| GitVeilError::Gpg(format!("{} in key file: {}", e, path.display())))?;
    info.path = path.to_path_buf();
    Ok(info)
}

/// Parse `gpg --with-colons` key listing output into a [`GpgKeyInfo`].
///
/// Split out from the subprocess call so the parsing — including fingerprint
/// validation — is testable without invoking gpg. `path` is left empty; the
/// caller fills it in.
fn parse_key_info(colon_output: &str) -> Result<GpgKeyInfo, GitVeilError> {
    // `gpg --import` imports *every* key in a file, so a file holding more
    // than one key would add keys the user never saw in the preview. Only
    // single-key files are accepted.
    let primary_count = colon_output
        .lines()
        .filter(|l| l.starts_with("pub:") || l.starts_with("sec:"))
        .count();
    if primary_count > 1 {
        return Err(GitVeilError::Gpg(format!(
            "file contains {} keys; only one key per file is supported",
            primary_count
        )));
    }

    let mut uid = String::new();
    // The fingerprint is the primary key's — the `fpr` record directly
    // after `pub`/`sec` — never a subkey's.
    let mut primary_fpr: Option<String> = None;
    let mut expect_primary_fpr = false;

    for line in colon_output.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        match parts[0] {
            "pub" | "sec" => expect_primary_fpr = true,
            "fpr" => {
                if expect_primary_fpr && primary_fpr.is_none() && parts.len() > 9 {
                    primary_fpr = Some(parts[9].to_string());
                }
                expect_primary_fpr = false;
            }
            "grp" => {}
            "uid" => {
                if uid.is_empty() && parts.len() > 9 {
                    uid = parts[9].to_string();
                }
                expect_primary_fpr = false;
            }
            _ => expect_primary_fpr = false,
        }
    }

    let fingerprint = match primary_fpr {
        Some(fp) if !fp.is_empty() => fp,
        _ => return Err(GitVeilError::Gpg("no fingerprint found".into())),
    };

    // This fingerprint becomes a path component (`<fingerprint>.gpg`) and a
    // gpg recipient argument. Every other fingerprint in the codebase is
    // validated at its source; this one arrives via key-file parsing, so it
    // is held to the same rule.
    validate_fingerprint(&fingerprint)?;

    if uid.is_empty() {
        uid = "(no UID)".to_string();
    }

    Ok(GpgKeyInfo {
        path: std::path::PathBuf::new(),
        uid,
        fingerprint,
    })
}

/// Import the single GPG public key previewed from `path` into the local
/// keyring.
///
/// `expected_fingerprint` is the fingerprint the user was shown (from
/// [`preview_key_file`]). The import is minimal (no third-party signatures)
/// and gpg's `IMPORT_OK` status lines are checked so that nothing other
/// than that key was imported — the file could hold more keys than the
/// preview showed, or have changed since it was previewed. Any unexpected
/// key the import newly added is deleted again and the import fails.
pub fn import_key_file(path: &Path, expected_fingerprint: &str) -> Result<(), GitVeilError> {
    let gpg = get_gpg_program();

    let output = Command::new(&gpg)
        .args([
            "--batch",
            "--status-fd",
            "1",
            "--import-options",
            "import-minimal",
            "--import",
            "--",
        ])
        .arg(path)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| GitVeilError::Gpg(format!("failed to run {}: {}", gpg, e)))?;

    let status = String::from_utf8_lossy(&output.stdout);
    let imported = parse_import_ok(&status);

    let unexpected: Vec<&(u32, String)> = imported
        .iter()
        .filter(|(_, fp)| !fp.eq_ignore_ascii_case(expected_fingerprint))
        .collect();

    if !unexpected.is_empty() {
        // Roll back keys this import newly added (reason bit 0x01). Keys
        // that were already in the keyring are left alone.
        for (reason, fp) in &unexpected {
            if reason & 0x01 != 0 && validate_fingerprint(fp).is_ok() {
                let _ = Command::new(&gpg)
                    .args(["--batch", "--yes", "--delete-keys", "--"])
                    .arg(fp)
                    .stdin(Stdio::null())
                    .output();
            }
        }
        return Err(GitVeilError::Gpg(format!(
            "'{}' imported keys other than the previewed key {}; refusing",
            path.display(),
            expected_fingerprint
        )));
    }

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GitVeilError::Gpg(format!(
            "failed to import GPG key from '{}': {}",
            path.display(),
            sanitize_for_display(stderr.trim())
        )));
    }

    if imported.is_empty() {
        return Err(GitVeilError::Gpg(format!(
            "gpg did not import key {} from '{}'",
            expected_fingerprint,
            path.display()
        )));
    }

    Ok(())
}

/// Parse `[GNUPG:] IMPORT_OK <reason> <fingerprint>` status lines.
fn parse_import_ok(status: &str) -> Vec<(u32, String)> {
    status
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("[GNUPG:] IMPORT_OK ")?;
            let mut fields = rest.split_whitespace();
            let reason = fields.next()?.parse().ok()?;
            let fp = fields.next()?.to_string();
            Some((reason, fp))
        })
        .collect()
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
        let uid = sanitize_for_display(&key.uid).bold();
        let fp_short = if key.fingerprint.len() >= 16 {
            &key.fingerprint[..16]
        } else {
            &key.fingerprint
        };
        let fp = format!("({}...)", fp_short).dimmed();
        let file = sanitize_for_display(
            &key.path
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_default(),
        )
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
/// Symlinks are skipped to prevent symlink-based attacks (see CLAUDE.md security policy).
fn scan_dir_recursive(dir: &Path, keys: &mut Vec<GpgKeyInfo>) -> Result<(), GitVeilError> {
    let entries = std::fs::read_dir(dir)?;

    for entry in entries.filter_map(|e| e.ok()) {
        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };

        // Skip symlinks (security: prevent following malicious symlinks)
        if ft.is_symlink() {
            continue;
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_OUTPUT: &str = "\
pub:-:3072:1:ABCDEF0123456789:1700000000:::-:::scESC::::::23::0:
fpr:::::::::AAAABBBBCCCCDDDDEEEEFFFF00001111222233334444:
uid:::::::::Alice Mueller <alice@example.test>:
";

    #[test]
    fn parses_uid_and_fingerprint() {
        let info = parse_key_info(REAL_OUTPUT).unwrap();
        assert_eq!(
            info.fingerprint,
            "AAAABBBBCCCCDDDDEEEEFFFF00001111222233334444"
        );
        assert_eq!(info.uid, "Alice Mueller <alice@example.test>");
    }

    /// The fingerprint is joined into a path (`<fingerprint>.gpg` under
    /// `.git-crypt/keys/<key>/0/`), so it must be hex before it is used —
    /// every other fingerprint entering the codebase is already validated.
    #[test]
    fn rejects_a_fingerprint_that_is_not_hex() {
        let output = "fpr:::::::::../../../../etc/cron.d/pwned:\n";
        assert!(
            parse_key_info(output).is_err(),
            "non-hex fingerprint must be rejected"
        );
    }

    /// `gpg --import` imports every key in a file, so a file with more
    /// keys than the one shown in the preview must be rejected.
    #[test]
    fn rejects_a_file_with_more_than_one_key() {
        let output = format!(
            "{}pub:-:3072:1:1111111111111111:1700000000:::-:::scESC::::::23::0:\n\
             fpr:::::::::1111111111111111111111111111111111111111:\n",
            REAL_OUTPUT
        );
        assert!(parse_key_info(&output).is_err());
    }

    /// The fingerprint must be the primary key's, not a subkey's.
    #[test]
    fn uses_the_primary_fingerprint_not_a_subkey() {
        let output = "\
pub:-:3072:1:ABCDEF0123456789:1700000000:::-:::scESC::::::23::0:
uid:::::::::Alice <alice@example.test>:
sub:-:3072:1:2222222222222222:1700000000::::::e::::::23:
fpr:::::::::2222222222222222222222222222222222222222:
";
        assert!(
            parse_key_info(output).is_err(),
            "a subkey fingerprint must not be taken as the key's fingerprint"
        );
    }

    #[test]
    fn parses_import_ok_lines() {
        let status = "[GNUPG:] IMPORT_OK 1 AAAABBBBCCCCDDDDEEEEFFFF00001111222233334444\n\
                      [GNUPG:] KEY_CONSIDERED AAAA 0\n\
                      [GNUPG:] IMPORT_OK 0 1111111111111111111111111111111111111111\n";
        let parsed = parse_import_ok(status);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, 1);
        assert_eq!(parsed[1].1, "1111111111111111111111111111111111111111");
    }

    #[test]
    fn rejects_a_fingerprint_of_the_wrong_length() {
        let output = "pub:::::::::\nfpr:::::::::AABB:\n";
        assert!(
            parse_key_info(output).is_err(),
            "short fingerprint must be rejected"
        );
    }

    #[test]
    fn rejects_output_without_a_fingerprint() {
        let output = "uid:::::::::Alice <alice@example.test>:\n";
        assert!(
            parse_key_info(output).is_err(),
            "missing fpr must be an error"
        );
    }

    #[test]
    fn falls_back_to_a_placeholder_uid() {
        let output = "pub:-:3072:1:ABCDEF0123456789:1700000000:::-:::scESC::::::23::0:\n\
                      fpr:::::::::AAAABBBBCCCCDDDDEEEEFFFF00001111222233334444:\n";
        let info = parse_key_info(output).unwrap();
        assert_eq!(info.uid, "(no UID)");
    }
}
