use std::path::Path;

use colored::Colorize;

use crate::constants::DEFAULT_KEY_NAME;
use crate::error::GitVeilError;
use crate::git::repo::{find_repo_root, git_crypt_dir};

/// List GPG users who have been granted access to the repository.
/// Scans .git-crypt/keys/<keyname>/0/ for .gpg files and resolves
/// fingerprints to UIDs via the local GPG keyring.
pub fn ls_gpg_users(key_name: Option<&str>) -> Result<(), GitVeilError> {
    let repo_root = find_repo_root()?;
    let crypt_dir = git_crypt_dir(&repo_root);

    if !crypt_dir.is_dir() {
        return Err(GitVeilError::Other(
            "No GPG users configured. Use 'gitveil add-gpg-user' first.".into(),
        ));
    }

    let keys_dir = crypt_dir.join("keys");
    if !keys_dir.is_dir() {
        return Err(GitVeilError::Other(
            "No GPG users configured. Use 'gitveil add-gpg-user' first.".into(),
        ));
    }

    match key_name {
        Some(name) => list_users_for_key(&keys_dir, name),
        None => {
            // List all keys
            let mut key_dirs: Vec<_> = std::fs::read_dir(&keys_dir)?
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                .collect();

            if key_dirs.is_empty() {
                return Err(GitVeilError::Other(
                    "No GPG users configured. Use 'gitveil add-gpg-user' first.".into(),
                ));
            }

            key_dirs.sort_by_key(|e| e.file_name());

            for (i, entry) in key_dirs.iter().enumerate() {
                let name = entry.file_name().to_string_lossy().to_string();
                if i > 0 {
                    println!();
                }
                list_users_for_key(&keys_dir, &name)?;
            }
            Ok(())
        }
    }
}

fn list_users_for_key(keys_dir: &Path, key_name: &str) -> Result<(), GitVeilError> {
    let version_dir = keys_dir.join(key_name).join("0");

    if !version_dir.is_dir() {
        println!(
            "{} '{}': no GPG users",
            "Key".bold(),
            key_name.cyan().bold()
        );
        return Ok(());
    }

    let gpg_files: Vec<_> = std::fs::read_dir(&version_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_type().map(|t| t.is_file()).unwrap_or(false)
                && e.path().extension().map(|ext| ext == "gpg").unwrap_or(false)
        })
        .collect();

    let display_name = if key_name == DEFAULT_KEY_NAME {
        "default".to_string()
    } else {
        key_name.to_string()
    };

    if gpg_files.is_empty() {
        println!(
            "{} '{}': no GPG users",
            "Key".bold(),
            display_name.cyan().bold()
        );
        return Ok(());
    }

    println!(
        "{} '{}' ({} user{}):",
        "Key".bold(),
        display_name.cyan().bold(),
        gpg_files.len().to_string().green().bold(),
        if gpg_files.len() == 1 { "" } else { "s" }
    );

    for entry in &gpg_files {
        let fingerprint = entry
            .path()
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();

        // Try to resolve fingerprint to a UID via GPG
        let uid = resolve_gpg_uid(&fingerprint);

        let fp_short = if fingerprint.len() >= 16 {
            &fingerprint[..16]
        } else {
            &fingerprint
        };

        match uid {
            Some(name) => println!(
                "  {}  {}",
                name.bold(),
                format!("({}...)", fp_short).dimmed()
            ),
            None => println!(
                "  {}  {}",
                format!("{}...", fp_short).yellow(),
                "(not in local keyring)".dimmed()
            ),
        }
    }

    Ok(())
}

/// Try to resolve a GPG fingerprint to a UID (name + email).
fn resolve_gpg_uid(fingerprint: &str) -> Option<String> {
    let output = std::process::Command::new("gpg")
        .args([
            "--with-colons",
            "--batch",
            "--list-keys",
            &format!("0x{}", fingerprint),
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.starts_with("uid:") {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() > 9 {
                return Some(parts[9].to_string());
            }
        }
    }

    None
}
