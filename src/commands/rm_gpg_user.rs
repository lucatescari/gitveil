use std::process::Command;

use colored::Colorize;

use crate::constants::DEFAULT_KEY_NAME;
use crate::error::GitVeilError;
use crate::git::repo::{find_repo_root, git_crypt_dir};
use crate::gpg::operations::gpg_get_fingerprints;

/// Remove a GPG user's access by deleting their encrypted key file.
///
/// Note: this only prevents the user from unlocking future clones.
/// They may still have the symmetric key cached locally from a prior unlock.
/// For full revocation, rotate the key (re-init + re-encrypt).
pub fn rm_gpg_user(
    key_name: Option<&str>,
    no_commit: bool,
    gpg_user_id: &str,
) -> Result<(), GitVeilError> {
    let key_name = key_name.unwrap_or(DEFAULT_KEY_NAME);
    let repo_root = find_repo_root()?;
    let crypt_dir = git_crypt_dir(&repo_root);

    let keys_dir = crypt_dir.join("keys").join(key_name).join("0");
    if !keys_dir.is_dir() {
        return Err(GitVeilError::Other(format!(
            "No GPG users configured for key '{}'.",
            key_name
        )));
    }

    // Resolve GPG user ID to fingerprint(s)
    let fingerprints = gpg_get_fingerprints(gpg_user_id)?;

    let mut removed_any = false;
    let mut removed_path = None;

    for fp in &fingerprints {
        let gpg_file = keys_dir.join(format!("{}.gpg", fp));
        if gpg_file.exists() {
            std::fs::remove_file(&gpg_file)?;
            removed_path = Some(gpg_file);
            removed_any = true;
            eprintln!(
                "{} GPG user {} (fingerprint: {}) from key '{}'.",
                "Removed".red().bold(),
                gpg_user_id.bold(),
                if fp.len() >= 16 { &fp[..16] } else { fp }.dimmed(),
                key_name.bold()
            );
            break;
        }
    }

    if !removed_any {
        return Err(GitVeilError::Other(format!(
            "No encrypted key found for '{}' under key '{}'. \
             Use 'gitveil ls-gpg-users' to see current users.",
            gpg_user_id, key_name
        )));
    }

    if !no_commit {
        if let Some(ref path) = removed_path {
            // Stage the deletion
            let status = Command::new("git")
                .args(["rm", "--cached", "--"])
                .arg(path)
                .status()
                .map_err(|e| GitVeilError::Git(format!("failed to stage removal: {}", e)))?;

            if !status.success() {
                // File might not be tracked yet — just remove it
                return Ok(());
            }

            // Sanitize user ID for commit message
            let safe_user_id: String = gpg_user_id
                .chars()
                .map(|c| if c.is_control() { '_' } else { c })
                .collect();

            let commit_msg = format!(
                "Remove {} from gitveil collaborators\n\nKey: {}",
                safe_user_id, key_name
            );

            let status = Command::new("git")
                .args(["commit", "-m", &commit_msg])
                .status()
                .map_err(|e| GitVeilError::Git(format!("failed to commit: {}", e)))?;

            if !status.success() {
                return Err(GitVeilError::Git("failed to commit removal".into()));
            }
        }
    }

    eprintln!(
        "\n{} This only removes their encrypted key file. If they previously \
         unlocked the repo, they may still have the symmetric key locally. \
         For full revocation, rotate the key with 'gitveil init'.",
        "Note:".yellow().bold()
    );

    Ok(())
}
