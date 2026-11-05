use std::process::Command;

use colored::Colorize;

use crate::constants::DEFAULT_KEY_NAME;
use crate::error::GitVeilError;
use crate::git::repo::{find_repo_root, git_crypt_dir};
use crate::gpg::display::sanitize_for_display;
use crate::gpg::operations::gpg_get_primary_fingerprint;
use crate::gpg::safe_path::ensure_no_symlink_components;

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
    // A symlinked `.git-crypt`, key or version directory committed to the
    // repo would otherwise make us delete a file outside the repository.
    ensure_no_symlink_components(&repo_root, &keys_dir)?;
    if !keys_dir.is_dir() {
        return Err(GitVeilError::Other(format!(
            "No GPG users configured for key '{}'.",
            key_name
        )));
    }

    // Resolve the GPG user ID to exactly one primary fingerprint. Like
    // git-crypt, an ID matching several keys is an error rather than a
    // guess about whose access to revoke.
    let fp = gpg_get_primary_fingerprint(gpg_user_id)?;

    let mut removed_any = false;
    let mut removed_path = None;

    let gpg_file = keys_dir.join(format!("{}.gpg", fp));
    ensure_no_symlink_components(&repo_root, &gpg_file)?;
    if std::fs::symlink_metadata(&gpg_file)
        .map(|m| m.is_file())
        .unwrap_or(false)
    {
        std::fs::remove_file(&gpg_file)?;
        removed_path = Some(gpg_file);
        removed_any = true;
        eprintln!(
            "{} GPG user {} (fingerprint: {}) from key '{}'.",
            "Removed".red().bold(),
            sanitize_for_display(gpg_user_id).bold(),
            fp[..16].dimmed(),
            key_name.bold()
        );
    }

    if !removed_any {
        return Err(GitVeilError::Other(format!(
            "No encrypted key found for '{}' under key '{}'. \
             Use 'gitveil ls-gpg-users' to see current users.",
            sanitize_for_display(gpg_user_id),
            key_name
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

            let safe_user_id = sanitize_for_display(gpg_user_id);

            let commit_msg = format!(
                "Remove {} from gitveil collaborators\n\nKey: {}",
                safe_user_id, key_name
            );

            // Commit only the removed key file: without a pathspec, `git
            // commit` would also sweep in whatever else the user had staged.
            let status = Command::new("git")
                .args(["commit", "-m", &commit_msg, "--"])
                .arg(path)
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
