use std::process::Command;

use crate::constants::DEFAULT_KEY_NAME;
use crate::error::GitVeilError;
use crate::git::repo::{find_git_dir, find_repo_root, git_crypt_dir, key_path};
use crate::gpg::operations::{gpg_encrypt_to_file, gpg_get_fingerprints};
use crate::key::key_file::KeyFile;

/// Add a GPG user as a collaborator who can unlock the repository.
///
/// This encrypts the symmetric key to the user's GPG public key
/// and commits the result to .git-crypt/keys/<keyname>/0/<fingerprint>.gpg
pub fn add_gpg_user(
    key_name: Option<&str>,
    no_commit: bool,
    trusted: bool,
    gpg_user_id: &str,
) -> Result<(), GitVeilError> {
    let key_name = key_name.unwrap_or(DEFAULT_KEY_NAME);
    let git_dir = find_git_dir()?;
    let repo_root = find_repo_root()?;
    let kp = key_path(&git_dir, key_name);

    if !kp.exists() {
        return Err(GitVeilError::NotInitialized);
    }

    // Load the symmetric key
    let kf = KeyFile::load_from_file(&kp)?;

    // Get the GPG fingerprint
    let fingerprints = gpg_get_fingerprints(gpg_user_id)?;
    let fingerprint = &fingerprints[0]; // Use the first (primary) fingerprint

    // Serialize the key
    let key_data = kf.to_bytes()?;

    // Encrypt to the GPG user
    let crypt_dir = git_crypt_dir(&repo_root);
    let gpg_key_dir = crypt_dir.join("keys").join(key_name).join("0");
    let gpg_file_path = gpg_key_dir.join(format!("{}.gpg", fingerprint));

    gpg_encrypt_to_file(&key_data, fingerprint, &gpg_file_path, trusted)?;

    // Create .gitattributes in .git-crypt to prevent encrypting GPG key files
    let gitattributes_path = crypt_dir.join(".gitattributes");
    if !gitattributes_path.exists() {
        std::fs::write(
            &gitattributes_path,
            "# Do not encrypt GPG-encrypted key files\n* !filter !diff\n",
        )?;
    }

    if !no_commit {
        // Stage and commit the GPG-encrypted key file
        let status = Command::new("git")
            .args(["add", "--"])
            .arg(&gpg_file_path)
            .arg(&gitattributes_path)
            .status()
            .map_err(|e| GitVeilError::Git(format!("failed to stage files: {}", e)))?;

        if !status.success() {
            return Err(GitVeilError::Git("failed to stage GPG key files".into()));
        }

        // Sanitize user ID: replace control characters and newlines to prevent
        // injection of extra lines into the commit message.
        let safe_user_id: String = gpg_user_id
            .chars()
            .map(|c| if c.is_control() { '_' } else { c })
            .collect();

        let commit_msg = format!(
            "Add {} as gitveil collaborator\n\nKey: {}\nFingerprint: {}",
            safe_user_id, key_name, fingerprint
        );

        let status = Command::new("git")
            .args(["commit", "-m", &commit_msg, "--"])
            .arg(&gpg_file_path)
            .arg(&gitattributes_path)
            .status()
            .map_err(|e| GitVeilError::Git(format!("failed to commit: {}", e)))?;

        if !status.success() {
            return Err(GitVeilError::Git("failed to commit GPG key files".into()));
        }
    }

    eprintln!(
        "Added GPG user {} (fingerprint: {}) for key '{}'.",
        gpg_user_id, fingerprint, key_name
    );

    Ok(())
}
