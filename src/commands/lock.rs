use crate::constants::DEFAULT_KEY_NAME;
use crate::error::GitVeilError;
use crate::git::checkout::force_checkout_files;
use crate::git::config::deconfigure_filters;
use crate::git::repo::{find_git_dir, get_encrypted_files, is_working_tree_clean, key_path};

/// Lock the repository: remove keys, deconfigure filters, and re-encrypt working copy.
pub fn lock(key_name: Option<&str>, _all: bool, force: bool) -> Result<(), GitVeilError> {
    let key_name = key_name.unwrap_or(DEFAULT_KEY_NAME);
    let git_dir = find_git_dir()?;
    let kp = key_path(&git_dir, key_name);

    if !kp.exists() {
        return Err(GitVeilError::NotInitialized);
    }

    if !force && !is_working_tree_clean()? {
        return Err(GitVeilError::DirtyWorkingDir);
    }

    // Get list of encrypted files before deconfiguring filters
    let files = get_encrypted_files(key_name)?;

    // Deconfigure git filters
    deconfigure_filters(key_name)?;

    // Remove the key file
    std::fs::remove_file(&kp)
        .map_err(|e| GitVeilError::Io(e))?;

    // Clean up empty parent directories
    if let Some(parent) = kp.parent() {
        let _ = std::fs::remove_dir(parent);
        if let Some(grandparent) = parent.parent() {
            let _ = std::fs::remove_dir(grandparent);
        }
    }

    // Force checkout to re-encrypt files in working copy
    // Without filters, git checkout will leave the encrypted blobs as-is
    if !files.is_empty() {
        force_checkout_files(&files)?;
    }

    eprintln!("Locked key '{}'.", key_name);
    Ok(())
}
