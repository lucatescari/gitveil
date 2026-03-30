use colored::Colorize;

use crate::constants::DEFAULT_KEY_NAME;
use crate::error::GitVeilError;
use crate::git::checkout::force_checkout_files;
use crate::git::config::deconfigure_filters;
use crate::git::repo::{find_git_dir, get_encrypted_files, is_working_tree_clean, key_path};

/// Lock the repository: remove keys, deconfigure filters, and re-encrypt working copy.
pub fn lock(key_name: Option<&str>, all: bool, force: bool, quiet: bool) -> Result<(), GitVeilError> {
    let git_dir = find_git_dir()?;

    if !force && !is_working_tree_clean()? {
        return Err(GitVeilError::DirtyWorkingDir);
    }

    if all {
        // Lock all keys by iterating over .git/git-crypt/keys/
        let keys_dir = git_dir.join("git-crypt").join("keys");
        if !keys_dir.is_dir() {
            return Err(GitVeilError::NotInitialized);
        }

        let key_dirs: Vec<_> = std::fs::read_dir(&keys_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                // Use file_type() which does NOT follow symlinks on DirEntry,
                // so is_dir() is false for symlinks to directories.
                e.file_type().map(|t| t.is_dir()).unwrap_or(false)
            })
            .collect();

        if key_dirs.is_empty() {
            return Err(GitVeilError::NotInitialized);
        }

        for entry in key_dirs {
            let name = entry.file_name().to_string_lossy().to_string();
            lock_single_key(&name, &git_dir, quiet)?;
        }
    } else {
        let key_name = key_name.unwrap_or(DEFAULT_KEY_NAME);
        lock_single_key(key_name, &git_dir, quiet)?;
    }

    Ok(())
}

fn lock_single_key(key_name: &str, git_dir: &std::path::Path, quiet: bool) -> Result<(), GitVeilError> {
    let kp = key_path(git_dir, key_name);

    if !kp.exists() {
        return Err(GitVeilError::NotInitialized);
    }

    // Get list of encrypted files before deconfiguring filters
    let files = get_encrypted_files(key_name)?;

    // Deconfigure git filters
    deconfigure_filters(key_name)?;

    // Remove the key file
    std::fs::remove_file(&kp)?;

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

    if !quiet {
        eprintln!("{} key '{}'.", "Locked".yellow().bold(), key_name.bold());
    }
    Ok(())
}
