use std::collections::HashSet;
use std::io::Cursor;
use std::path::PathBuf;

use colored::Colorize;

use crate::error::GitVeilError;
use crate::git::checkout::force_checkout_files;
use crate::git::config::configure_filters;
use crate::git::repo::{
    find_git_dir, find_repo_root, get_encrypted_files, git_crypt_dir, key_path,
};
use crate::gpg::operations::{gpg_decrypt_from_file, gpg_list_secret_key_fingerprints};
use crate::key::key_file::{validate_existing_key_name, KeyFile};

/// Unlock the repository: load key, configure filters, and decrypt working copy.
///
/// If key_files are provided, load symmetric keys from them.
/// Otherwise, attempt GPG-based unlock using keys in .git-crypt/.
pub fn unlock(key_files: &[PathBuf], quiet: bool) -> Result<(), GitVeilError> {
    let git_dir = find_git_dir()?;

    if !key_files.is_empty() {
        // Symmetric key file unlock
        for key_file_path in key_files {
            let kf = KeyFile::load_from_file(key_file_path)?;
            let key_name = kf.key_name().to_string();
            let kp = key_path(&git_dir, &key_name);

            kf.store_to_file(&kp)?;
            configure_filters(&key_name)?;

            // Force checkout to decrypt files
            let files = get_encrypted_files(&key_name)?;
            if !files.is_empty() {
                force_checkout_files(&files)?;
            }

            if !quiet {
                eprintln!("{} key '{}'.", "Unlocked".green().bold(), key_name.bold());
            }
        }
    } else {
        // GPG-based unlock
        let repo_root = find_repo_root()?;
        let crypt_dir = git_crypt_dir(&repo_root);

        if !crypt_dir.exists() {
            return Err(GitVeilError::NotInitialized);
        }

        let keys_dir = crypt_dir.join("keys");
        if !keys_dir.is_dir() {
            return Err(GitVeilError::NotInitialized);
        }

        // Enumerate the fingerprints of secret keys in the local GPG keyring
        // so we only attempt to decrypt collaborator files we actually have a
        // private key for. This stops pinentry from being invoked once per
        // collaborator and stops gpg from spamming stderr with "no secret
        // key" for keys we obviously cannot decrypt.
        let secret_fps: HashSet<String> = gpg_list_secret_key_fingerprints()?
            .into_iter()
            .map(|f| f.to_ascii_lowercase())
            .collect();

        let mut unlocked_any = false;
        let mut last_gpg_error: Option<String> = None;
        let mut any_collaborator_found = false;

        // Iterate over key directories (skip symlinks)
        let key_dirs: Vec<_> = std::fs::read_dir(&keys_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .collect();

        for key_dir_entry in key_dirs {
            let key_name = key_dir_entry.file_name().to_string_lossy().to_string();

            // This name is repository content. Unvalidated, it would flow
            // into `git config filter.<name>.smudge`, which git executes
            // through a shell — a crafted directory name in a cloned repo
            // would run arbitrary code here. The name is escaped for display
            // so it cannot smuggle terminal control sequences either.
            if let Err(e) = validate_existing_key_name(&key_name) {
                eprintln!(
                    "{} ignoring key directory with invalid name \"{}\": {}",
                    "warning:".yellow().bold(),
                    key_name.escape_default(),
                    e
                );
                continue;
            }

            // Look for GPG files in the key's version directories
            let key_dir = key_dir_entry.path();
            let gpg_files = find_gpg_files(&key_dir);

            if !gpg_files.is_empty() {
                any_collaborator_found = true;
            }

            for gpg_file in &gpg_files {
                let stem = gpg_file
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_ascii_lowercase())
                    .unwrap_or_default();

                // Skip files encrypted to recipients we don't have a secret
                // key for. Filenames are the recipient's primary fingerprint.
                if !secret_fps.contains(&stem) {
                    continue;
                }

                match gpg_decrypt_from_file(gpg_file) {
                    Ok(key_data) => {
                        let mut cursor = Cursor::new(key_data.as_slice());
                        let kf = KeyFile::load(&mut cursor)?;
                        let kp = key_path(&git_dir, &key_name);

                        kf.store_to_file(&kp)?;
                        configure_filters(&key_name)?;

                        let files = get_encrypted_files(&key_name)?;
                        if !files.is_empty() {
                            force_checkout_files(&files)?;
                        }

                        if !quiet {
                            eprintln!(
                                "{} key '{}' via GPG.",
                                "Unlocked".green().bold(),
                                key_name.bold()
                            );
                        }
                        unlocked_any = true;
                        break;
                    }
                    Err(e) => {
                        last_gpg_error = Some(format!("{}", e));
                        continue;
                    }
                }
            }
        }

        if !unlocked_any {
            if !any_collaborator_found {
                return Err(GitVeilError::Gpg(
                    "no GPG-encrypted keys found in .git-crypt/keys/".into(),
                ));
            }
            if let Some(detail) = last_gpg_error {
                // A matching key was attempted but decryption failed (e.g.,
                // the user cancelled the pinentry prompt, or the secret key
                // is no longer available to gpg-agent).
                return Err(GitVeilError::Gpg(format!(
                    "GPG decryption failed. {}",
                    detail
                )));
            }
            // Collaborators exist but none match a secret key in our keyring.
            return Err(GitVeilError::Gpg(
                "no GPG secret key in your keyring matches any collaborator on this \
                 repository. Make sure the right private key is imported (try \
                 `gpg --list-secret-keys`)."
                    .into(),
            ));
        }
    }

    Ok(())
}

/// Recursively find .gpg files in a directory.
/// Skips symlinks to prevent traversal outside the repository.
fn find_gpg_files(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            // DirEntry::file_type() does not follow symlinks, so
            // is_dir()/is_file() return false for symlinks.
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            let path = entry.path();
            if ft.is_dir() {
                files.extend(find_gpg_files(&path));
            } else if ft.is_file() && path.extension().map(|e| e == "gpg").unwrap_or(false) {
                files.push(path);
            }
        }
    }
    files
}
