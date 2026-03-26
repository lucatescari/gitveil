use std::io::Cursor;
use std::path::PathBuf;

use crate::error::GitVeilError;
use crate::git::checkout::force_checkout_files;
use crate::git::config::configure_filters;
use crate::git::repo::{find_git_dir, find_repo_root, get_encrypted_files, git_crypt_dir, key_path};
use crate::gpg::operations::gpg_decrypt_from_file;
use crate::key::key_file::KeyFile;

/// Unlock the repository: load key, configure filters, and decrypt working copy.
///
/// If key_files are provided, load symmetric keys from them.
/// Otherwise, attempt GPG-based unlock using keys in .git-crypt/.
pub fn unlock(key_files: &[PathBuf]) -> Result<(), GitVeilError> {
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

            eprintln!("Unlocked key '{}'.", key_name);
        }
    } else {
        // GPG-based unlock
        let repo_root = find_repo_root()?;
        let crypt_dir = git_crypt_dir(&repo_root);

        if !crypt_dir.exists() {
            return Err(GitVeilError::NotInitialized);
        }

        let keys_dir = crypt_dir.join("keys");
        if !keys_dir.exists() {
            return Err(GitVeilError::NotInitialized);
        }

        let mut unlocked_any = false;

        // Iterate over key directories
        let key_dirs: Vec<_> = std::fs::read_dir(&keys_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .collect();

        for key_dir_entry in key_dirs {
            let key_name = key_dir_entry
                .file_name()
                .to_string_lossy()
                .to_string();

            // Look for GPG files in the key's version directories
            let key_dir = key_dir_entry.path();
            let gpg_files = find_gpg_files(&key_dir);

            for gpg_file in &gpg_files {
                match gpg_decrypt_from_file(gpg_file) {
                    Ok(key_data) => {
                        let mut cursor = Cursor::new(key_data);
                        let kf = KeyFile::load(&mut cursor)?;
                        let kp = key_path(&git_dir, &key_name);

                        kf.store_to_file(&kp)?;
                        configure_filters(&key_name)?;

                        let files = get_encrypted_files(&key_name)?;
                        if !files.is_empty() {
                            force_checkout_files(&files)?;
                        }

                        eprintln!("Unlocked key '{}' via GPG.", key_name);
                        unlocked_any = true;
                        break;
                    }
                    Err(_) => {
                        // Try next GPG file
                        continue;
                    }
                }
            }
        }

        if !unlocked_any {
            return Err(GitVeilError::Gpg(
                "failed to decrypt any GPG-encrypted key. \
                 Do you have the right GPG private key?"
                    .into(),
            ));
        }
    }

    Ok(())
}

/// Recursively find .gpg files in a directory.
fn find_gpg_files(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_dir() {
                files.extend(find_gpg_files(&path));
            } else if path.extension().map(|e| e == "gpg").unwrap_or(false) {
                files.push(path);
            }
        }
    }
    files
}
