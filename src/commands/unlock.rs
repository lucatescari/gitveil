use std::io::Cursor;
use std::path::PathBuf;

use colored::Colorize;

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

        let mut unlocked_any = false;
        let mut last_gpg_error: Option<String> = None;

        // Iterate over key directories (skip symlinks)
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
                            eprintln!("{} key '{}' via GPG.", "Unlocked".green().bold(), key_name.bold());
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
            let detail = last_gpg_error
                .map(|e| format!(" Last error: {}", e))
                .unwrap_or_default();
            return Err(GitVeilError::Gpg(format!(
                "failed to decrypt any GPG-encrypted key. \
                 Do you have the right GPG private key?{}",
                detail
            )));
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
