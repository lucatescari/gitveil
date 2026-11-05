use std::collections::HashSet;
use std::io::Cursor;
use std::path::PathBuf;

use colored::Colorize;

use crate::error::GitVeilError;
use crate::filter::decrypt::key_decrypts_blob;
use crate::git::checkout::force_checkout_files;
use crate::git::config::configure_filters;
use crate::git::repo::{
    find_git_dir, find_repo_root, get_encrypted_files, git_crypt_dir, is_tracked_tree_clean,
    key_path, read_index_blob,
};
use crate::gpg::display::sanitize_for_display;
use crate::gpg::operations::{gpg_decrypt_from_file, gpg_list_secret_key_fingerprints};
use crate::gpg::safe_path::ensure_no_symlink_components;
use crate::key::key_file::{validate_existing_key_name, KeyFile};

/// Unlock the repository: load key, configure filters, and decrypt working copy.
///
/// If key_files are provided, load symmetric keys from them.
/// Otherwise, attempt GPG-based unlock using keys in .git-crypt/.
pub fn unlock(key_files: &[PathBuf], quiet: bool) -> Result<(), GitVeilError> {
    let git_dir = find_git_dir()?;

    // The forced checkout below deletes and re-materializes every encrypted
    // file, which would silently destroy uncommitted edits. Like git-crypt,
    // refuse unless tracked files are clean (untracked files are safe).
    // (DirtyWorkingDir's message suggests --force, which unlock lacks.)
    if !is_tracked_tree_clean()? {
        return Err(GitVeilError::Other(
            "Working directory is dirty; commit or stash your changes to tracked \
             files before running 'gitveil unlock'"
                .into(),
        ));
    }

    if !key_files.is_empty() {
        // Symmetric key file unlock
        for key_file_path in key_files {
            let kf = KeyFile::load_from_file(key_file_path)?;
            let key_name = kf.key_name().to_string();

            let files = get_encrypted_files(&key_name)?;
            check_key_matches_repo(&kf, &key_name, &files)?;
            install_key(&git_dir, &kf, &key_name, &files)?;

            if !quiet {
                eprintln!("{} key '{}'.", "Unlocked".green().bold(), key_name.bold());
            }
        }
    } else {
        // GPG-based unlock
        let repo_root = find_repo_root()?;
        let crypt_dir = git_crypt_dir(&repo_root);

        if std::fs::symlink_metadata(&crypt_dir).is_err() {
            return Err(GitVeilError::NotInitialized);
        }

        // `.git-crypt/` is repository content: a committed symlink here
        // would make unlock read key files from outside the repository.
        let keys_dir = crypt_dir.join("keys");
        ensure_no_symlink_components(&repo_root, &keys_dir)?;
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

                // Gather the file list before changing any state, and check the
                // candidate key against real ciphertext before installing it.
                let candidate =
                    decrypt_collaborator_key(gpg_file, &stem, &key_name).and_then(|kf| {
                        let files = get_encrypted_files(&key_name)?;
                        check_key_matches_repo(&kf, &key_name, &files)?;
                        Ok((kf, files))
                    });
                match candidate {
                    Ok((kf, files)) => {
                        install_key(&git_dir, &kf, &key_name, &files)?;

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
                        eprintln!(
                            "{} {}",
                            "warning:".yellow().bold(),
                            sanitize_for_display(&e.to_string())
                        );
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

/// Store the key, configure the filters, and re-check-out the encrypted
/// files so they are decrypted. Only called once the key has been verified.
fn install_key(
    git_dir: &std::path::Path,
    kf: &KeyFile,
    key_name: &str,
    files: &[String],
) -> Result<(), GitVeilError> {
    kf.store_to_file(&key_path(git_dir, key_name))?;
    configure_filters(key_name)?;
    if !files.is_empty() {
        force_checkout_files(files)?;
    }
    Ok(())
}

/// Check that `kf` really is this repository's key, by decrypting and
/// HMAC-verifying the first encrypted blob found in the index.
///
/// A `.gpg` file that is genuinely encrypted to your public key proves
/// nothing about *who* made it: anyone with push access can encrypt a key of
/// their choosing to you. If gitveil installed such a key, every secret you
/// commit afterwards would be encrypted under a key the attacker knows (and
/// the existing files would fail to decrypt mid-checkout). The same check
/// catches a wrong symmetric key file. git-crypt does not do this.
///
/// If the repository has no encrypted blobs yet there is nothing to compare
/// against, and the key is accepted.
fn check_key_matches_repo(
    kf: &KeyFile,
    key_name: &str,
    files: &[String],
) -> Result<(), GitVeilError> {
    let repo_root = find_repo_root()?;
    for path in files {
        let Some(blob) = read_index_blob(&repo_root, path)? else {
            continue;
        };
        if !blob.starts_with(crate::constants::ENCRYPTED_FILE_HEADER) {
            // Committed in plaintext; `status` reports these.
            continue;
        }
        if key_decrypts_blob(kf, &blob) {
            return Ok(());
        }
        return Err(GitVeilError::InvalidKeyFile(format!(
            "key for '{}' does not decrypt the files in this repository (checked '{}'); \
             refusing to install it",
            sanitize_for_display(key_name),
            sanitize_for_display(path)
        )));
    }
    Ok(())
}

/// Decrypt a collaborator key file and check it is a well-formed key for
/// `key_name`.
///
/// The file is repository content, so anyone with push access could have
/// planted it. `gpg_decrypt_from_file` only returns data that was genuinely
/// public-key encrypted to `fingerprint` (no unencrypted literal packets,
/// no passphrase-only messages). Like git-crypt, the decrypted key must
/// also carry the name of the directory it was found in and must contain
/// key material.
fn decrypt_collaborator_key(
    gpg_file: &std::path::Path,
    fingerprint: &str,
    key_name: &str,
) -> Result<KeyFile, GitVeilError> {
    let key_data = gpg_decrypt_from_file(gpg_file, fingerprint)?;
    let mut cursor = Cursor::new(key_data.as_slice());
    let kf = KeyFile::load(&mut cursor)?;
    validate_collaborator_key(&kf, key_name)?;
    Ok(kf)
}

/// Check a decrypted collaborator key against the directory it came from.
fn validate_collaborator_key(kf: &KeyFile, key_name: &str) -> Result<(), GitVeilError> {
    // `key_name()` reports an unnamed key as "default", which is exactly the
    // name of the default key's directory.
    if kf.key_name() != key_name {
        return Err(GitVeilError::InvalidKeyFile(format!(
            "GPG-encrypted key file for key '{}' is malformed because it does \
             not contain the expected key name (found '{}')",
            sanitize_for_display(key_name),
            sanitize_for_display(kf.key_name())
        )));
    }
    // Files are under `.git-crypt/keys/<name>/0/`: git-crypt requires the
    // decrypted key to contain that version-0 entry.
    if kf.get(0).is_none() {
        return Err(GitVeilError::InvalidKeyFile(format!(
            "GPG-encrypted key file for key '{}' has no version-0 key entry",
            sanitize_for_display(key_name)
        )));
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A serialized key file containing a single entry with `version`.
    fn key_bytes(version: u32, name: Option<&str>) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"\x00GITCRYPTKEY");
        b.extend_from_slice(&2u32.to_be_bytes());
        if let Some(n) = name {
            b.extend_from_slice(&1u32.to_be_bytes());
            b.extend_from_slice(&(n.len() as u32).to_be_bytes());
            b.extend_from_slice(n.as_bytes());
        }
        b.extend_from_slice(&0u32.to_be_bytes());
        for (id, data) in [
            (1u32, version.to_be_bytes().to_vec()),
            (3, vec![0x11; 32]),
            (5, vec![0x22; 64]),
        ] {
            b.extend_from_slice(&id.to_be_bytes());
            b.extend_from_slice(&(data.len() as u32).to_be_bytes());
            b.extend_from_slice(&data);
        }
        b.extend_from_slice(&0u32.to_be_bytes());
        b
    }

    fn load(bytes: &[u8]) -> KeyFile {
        KeyFile::load(&mut Cursor::new(bytes)).unwrap()
    }

    #[test]
    fn accepts_version_zero_default_key() {
        assert!(validate_collaborator_key(&load(&key_bytes(0, None)), "default").is_ok());
    }

    #[test]
    fn rejects_key_without_version_zero_entry() {
        let err = validate_collaborator_key(&load(&key_bytes(1, None)), "default").unwrap_err();
        assert!(err.to_string().contains("version-0"), "{err}");
    }

    #[test]
    fn rejects_key_name_mismatch() {
        assert!(validate_collaborator_key(&load(&key_bytes(0, Some("ops"))), "default").is_err());
        assert!(validate_collaborator_key(&load(&key_bytes(0, None)), "ops").is_err());
        assert!(validate_collaborator_key(&load(&key_bytes(0, Some("ops"))), "ops").is_ok());
    }
}
