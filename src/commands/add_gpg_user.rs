use std::path::Path;
use std::process::Command;

use colored::Colorize;

use crate::constants::DEFAULT_KEY_NAME;
use crate::error::GitVeilError;
use crate::git::repo::{find_git_dir, find_repo_root, git_crypt_dir, key_path};
use crate::gpg::import::{import_key_file, pick_keys, preview_key_file, scan_key_directory};
use crate::gpg::operations::{gpg_encrypt_to_file, gpg_get_fingerprints};
use crate::key::key_file::KeyFile;

/// Add a GPG user as a collaborator who can unlock the repository.
///
/// This encrypts the symmetric key to the user's GPG public key
/// and commits the result to .git-crypt/keys/<keyname>/0/<fingerprint>.gpg
///
/// When `--from` is provided, imports the GPG key from a file or directory
/// before adding the user. If a directory is given, shows an interactive picker.
pub fn add_gpg_user(
    key_name: Option<&str>,
    no_commit: bool,
    trusted: bool,
    gpg_user_id: Option<&str>,
    from: Option<&Path>,
) -> Result<(), GitVeilError> {
    let key_name = key_name.unwrap_or(DEFAULT_KEY_NAME);
    let git_dir = find_git_dir()?;
    let kp = key_path(&git_dir, key_name);

    if !kp.exists() {
        return Err(GitVeilError::NotInitialized);
    }

    match from {
        Some(from_path) => add_from_path(key_name, no_commit, trusted, from_path, &git_dir)?,
        None => {
            let gpg_user_id = gpg_user_id.ok_or_else(|| {
                GitVeilError::Other(
                    "GPG user ID is required (or use --from to import from a file/directory)"
                        .into(),
                )
            })?;
            add_single_user(key_name, no_commit, trusted, gpg_user_id, &git_dir)?;
        }
    }

    Ok(())
}

/// Handle --from: import from a file or directory, then add as collaborator.
fn add_from_path(
    key_name: &str,
    no_commit: bool,
    trusted: bool,
    from_path: &Path,
    git_dir: &Path,
) -> Result<(), GitVeilError> {
    if from_path.is_file() {
        // Single file: preview, import, add
        let info = preview_key_file(from_path)?;
        eprintln!(
            "{} key: {} ({})",
            "Importing".cyan().bold(),
            info.uid.bold(),
            info.fingerprint.dimmed()
        );
        import_key_file(from_path)?;
        add_by_fingerprint(key_name, no_commit, trusted, &info.fingerprint, &info.uid, git_dir)?;
    } else if from_path.is_dir() {
        // Directory: scan, pick, import, add each
        let keys = scan_key_directory(from_path)?;
        let selected = pick_keys(&keys)?;

        eprintln!();
        for &idx in &selected {
            let info = &keys[idx];
            eprintln!(
                "{} key: {} ({})",
                "Importing".cyan().bold(),
                info.uid.bold(),
                info.fingerprint.dimmed()
            );
            import_key_file(&info.path)?;
            add_by_fingerprint(
                key_name,
                no_commit,
                trusted,
                &info.fingerprint,
                &info.uid,
                git_dir,
            )?;
        }
    } else {
        return Err(GitVeilError::Other(format!(
            "'{}' is not a file or directory",
            from_path.display()
        )));
    }

    Ok(())
}

/// Add a user by GPG user ID (email, key ID, or fingerprint).
fn add_single_user(
    key_name: &str,
    no_commit: bool,
    trusted: bool,
    gpg_user_id: &str,
    git_dir: &Path,
) -> Result<(), GitVeilError> {
    let fingerprints = gpg_get_fingerprints(gpg_user_id)?;
    let fingerprint = &fingerprints[0];

    add_by_fingerprint(key_name, no_commit, trusted, fingerprint, gpg_user_id, git_dir)
}

/// Core logic: encrypt the repo key to a GPG fingerprint and optionally commit.
fn add_by_fingerprint(
    key_name: &str,
    no_commit: bool,
    trusted: bool,
    fingerprint: &str,
    display_name: &str,
    git_dir: &Path,
) -> Result<(), GitVeilError> {
    let kp = key_path(git_dir, key_name);
    let repo_root = find_repo_root()?;

    // Load the symmetric key
    let kf = KeyFile::load_from_file(&kp)?;

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

        // Sanitize display name: replace control characters to prevent
        // injection of extra lines into the commit message.
        let safe_name: String = display_name
            .chars()
            .map(|c| if c.is_control() { '_' } else { c })
            .collect();

        let commit_msg = format!(
            "Add {} as gitveil collaborator\n\nKey: {}\nFingerprint: {}",
            safe_name, key_name, fingerprint
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
        "{} GPG user {} (fingerprint: {}) for key '{}'.",
        "Added".green().bold(),
        display_name.bold(),
        &fingerprint[..16].dimmed(),
        key_name.bold()
    );

    Ok(())
}
