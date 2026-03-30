use colored::Colorize;

use crate::constants::DEFAULT_KEY_NAME;
use crate::error::GitVeilError;
use crate::git::config::configure_filters;
use crate::git::repo::{find_git_dir, key_path};
use crate::key::key_file::KeyFile;

/// Initialize gitveil in the current repository.
/// Generates a new symmetric key and configures git filters.
pub fn init(key_name: Option<&str>, quiet: bool) -> Result<(), GitVeilError> {
    let key_name = key_name.unwrap_or(DEFAULT_KEY_NAME);
    let git_dir = find_git_dir()?;
    let kp = key_path(&git_dir, key_name);

    // Generate key
    let mut kf = KeyFile::generate();
    if key_name != DEFAULT_KEY_NAME {
        kf.set_key_name(key_name)?;
    }

    // Atomically create the key file (fails if it already exists),
    // avoiding a TOCTOU race between exists-check and write.
    kf.store_to_file_exclusive(&kp).map_err(|e| {
        if kp.exists() {
            GitVeilError::AlreadyInitialized(key_name.to_string())
        } else {
            e
        }
    })?;

    // Configure git filters
    configure_filters(key_name)?;

    if !quiet {
        eprintln!(
            "{} gitveil {} with key '{}'.",
            "Initialized".green().bold(),
            format!("v{}", env!("CARGO_PKG_VERSION")).dimmed(),
            key_name.bold()
        );
        eprintln!("Add files to encrypt by specifying them in .gitattributes:");
        if key_name == DEFAULT_KEY_NAME {
            eprintln!(
                "  {}",
                "secretfile filter=git-crypt diff=git-crypt".dimmed()
            );
        } else {
            eprintln!(
                "  {}",
                format!(
                    "secretfile filter=git-crypt-{} diff=git-crypt-{}",
                    key_name, key_name
                )
                .dimmed()
            );
        }
    }

    Ok(())
}
