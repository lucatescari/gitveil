use std::path::Path;

use colored::Colorize;

use crate::config;
use crate::error::GitVeilError;

/// Set the global GPG keyring directory.
pub fn config_set_keyring(path: &Path) -> Result<(), GitVeilError> {
    config::save_keyring_path(path)?;

    // Re-load to show the canonicalized path
    let canonical = config::load_keyring_path()?.unwrap_or_default();
    eprintln!(
        "{} keyring path: {}",
        "Set".green().bold(),
        canonical.display()
    );
    Ok(())
}

/// Remove the global GPG keyring directory setting.
pub fn config_unset_keyring() -> Result<(), GitVeilError> {
    config::remove_keyring_path()?;
    eprintln!("{} keyring path.", "Removed".green().bold());
    Ok(())
}

/// Show current configuration.
pub fn config_show() -> Result<(), GitVeilError> {
    match config::load_keyring_path() {
        Ok(Some(path)) => {
            println!("keyring-path: {}", path.display());
        }
        Ok(None) => {
            println!("keyring-path: (not set)");
        }
        Err(e) => {
            println!("keyring-path: (error: {})", e);
        }
    }
    Ok(())
}
