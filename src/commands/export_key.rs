use std::io;
use std::path::PathBuf;

use colored::Colorize;

use crate::constants::DEFAULT_KEY_NAME;
use crate::error::GitVeilError;
use crate::git::repo::{find_git_dir, key_path};
use crate::key::key_file::KeyFile;

/// Export the symmetric key to a file or stdout.
pub fn export_key(
    key_name: Option<&str>,
    output_file: Option<&PathBuf>,
    quiet: bool,
) -> Result<(), GitVeilError> {
    let key_name = key_name.unwrap_or(DEFAULT_KEY_NAME);
    let git_dir = find_git_dir()?;
    let kp = key_path(&git_dir, key_name);

    if !kp.exists() {
        return Err(GitVeilError::NotInitialized);
    }

    let kf = KeyFile::load_from_file(&kp)?;

    match output_file {
        Some(path) => {
            kf.store_to_file(path)?;
            if !quiet {
                eprintln!(
                    "Key '{}' {} to {}.",
                    key_name.bold(),
                    "exported".green().bold(),
                    path.display().to_string().dimmed()
                );
            }
        }
        None => {
            // Write to stdout
            let mut stdout = io::stdout().lock();
            kf.store(&mut stdout)?;
        }
    }

    Ok(())
}
