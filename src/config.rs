use std::fs;
use std::path::{Path, PathBuf};

use crate::error::GitVeilError;

/// Resolve the platform-appropriate config directory for gitveil.
///
/// - Linux/macOS: `$XDG_CONFIG_HOME/gitveil` or `~/.config/gitveil`
/// - Windows: `%APPDATA%\gitveil`
pub fn config_dir() -> Result<PathBuf, GitVeilError> {
    let base = config_base_dir()?;
    Ok(base.join("gitveil"))
}

/// Get the platform base config directory.
fn config_base_dir() -> Result<PathBuf, GitVeilError> {
    // Check XDG_CONFIG_HOME first (all platforms, for testability)
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        let p = PathBuf::from(xdg);
        if p.is_absolute() {
            return Ok(p);
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            return Ok(PathBuf::from(appdata));
        }
    }

    // Fall back to ~/.config
    home_dir()
        .map(|h| h.join(".config"))
        .ok_or_else(|| GitVeilError::Other("cannot determine home directory".into()))
}

/// Get the user's home directory.
fn home_dir() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        std::env::var("HOME").ok().map(PathBuf::from)
    }
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE").ok().map(PathBuf::from)
    }
}

/// Path to the config file within the config directory.
pub fn config_file_path() -> Result<PathBuf, GitVeilError> {
    Ok(config_dir()?.join("config"))
}

/// Load the configured keyring path from the config file.
/// Returns `Ok(None)` if no config file exists.
/// Returns `Err` if the config file exists but the path is invalid.
pub fn load_keyring_path() -> Result<Option<PathBuf>, GitVeilError> {
    let cf = config_file_path()?;
    if !cf.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(&cf)
        .map_err(|e| GitVeilError::Other(format!("failed to read config file: {}", e)))?;

    let path_str = content.trim();
    if path_str.is_empty() {
        return Ok(None);
    }

    let path = PathBuf::from(path_str);

    // Re-validate on every load
    if !path.exists() {
        return Err(GitVeilError::Other(format!(
            "configured keyring path no longer exists: {}",
            path.display()
        )));
    }
    if !path.is_dir() {
        return Err(GitVeilError::Other(format!(
            "configured keyring path is not a directory: {}",
            path.display()
        )));
    }

    Ok(Some(path))
}

/// Save a keyring path to the config file.
/// Validates the path, canonicalizes it, and writes with restrictive permissions.
pub fn save_keyring_path(path: &Path) -> Result<(), GitVeilError> {
    if !path.exists() {
        return Err(GitVeilError::Other(format!(
            "path does not exist: {}",
            path.display()
        )));
    }
    if !path.is_dir() {
        return Err(GitVeilError::Other(format!(
            "path is not a directory: {}",
            path.display()
        )));
    }

    // Canonicalize to resolve symlinks and relative components
    let canonical = fs::canonicalize(path)
        .map_err(|e| GitVeilError::Other(format!("failed to resolve path: {}", e)))?;

    // After resolving, verify it's still a directory (symlink might point to a file)
    if !canonical.is_dir() {
        return Err(GitVeilError::Other(format!(
            "path resolves to a non-directory: {}",
            canonical.display()
        )));
    }

    let dir = config_dir()?;
    create_config_dir(&dir)?;

    let cf = dir.join("config");
    write_config_file(&cf, canonical.to_string_lossy().as_ref())?;

    Ok(())
}

/// Remove the keyring path configuration.
pub fn remove_keyring_path() -> Result<(), GitVeilError> {
    let cf = config_file_path()?;
    if cf.exists() {
        fs::remove_file(&cf)
            .map_err(|e| GitVeilError::Other(format!("failed to remove config file: {}", e)))?;
    }
    Ok(())
}

/// Create the config directory with restrictive permissions.
fn create_config_dir(dir: &Path) -> Result<(), GitVeilError> {
    fs::create_dir_all(dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }

    Ok(())
}

/// Write content to the config file with restrictive permissions.
fn write_config_file(path: &Path, content: &str) -> Result<(), GitVeilError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(content.as_bytes())?;
        // Enforce permissions even if file pre-existed
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }

    #[cfg(not(unix))]
    {
        fs::write(path, content)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_config_dir_uses_xdg() {
        let tmp = TempDir::new().unwrap();
        std::env::set_var("XDG_CONFIG_HOME", tmp.path());
        let dir = config_dir().unwrap();
        assert_eq!(dir, tmp.path().join("gitveil"));
        std::env::remove_var("XDG_CONFIG_HOME");
    }

    #[test]
    fn test_save_load_roundtrip() {
        let tmp_config = TempDir::new().unwrap();
        let tmp_keyring = TempDir::new().unwrap();
        std::env::set_var("XDG_CONFIG_HOME", tmp_config.path());

        save_keyring_path(tmp_keyring.path()).unwrap();
        let loaded = load_keyring_path().unwrap();
        assert!(loaded.is_some());
        let loaded_path = loaded.unwrap();
        // Canonicalize both for comparison (macOS /private/var vs /var)
        let expected = fs::canonicalize(tmp_keyring.path()).unwrap();
        assert_eq!(loaded_path, expected);

        std::env::remove_var("XDG_CONFIG_HOME");
    }

    #[test]
    fn test_load_missing_config_returns_none() {
        let tmp = TempDir::new().unwrap();
        std::env::set_var("XDG_CONFIG_HOME", tmp.path());
        let loaded = load_keyring_path().unwrap();
        assert!(loaded.is_none());
        std::env::remove_var("XDG_CONFIG_HOME");
    }
}
