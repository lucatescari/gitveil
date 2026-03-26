use std::process::Command;

use crate::constants::DEFAULT_KEY_NAME;
use crate::error::GitVeilError;

/// Get a git config value. Returns None if not set.
pub fn get_git_config(name: &str) -> Result<Option<String>, GitVeilError> {
    let output = Command::new("git")
        .args(["config", "--get", name])
        .output()
        .map_err(|e| GitVeilError::Git(format!("failed to run git config: {}", e)))?;

    if output.status.success() {
        Ok(Some(
            String::from_utf8_lossy(&output.stdout).trim().to_string(),
        ))
    } else {
        Ok(None)
    }
}

/// Set a git config value.
pub fn set_git_config(name: &str, value: &str) -> Result<(), GitVeilError> {
    let status = Command::new("git")
        .args(["config", name, value])
        .status()
        .map_err(|e| GitVeilError::Git(format!("failed to run git config: {}", e)))?;

    if !status.success() {
        return Err(GitVeilError::Git(format!(
            "failed to set git config {name}={value}"
        )));
    }
    Ok(())
}

/// Remove a git config entry.
pub fn unset_git_config(name: &str) -> Result<(), GitVeilError> {
    let status = Command::new("git")
        .args(["config", "--unset", name])
        .status()
        .map_err(|e| GitVeilError::Git(format!("failed to run git config: {}", e)))?;

    // Exit code 5 means the key was not found — that's okay
    if !status.success() && status.code() != Some(5) {
        return Err(GitVeilError::Git(format!(
            "failed to unset git config {name}"
        )));
    }
    Ok(())
}

/// Get the filter/diff config name for a key.
/// Both the filter and diff sections use the same name.
fn filter_name(key_name: &str) -> String {
    if key_name == DEFAULT_KEY_NAME {
        "git-crypt".to_string()
    } else {
        format!("git-crypt-{}", key_name)
    }
}

/// Configure git clean/smudge/diff filters for a key.
/// Uses the gitveil binary path so git invokes the correct executable.
pub fn configure_filters(key_name: &str) -> Result<(), GitVeilError> {
    let exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "gitveil".to_string());

    let name = filter_name(key_name);

    let key_arg = if key_name == DEFAULT_KEY_NAME {
        String::new()
    } else {
        format!(" {}", key_name)
    };

    set_git_config(
        &format!("filter.{name}.smudge"),
        &format!("\"{exe}\" smudge{key_arg}"),
    )?;
    set_git_config(
        &format!("filter.{name}.clean"),
        &format!("\"{exe}\" clean{key_arg}"),
    )?;
    set_git_config(&format!("filter.{name}.required"), "true")?;
    set_git_config(
        &format!("diff.{name}.textconv"),
        &format!("\"{exe}\" diff{key_arg}"),
    )?;

    Ok(())
}

/// Remove git clean/smudge/diff filter configuration for a key.
pub fn deconfigure_filters(key_name: &str) -> Result<(), GitVeilError> {
    let name = filter_name(key_name);

    unset_git_config(&format!("filter.{name}.smudge"))?;
    unset_git_config(&format!("filter.{name}.clean"))?;
    unset_git_config(&format!("filter.{name}.required"))?;
    unset_git_config(&format!("diff.{name}.textconv"))?;

    Ok(())
}
