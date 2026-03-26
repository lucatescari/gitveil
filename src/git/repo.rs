use std::path::PathBuf;
use std::process::Command;

use crate::error::GitVeilError;

/// Get the path to the .git directory.
pub fn find_git_dir() -> Result<PathBuf, GitVeilError> {
    let output = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output()
        .map_err(|e| GitVeilError::Git(format!("failed to run git: {}", e)))?;

    if !output.status.success() {
        return Err(GitVeilError::NotAGitRepo);
    }

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(PathBuf::from(path))
}

/// Get the repository root (working tree top-level directory).
pub fn find_repo_root() -> Result<PathBuf, GitVeilError> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|e| GitVeilError::Git(format!("failed to run git: {}", e)))?;

    if !output.status.success() {
        return Err(GitVeilError::NotAGitRepo);
    }

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(PathBuf::from(path))
}

/// Check if the current directory is inside a git repository.
#[allow(dead_code)]
pub fn is_git_repo() -> bool {
    Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if the working tree is clean (no uncommitted changes).
pub fn is_working_tree_clean() -> Result<bool, GitVeilError> {
    let output = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .map_err(|e| GitVeilError::Git(format!("failed to run git status: {}", e)))?;

    if !output.status.success() {
        return Err(GitVeilError::Git("git status failed".into()));
    }

    Ok(output.stdout.is_empty())
}

/// Get the path where keys are stored for a given key name.
/// Keys are stored in .git/git-crypt/keys/<keyname>
pub fn key_path(git_dir: &PathBuf, key_name: &str) -> PathBuf {
    git_dir.join("git-crypt").join("keys").join(key_name)
}

/// Get the path to the .git-crypt directory in the repo root (committed to repo).
/// This is where GPG-encrypted keys are stored.
pub fn git_crypt_dir(repo_root: &PathBuf) -> PathBuf {
    repo_root.join(".git-crypt")
}

/// List files that have the git-crypt filter attribute set.
pub fn get_encrypted_files(key_name: &str) -> Result<Vec<String>, GitVeilError> {
    let filter_name = if key_name == "default" {
        "git-crypt".to_string()
    } else {
        format!("git-crypt-{}", key_name)
    };

    // Use git ls-files to find tracked files, then check attributes
    let output = Command::new("git")
        .args(["ls-files"])
        .output()
        .map_err(|e| GitVeilError::Git(format!("failed to run git ls-files: {}", e)))?;

    if !output.status.success() {
        return Err(GitVeilError::Git("git ls-files failed".into()));
    }

    let all_files = String::from_utf8_lossy(&output.stdout);
    let mut encrypted_files = Vec::new();

    for file in all_files.lines() {
        if file.is_empty() {
            continue;
        }

        // Check if this file has the git-crypt filter attribute
        let attr_output = Command::new("git")
            .args(["check-attr", "filter", "--", file])
            .output()
            .map_err(|e| GitVeilError::Git(format!("failed to check attributes: {}", e)))?;

        if attr_output.status.success() {
            let attr_str = String::from_utf8_lossy(&attr_output.stdout);
            // Output format: "path: filter: value"
            if attr_str.contains(&format!(": {}", filter_name)) {
                encrypted_files.push(file.to_string());
            }
        }
    }

    Ok(encrypted_files)
}
