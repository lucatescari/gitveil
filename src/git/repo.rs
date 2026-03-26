use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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
pub fn key_path(git_dir: &Path, key_name: &str) -> PathBuf {
    git_dir.join("git-crypt").join("keys").join(key_name)
}

/// Get the path to the .git-crypt directory in the repo root (committed to repo).
/// This is where GPG-encrypted keys are stored.
pub fn git_crypt_dir(repo_root: &Path) -> PathBuf {
    repo_root.join(".git-crypt")
}

/// List files that have the git-crypt filter attribute set.
/// Uses `git check-attr --stdin` to batch-check all files in a single subprocess.
pub fn get_encrypted_files(key_name: &str) -> Result<Vec<String>, GitVeilError> {
    let filter_name = if key_name == "default" {
        "git-crypt".to_string()
    } else {
        format!("git-crypt-{}", key_name)
    };

    // Get all tracked files
    let ls_output = Command::new("git")
        .args(["ls-files"])
        .output()
        .map_err(|e| GitVeilError::Git(format!("failed to run git ls-files: {}", e)))?;

    if !ls_output.status.success() {
        return Err(GitVeilError::Git("git ls-files failed".into()));
    }

    let all_files_str = String::from_utf8_lossy(&ls_output.stdout);
    let all_files: Vec<&str> = all_files_str.lines().filter(|l| !l.is_empty()).collect();

    if all_files.is_empty() {
        return Ok(Vec::new());
    }

    // Batch check attributes using --stdin (single subprocess for all files)
    let mut child = Command::new("git")
        .args(["check-attr", "filter", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| GitVeilError::Git(format!("failed to run git check-attr: {}", e)))?;

    // Write all filenames to stdin
    if let Some(ref mut stdin) = child.stdin {
        for file in &all_files {
            writeln!(stdin, "{}", file).map_err(|e| {
                GitVeilError::Git(format!("failed to write to git check-attr stdin: {}", e))
            })?;
        }
    }
    // Drop stdin to signal EOF
    drop(child.stdin.take());

    let output = child
        .wait_with_output()
        .map_err(|e| GitVeilError::Git(format!("failed to wait for git check-attr: {}", e)))?;

    if !output.status.success() {
        return Err(GitVeilError::Git("git check-attr --stdin failed".into()));
    }

    // Parse output: each line is "path: filter: value"
    let attr_output = String::from_utf8_lossy(&output.stdout);
    let expected_suffix = format!(": filter: {}", filter_name);
    let mut encrypted_files = Vec::new();

    for line in attr_output.lines() {
        if line.ends_with(&expected_suffix) {
            // Extract path: everything before ": filter: <value>"
            let path = &line[..line.len() - expected_suffix.len()];
            encrypted_files.push(path.to_string());
        }
    }

    Ok(encrypted_files)
}
