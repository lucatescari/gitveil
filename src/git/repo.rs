use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

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

/// Check if tracked files are clean, ignoring untracked files. This is
/// git-crypt's `unlock` check (`git status -uno --porcelain`): untracked
/// files cannot be clobbered by the forced checkout, but uncommitted edits
/// to tracked files can.
pub fn is_tracked_tree_clean() -> Result<bool, GitVeilError> {
    let output = Command::new("git")
        .args(["status", "-uno", "--porcelain"])
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

/// Run a git command whose output is a NUL-delimited list (e.g.
/// `ls-files -z`) in `dir` (or the cwd when `None`), returning each
/// non-empty entry as raw bytes.
///
/// NUL delimiting is essential: without `-z`, git C-quotes names containing
/// non-ASCII bytes, quotes, backslashes or newlines (`core.quotePath`), and
/// line splitting breaks on embedded newlines.
pub fn git_nul_list(dir: Option<&Path>, args: &[&str]) -> Result<Vec<Vec<u8>>, GitVeilError> {
    let mut cmd = Command::new("git");
    cmd.args(args);
    if let Some(dir) = dir {
        cmd.current_dir(dir);
    }
    let out = cmd
        .output()
        .map_err(|e| GitVeilError::Git(format!("failed to run git {:?}: {}", args, e)))?;

    if !out.status.success() {
        return Err(GitVeilError::Git(format!("git {:?} failed", args)));
    }

    Ok(out
        .stdout
        .split(|&b| b == 0)
        .filter(|c| !c.is_empty())
        .map(|c| c.to_vec())
        .collect())
}

/// A `(path, attribute value)` pair from `git check-attr`, as raw bytes.
pub type PathAttr = (Vec<u8>, Vec<u8>);

/// Resolve the `filter` attribute of each path with a single
/// `git check-attr -z --stdin` run in `dir` (or the cwd when `None`); paths
/// are interpreted relative to that directory. Returns `(path, value)`
/// pairs in git's output order.
pub fn batch_check_filter_attr(
    dir: Option<&Path>,
    paths: Vec<Vec<u8>>,
) -> Result<Vec<PathAttr>, GitVeilError> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }

    let mut cmd = Command::new("git");
    cmd.args(["check-attr", "-z", "--stdin", "filter"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(dir) = dir {
        cmd.current_dir(dir);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| GitVeilError::Git(format!("failed to run git check-attr: {}", e)))?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| GitVeilError::Git("failed to open check-attr stdin".into()))?;

    // Write paths on a separate thread to avoid pipe deadlock when the
    // number of files is large enough to overflow the OS pipe buffer.
    let writer_thread = thread::spawn(move || {
        let mut stdin = stdin;
        for path in &paths {
            if stdin.write_all(path).is_err() || stdin.write_all(b"\0").is_err() {
                break;
            }
        }
    });

    let output = child
        .wait_with_output()
        .map_err(|e| GitVeilError::Git(format!("failed to wait for git check-attr: {}", e)))?;

    let _ = writer_thread.join();

    if !output.status.success() {
        return Err(GitVeilError::Git("git check-attr -z --stdin failed".into()));
    }

    // NUL-delimited output: path\0attr\0value\0 (repeating triplets). The
    // trailing NUL yields one empty final field, which the bound skips.
    let fields: Vec<&[u8]> = output.stdout.split(|&b| b == 0).collect();
    let mut result = Vec::new();
    let mut i = 0;
    while i + 2 < fields.len() {
        result.push((fields[i].to_vec(), fields[i + 2].to_vec()));
        i += 3;
    }
    Ok(result)
}

/// Git filter name for a key name.
fn filter_name_for(key_name: &str) -> String {
    if key_name == "default" {
        "git-crypt".to_string()
    } else {
        format!("git-crypt-{}", key_name)
    }
}

/// List tracked files that have the git-crypt filter attribute for
/// `key_name`, as paths relative to the repository root.
///
/// Git runs from the repository root so the result covers the whole working
/// tree regardless of the caller's cwd: `lock` removes the key for the whole
/// repository, so it must re-check-out every encrypted file, not only those
/// under the current directory. Pass the result to
/// [`crate::git::checkout::force_checkout_files`], which also works from the
/// repository root.
pub fn get_encrypted_files(key_name: &str) -> Result<Vec<String>, GitVeilError> {
    let repo_root = find_repo_root()?;
    let filter_name = filter_name_for(key_name);

    let all_files = git_nul_list(Some(&repo_root), &["ls-files", "-z", "--full-name"])?;
    let attrs = batch_check_filter_attr(Some(&repo_root), all_files)?;

    let mut encrypted_files = Vec::new();
    for (path, value) in attrs {
        if value != filter_name.as_bytes() {
            continue;
        }
        // Refuse rather than mangle: a lossily-decoded name would not match
        // the file on disk, so it would silently stay plaintext on lock.
        // Lock calls this before it changes any state.
        let path = String::from_utf8(path).map_err(|e| {
            GitVeilError::Git(format!(
                "encrypted file has a non-UTF-8 name, which is not supported: {}",
                String::from_utf8_lossy(e.as_bytes()).escape_default()
            ))
        })?;
        encrypted_files.push(path);
    }

    Ok(encrypted_files)
}
