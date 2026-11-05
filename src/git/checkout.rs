use std::path::Path;
use std::process::Command;

use crate::error::GitVeilError;
use crate::git::repo::find_repo_root;

/// Force checkout files to trigger smudge/clean filters.
///
/// `files` are paths relative to the repository root, as returned by
/// [`crate::git::repo::get_encrypted_files`]; this works from the root
/// regardless of the caller's cwd.
///
/// Removes files first to force git to re-materialize them from blobs,
/// then runs `git checkout` to recreate them (applying the current
/// smudge filter, or leaving encrypted blobs if filters are deconfigured).
/// Processes files in batches to avoid exceeding OS argument limits.
pub fn force_checkout_files(files: &[String]) -> Result<(), GitVeilError> {
    if files.is_empty() {
        return Ok(());
    }

    let repo_root = find_repo_root()?;
    force_checkout_files_in(&repo_root, files)
}

fn force_checkout_files_in(repo_root: &Path, files: &[String]) -> Result<(), GitVeilError> {
    const BATCH_SIZE: usize = 100;

    for chunk in files.chunks(BATCH_SIZE) {
        // Remove files so git checkout is forced to re-materialize them.
        // This is necessary because git skips checkout when the working
        // copy matches the index, even with -f.
        for file in chunk {
            if let Err(e) = std::fs::remove_file(repo_root.join(file)) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    eprintln!("Warning: could not remove {}: {}", file.escape_default(), e);
                }
            }
        }

        let status = build_checkout_command(repo_root, chunk)
            .status()
            .map_err(|e| GitVeilError::Git(format!("failed to run git checkout: {}", e)))?;

        if !status.success() {
            return Err(GitVeilError::Git(
                "git checkout failed for some files".into(),
            ));
        }
    }

    Ok(())
}

/// `git checkout -- <files>` run from the repository root.
///
/// `--literal-pathspecs` stops names such as `[ab].txt` or `:(glob)*` from
/// being interpreted as glob or magic pathspecs; `--` stops names with a
/// leading dash from being parsed as options.
fn build_checkout_command(repo_root: &Path, files: &[String]) -> Command {
    let mut cmd = Command::new("git");
    cmd.current_dir(repo_root)
        .args(["--literal-pathspecs", "checkout", "--"])
        .args(files);
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkout_command_is_literal_and_rooted() {
        let root = Path::new("repo-root");
        let files = vec!["-x.txt".to_string(), "[ab].txt".to_string()];
        let cmd = build_checkout_command(root, &files);
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert_eq!(
            args,
            [
                "--literal-pathspecs",
                "checkout",
                "--",
                "-x.txt",
                "[ab].txt"
            ]
        );
        assert_eq!(cmd.get_current_dir(), Some(root));
    }
}
