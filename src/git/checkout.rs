use std::process::Command;

use crate::error::GitVeilError;

/// Force checkout files to trigger smudge/clean filters.
/// Removes files first to force git to re-materialize them from blobs,
/// then runs `git checkout` to recreate them (applying the current
/// smudge filter, or leaving encrypted blobs if filters are deconfigured).
/// Processes files in batches to avoid exceeding OS argument limits.
pub fn force_checkout_files(files: &[String]) -> Result<(), GitVeilError> {
    if files.is_empty() {
        return Ok(());
    }

    const BATCH_SIZE: usize = 100;

    for chunk in files.chunks(BATCH_SIZE) {
        // Remove files so git checkout is forced to re-materialize them.
        // This is necessary because git skips checkout when the working
        // copy matches the index, even with -f.
        for file in chunk {
            if let Err(e) = std::fs::remove_file(file) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    eprintln!("Warning: could not remove {}: {}", file, e);
                }
            }
        }

        let mut cmd = Command::new("git");
        cmd.args(["checkout", "--"]);
        for file in chunk {
            cmd.arg(file);
        }

        let status = cmd
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
