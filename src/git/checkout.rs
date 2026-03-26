use std::process::Command;

use crate::error::GitVeilError;

/// Force checkout files to trigger smudge/clean filters.
/// Processes files in batches to avoid exceeding OS command-line argument limits.
pub fn force_checkout_files(files: &[String]) -> Result<(), GitVeilError> {
    if files.is_empty() {
        return Ok(());
    }

    const BATCH_SIZE: usize = 100;

    for chunk in files.chunks(BATCH_SIZE) {
        // Remove the files first so git checkout actually does something
        for file in chunk {
            let _ = std::fs::remove_file(file);
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
