use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::crypto::random::generate_random_bytes;

/// Create a uniquely named, owner-only directory under the system temp
/// directory, returning its path.
///
/// # Security
///
/// The name carries 128 bits of OS randomness rather than something
/// guessable like the process id. On a shared system the temp directory is
/// world-writable, so a predictable name lets another local user pre-create
/// the path — or plant a symlink at it — and control what we later read back
/// out of it. Creation is a plain `mkdir`, which fails if the path already
/// exists, so an existing directory or symlink is never adopted.
pub fn create_private_temp_dir(prefix: &str) -> io::Result<PathBuf> {
    let mut raw = [0u8; 16];
    generate_random_bytes(&mut raw);
    let suffix: String = raw.iter().map(|b| format!("{b:02x}")).collect();

    let path = std::env::temp_dir().join(format!("{prefix}-{suffix}"));
    create_private_temp_dir_at(&path)?;
    Ok(path)
}

/// Create one owner-only directory at exactly `path`, failing if anything is
/// already there. Split out so the create-never-adopts rule is testable.
fn create_private_temp_dir_at(path: &Path) -> io::Result<()> {
    // Built per-platform rather than mutated behind a `cfg`, which would
    // leave an unused `mut` on non-unix targets.
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
    };
    #[cfg(not(unix))]
    let builder = fs::DirBuilder::new();

    // Deliberately not `recursive(true)`: that would silently succeed on an
    // existing path, which is the behaviour this function exists to avoid.
    builder.create(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_a_directory_that_exists() {
        let dir = create_private_temp_dir("gitveil-test").unwrap();
        assert!(dir.is_dir(), "{} should be a directory", dir.display());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The old name was derived from the process id. On a shared system
    /// `/tmp` is world-writable, so a guessable name lets another local user
    /// pre-create the path (or plant a symlink at it) and control what we
    /// read back out. Names must be unpredictable.
    #[test]
    fn creates_a_distinct_directory_each_call() {
        let mut seen = std::collections::HashSet::new();
        let mut dirs = Vec::new();
        for _ in 0..25 {
            let dir = create_private_temp_dir("gitveil-test").unwrap();
            assert!(
                seen.insert(dir.clone()),
                "duplicate temp dir name: {}",
                dir.display()
            );
            dirs.push(dir);
        }
        for dir in dirs {
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// Creation must fail rather than adopt a path that already exists,
    /// so a pre-created directory or symlink can never be taken over.
    #[test]
    fn refuses_to_adopt_an_existing_path() {
        let dir = create_private_temp_dir("gitveil-test").unwrap();
        let err =
            create_private_temp_dir_at(&dir).expect_err("creating over an existing path must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn creates_the_directory_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = create_private_temp_dir("gitveil-test").unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o700,
            "temp dir must not be group/world accessible"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
