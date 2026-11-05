//! Path checks for writing into repository-controlled directories.
//!
//! Everything under `.git-crypt/` is repository content. A cloned repository
//! can commit a symlink at `.git-crypt`, `.git-crypt/keys/<name>`, `.../0`,
//! `<FINGERPRINT>.gpg` or `.git-crypt/.gitattributes`; `create_dir_all`,
//! `gpg -o` and `fs::write` all follow symlinks, so writing through such a
//! path would land outside the repository.

use std::io;
use std::path::{Component, Path};

use crate::error::GitVeilError;

/// Refuse if any existing component of `path` below `root` is a symlink.
///
/// `root` itself is trusted (it comes from `git rev-parse --show-toplevel`)
/// and may legitimately sit behind a symlink such as macOS's `/tmp`. Only the
/// components *below* it are inspected, using `symlink_metadata` so the link
/// itself is examined rather than its target. Components that do not exist
/// yet are fine — they will be created as real directories or files — and
/// everything after the first missing component cannot exist either.
pub fn ensure_no_symlink_components(root: &Path, path: &Path) -> Result<(), GitVeilError> {
    let relative = path.strip_prefix(root).map_err(|_| {
        GitVeilError::Other(format!(
            "refusing to write '{}': it is not inside the repository",
            path.display()
        ))
    })?;

    let mut current = root.to_path_buf();
    for component in relative.components() {
        match component {
            Component::Normal(part) => current.push(part),
            Component::CurDir => continue,
            _ => {
                return Err(GitVeilError::Other(format!(
                    "refusing to write '{}': unexpected path component",
                    path.display()
                )))
            }
        }

        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(GitVeilError::Other(format!(
                    "refusing to write through symlink '{}' (repository content \
                     must not redirect writes outside the repository)",
                    current.display()
                )));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

/// Create `dir` (and its parents) below `root`, refusing to traverse symlinks.
///
/// Checked before creation so nothing is created through a link, and again
/// afterwards so a link swapped in between is still caught before any file
/// is written into the directory.
pub fn create_dir_all_no_symlinks(root: &Path, dir: &Path) -> Result<(), GitVeilError> {
    ensure_no_symlink_components(root, dir)?;
    std::fs::create_dir_all(dir)?;
    ensure_no_symlink_components(root, dir)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_missing_components() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("a").join("b").join("c.gpg");
        ensure_no_symlink_components(root.path(), &path).unwrap();
    }

    #[test]
    fn accepts_real_directories() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("a").join("b");
        create_dir_all_no_symlinks(root.path(), &dir).unwrap();
        assert!(dir.is_dir());
    }

    #[test]
    fn rejects_paths_outside_root() {
        let root = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        assert!(ensure_no_symlink_components(root.path(), other.path()).is_err());
    }

    #[test]
    fn rejects_parent_dir_components() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("..").join("x");
        assert!(ensure_no_symlink_components(root.path(), &path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_symlinked_intermediate_directory() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("a")).unwrap();
        let path = root.path().join("a").join("b").join("c.gpg");
        assert!(ensure_no_symlink_components(root.path(), &path).is_err());
        assert!(create_dir_all_no_symlinks(root.path(), &path).is_err());
        assert!(!outside.path().join("b").exists());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_dangling_symlink_leaf() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let leaf = root.path().join("leaf");
        std::os::unix::fs::symlink(outside.path().join("missing"), &leaf).unwrap();
        assert!(ensure_no_symlink_components(root.path(), &leaf).is_err());
    }
}
