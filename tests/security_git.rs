//! Security regression tests for how gitveil drives git.
//!
//! Covers:
//! - lock/unlock run from a subdirectory must act on the whole repository,
//!   not only the cwd subtree (otherwise plaintext is left behind after the
//!   key is removed);
//! - filenames that git quotes or that break line-based parsing (non-ASCII,
//!   spaces, leading dash, glob characters, embedded newlines);
//! - status run from a subdirectory, and status blob checks for names with
//!   newlines;
//! - unlock refusing to run on a dirty working tree;
//! - status escaping control characters in filenames.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const HEADER: &[u8] = b"\x00GITCRYPT\x00";

fn gitveil_bin() -> PathBuf {
    let mut path = std::env::current_exe()
        .expect("cannot get test exe path")
        .parent()
        .expect("cannot get parent")
        .parent()
        .expect("cannot get grandparent")
        .to_path_buf();
    path.push("gitveil");
    path
}

fn gitveil(dir: &Path, args: &[&str]) -> Output {
    Command::new(gitveil_bin())
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|e| panic!("failed to run gitveil {:?}: {}", args, e))
}

fn git(dir: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|e| panic!("failed to run git {:?}: {}", args, e))
}

fn assert_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{} failed (exit {:?}):\nstdout: {}\nstderr: {}",
        context,
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn make_test_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("cannot create tempdir");
    assert_success(&git(dir.path(), &["init"]), "git init");
    assert_success(
        &git(dir.path(), &["config", "user.email", "test@gitveil.test"]),
        "git config email",
    );
    assert_success(
        &git(dir.path(), &["config", "user.name", "Test"]),
        "git config name",
    );
    // Make sure git quotes non-ASCII names in line-based output, which is
    // exactly what broke the old parser.
    assert_success(
        &git(dir.path(), &["config", "core.quotePath", "true"]),
        "git config quotePath",
    );
    fs::write(dir.path().join("README"), "test repo\n").unwrap();
    assert_success(&git(dir.path(), &["add", "README"]), "git add README");
    assert_success(
        &git(dir.path(), &["commit", "-m", "initial"]),
        "git commit initial",
    );
    dir
}

/// Initialise gitveil, write `.gitattributes` and the given files, commit
/// them all and export the key to a directory outside the repository (so
/// it does not show up as an untracked file).
fn setup_encrypted(dir: &Path, files: &[(&str, &str)]) -> (tempfile::TempDir, PathBuf) {
    assert_success(&gitveil(dir, &["init"]), "init");
    fs::write(
        dir.join(".gitattributes"),
        "*.secret filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();
    for (name, content) in files {
        let p = dir.join(name);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&p, content).unwrap();
    }
    // Add only the named files: `git add -A` could re-hash a file committed
    // earlier (racily clean) and silently encrypt a deliberately plaintext
    // blob that a status test relies on.
    let mut add_args = vec!["add", "--", ".gitattributes"];
    add_args.extend(files.iter().map(|(n, _)| *n));
    assert_success(&git(dir, &add_args), "git add");
    assert_success(&git(dir, &["commit", "-m", "secrets"]), "git commit");

    let key_dir = tempfile::tempdir().expect("cannot create key tempdir");
    let key_file = key_dir.path().join("key");
    assert_success(
        &gitveil(dir, &["export-key", key_file.to_str().unwrap()]),
        "export-key",
    );
    (key_dir, key_file)
}

fn assert_encrypted(path: &Path) {
    let data = fs::read(path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    assert!(
        data.starts_with(HEADER),
        "{} should be encrypted in the working tree, got {:?}",
        path.display(),
        String::from_utf8_lossy(&data),
    );
}

fn assert_plain(path: &Path, expected: &str) {
    let data =
        fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    assert_eq!(data, expected, "{} should be plaintext", path.display());
}

// ─── lock / unlock from a subdirectory ──────────────────────────

#[test]
fn test_lock_from_subdirectory_reencrypts_whole_repo() {
    let dir = make_test_repo();
    let root = dir.path();
    let files = [
        ("root.secret", "root secret\n"),
        ("sub/inner.secret", "inner secret\n"),
        ("sibling/other.secret", "sibling secret\n"),
    ];
    let (_kd, _key) = setup_encrypted(root, &files);

    assert_success(&gitveil(&root.join("sub"), &["lock"]), "lock from sub/");

    for (name, _) in &files {
        assert_encrypted(&root.join(name));
    }
    // Nothing should look modified: the working tree matches the
    // (encrypted) index everywhere.
    let st = git(root, &["status", "--porcelain", "-uno"]);
    assert_success(&st, "git status");
    assert!(
        st.stdout.is_empty(),
        "working tree should be clean after lock, got: {}",
        String::from_utf8_lossy(&st.stdout)
    );
}

#[test]
fn test_unlock_from_subdirectory_decrypts_whole_repo() {
    let dir = make_test_repo();
    let root = dir.path();
    let files = [
        ("root.secret", "root secret\n"),
        ("sub/inner.secret", "inner secret\n"),
        ("sibling/other.secret", "sibling secret\n"),
    ];
    let (_kd, key) = setup_encrypted(root, &files);

    assert_success(&gitveil(root, &["lock"]), "lock");
    for (name, _) in &files {
        assert_encrypted(&root.join(name));
    }

    assert_success(
        &gitveil(&root.join("sub"), &["unlock", key.to_str().unwrap()]),
        "unlock from sub/",
    );
    for (name, content) in &files {
        assert_plain(&root.join(name), content);
    }
}

// ─── special filenames ──────────────────────────────────────────

fn roundtrip_names(names: &[&str]) {
    let dir = make_test_repo();
    let root = dir.path();
    let files: Vec<(String, String)> = names
        .iter()
        .map(|n| (n.to_string(), format!("secret of {}\n", n.escape_default())))
        .collect();
    let refs: Vec<(&str, &str)> = files
        .iter()
        .map(|(n, c)| (n.as_str(), c.as_str()))
        .collect();
    let (_kd, key) = setup_encrypted(root, &refs);

    // Sanity: every blob in the index is encrypted.
    for (name, _) in &refs {
        let blob = git(root, &["cat-file", "blob", &format!(":{}", name)]);
        assert_success(&blob, "cat-file");
        assert!(
            blob.stdout.starts_with(HEADER),
            "{} blob should be encrypted",
            name.escape_default()
        );
    }

    assert_success(&gitveil(root, &["lock"]), "lock");
    for (name, _) in &refs {
        assert_encrypted(&root.join(name));
    }

    assert_success(&gitveil(root, &["unlock", key.to_str().unwrap()]), "unlock");
    for (name, content) in &refs {
        assert_plain(&root.join(name), content);
    }
}

#[test]
fn test_lock_unlock_non_ascii_filename() {
    roundtrip_names(&["é.secret", "dir-ü/日本.secret"]);
}

#[test]
fn test_lock_unlock_filename_with_spaces() {
    roundtrip_names(&["with space.secret", "a dir/two  spaces .secret"]);
}

#[test]
fn test_lock_unlock_filename_with_leading_dash() {
    roundtrip_names(&["-x.secret", "--force.secret"]);
}

#[test]
fn test_lock_unlock_filename_with_glob_characters() {
    // `[ab].secret` would be treated as a glob pathspec unless gitveil
    // passes paths literally. `a.secret` exists too so the glob would
    // match something else.
    roundtrip_names(&["[ab].secret", "a.secret"]);
}

#[cfg(unix)]
#[test]
fn test_lock_unlock_filename_with_newline_and_quotes() {
    roundtrip_names(&["new\nline.secret", "quo\"te.secret", "back\\slash.secret"]);
}

// ─── status ─────────────────────────────────────────────────────

#[test]
fn test_status_from_subdirectory_no_false_warnings() {
    let dir = make_test_repo();
    let root = dir.path();
    let files = [
        ("root.secret", "root secret\n"),
        ("sub/inner.secret", "inner secret\n"),
        ("sub/deeper/x.secret", "x\n"),
    ];
    let (_kd, _key) = setup_encrypted(root, &files);

    let out = gitveil(&root.join("sub"), &["status"]);
    assert_success(&out, "status from sub/");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("inner.secret"),
        "status should list files in the subdirectory, got: {}",
        stdout
    );
    assert!(
        !stdout.contains("WARNING") && !stderr.contains("Warning"),
        "correctly encrypted files must not produce warnings from a \
         subdirectory.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );
}

#[test]
fn test_status_from_subdirectory_detects_plain_blob() {
    let dir = make_test_repo();
    let root = dir.path();
    fs::create_dir_all(root.join("sub")).unwrap();
    fs::write(root.join("sub/leak.secret"), "leaked\n").unwrap();
    assert_success(&git(root, &["add", "sub/leak.secret"]), "add pre-filter");
    assert_success(&git(root, &["commit", "-m", "pre"]), "commit");
    let (_kd, _key) = setup_encrypted(root, &[]);

    let out = gitveil(&root.join("sub"), &["status"]);
    assert_success(&out, "status");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("leak.secret") && stdout.contains("WARNING"),
        "plaintext blob must be flagged from a subdirectory, got: {}",
        stdout
    );
}

#[test]
fn test_status_detects_plain_blob_non_ascii_name() {
    let dir = make_test_repo();
    let root = dir.path();
    fs::write(root.join("é.secret"), "leaked\n").unwrap();
    assert_success(&git(root, &["add", "é.secret"]), "add pre-filter");
    assert_success(&git(root, &["commit", "-m", "pre"]), "commit");
    let (_kd, _key) = setup_encrypted(root, &[]);

    let out = gitveil(root, &["status", "-u"]);
    assert_success(&out, "status -u");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("é.secret") && stdout.contains("WARNING"),
        "plaintext blob with non-ASCII name must be flagged, got: {}",
        stdout
    );
}

/// A newline in a filename used to desync the line-based `cat-file
/// --batch` protocol, which could hide a plaintext blob behind an
/// encrypted one.
#[cfg(unix)]
#[test]
fn test_status_detects_plain_blob_with_newline_in_name() {
    let dir = make_test_repo();
    let root = dir.path();
    let evil = "leak\nok.secret";
    fs::write(root.join(evil), "leaked plaintext\n").unwrap();
    assert_success(&git(root, &["add", "--", evil]), "add pre-filter");
    assert_success(&git(root, &["commit", "-m", "pre"]), "commit");
    // Correctly encrypted neighbours, added after the filter is in effect.
    let (_kd, _key) = setup_encrypted(root, &[("leak.secret", "fine\n"), ("ok.secret", "fine\n")]);

    let out = gitveil(root, &["status", "-u"]);
    assert_success(&out, "status -u");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let warning_lines: Vec<&str> = stdout.lines().filter(|l| l.contains("WARNING")).collect();
    assert_eq!(
        warning_lines.len(),
        1,
        "exactly the newline-named file should be flagged, got: {}",
        stdout
    );
    assert!(
        warning_lines[0].contains("leak") && warning_lines[0].contains("ok.secret"),
        "the warning should name the newline file (escaped onto one line), got: {}",
        warning_lines[0]
    );
}

/// Filenames are attacker-controlled repository content and must not be
/// able to emit terminal escape sequences through `status`.
#[cfg(unix)]
#[test]
fn test_status_escapes_control_characters_in_filenames() {
    let dir = make_test_repo();
    let root = dir.path();
    let evil = "\u{1b}[2J\u{1b}[31mevil.secret";
    let (_kd, _key) = setup_encrypted(root, &[(evil, "x\n"), ("plain.txt", "p\n")]);

    let out = gitveil(root, &["status", "-a"]);
    assert_success(&out, "status -a");
    assert!(
        !out.stdout.contains(&0x1b),
        "status output must not contain raw ESC bytes, got: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("evil.secret"),
        "the file should still be listed"
    );
}

// ─── unlock requires a clean working tree ───────────────────────

#[test]
fn test_unlock_refuses_dirty_working_tree() {
    let dir = make_test_repo();
    let root = dir.path();
    let (_kd, key) = setup_encrypted(root, &[("a.secret", "a\n")]);
    assert_success(&gitveil(root, &["lock"]), "lock");

    // Uncommitted edit to a tracked file.
    fs::write(root.join("README"), "local edit\n").unwrap();

    let out = gitveil(root, &["unlock", key.to_str().unwrap()]);
    assert!(
        !out.status.success(),
        "unlock must refuse with a dirty working tree, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr).to_lowercase();
    assert!(
        stderr.contains("uncommitted") || stderr.contains("dirty") || stderr.contains("clean"),
        "error should explain the dirty tree, got: {}",
        stderr
    );
    // The edit survives and nothing was unlocked.
    assert_plain(&root.join("README"), "local edit\n");
    assert_encrypted(&root.join("a.secret"));
}

#[test]
fn test_unlock_refuses_dirty_encrypted_file() {
    let dir = make_test_repo();
    let root = dir.path();
    let (_kd, key) = setup_encrypted(root, &[("a.secret", "a\n")]);
    assert_success(&gitveil(root, &["lock"]), "lock");

    // Overwrite the (locked) encrypted file: unlock would delete it.
    fs::write(root.join("a.secret"), "precious local edit\n").unwrap();

    let out = gitveil(root, &["unlock", key.to_str().unwrap()]);
    assert!(!out.status.success(), "unlock must refuse");
    assert_plain(&root.join("a.secret"), "precious local edit\n");
}

#[test]
fn test_unlock_allows_untracked_files() {
    // git-crypt only checks tracked files (`git status -uno`).
    let dir = make_test_repo();
    let root = dir.path();
    let (_kd, key) = setup_encrypted(root, &[("a.secret", "a\n")]);
    assert_success(&gitveil(root, &["lock"]), "lock");
    fs::write(root.join("untracked.txt"), "scratch\n").unwrap();

    assert_success(
        &gitveil(root, &["unlock", key.to_str().unwrap()]),
        "unlock with only untracked files",
    );
    assert_plain(&root.join("a.secret"), "a\n");
}
