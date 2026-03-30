//! Integration tests for gitveil.
//!
//! Each test creates a temporary git repository, runs gitveil commands via
//! the compiled binary, and verifies the results. Tests are isolated and
//! clean up automatically via `tempfile::TempDir`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Get the path to the compiled gitveil binary.
fn gitveil_bin() -> PathBuf {
    // cargo test builds to target/debug/gitveil
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

/// Run gitveil with the given args in the given directory.
fn gitveil(dir: &Path, args: &[&str]) -> Output {
    Command::new(gitveil_bin())
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|e| panic!("failed to run gitveil {:?}: {}", args, e))
}

/// Run git with the given args in the given directory.
fn git(dir: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|e| panic!("failed to run git {:?}: {}", args, e))
}

/// Assert a command succeeded, printing stderr on failure.
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

/// Create a temp directory with an initialized git repo.
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
    // Initial commit so HEAD exists
    let readme = dir.path().join("README");
    fs::write(&readme, "test repo\n").unwrap();
    assert_success(&git(dir.path(), &["add", "README"]), "git add README");
    assert_success(
        &git(dir.path(), &["commit", "-m", "initial"]),
        "git commit initial",
    );
    dir
}

// ─── Tests ──────────────────────────────────────────────────────

#[test]
fn test_init_creates_key_and_configures_filters() {
    let dir = make_test_repo();

    let out = gitveil(dir.path(), &["init"]);
    assert_success(&out, "gitveil init");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Initialized"),
        "init should print confirmation"
    );

    // Key file should exist with restricted permissions
    let key_path = dir.path().join(".git/git-crypt/keys/default");
    assert!(key_path.exists(), "key file should exist at {:?}", key_path);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key file should be mode 0600");
    }

    // Git filter should be configured
    let filter = git(dir.path(), &["config", "--get", "filter.git-crypt.smudge"]);
    assert_success(&filter, "filter.git-crypt.smudge should be set");
    let smudge = String::from_utf8_lossy(&filter.stdout);
    assert!(
        smudge.contains("smudge"),
        "smudge filter should contain 'smudge'"
    );
}

#[test]
fn test_init_twice_fails() {
    let dir = make_test_repo();

    assert_success(&gitveil(dir.path(), &["init"]), "first init");

    let out = gitveil(dir.path(), &["init"]);
    assert!(!out.status.success(), "second init should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Already initialized"),
        "should say already initialized, got: {}",
        stderr
    );
}

#[test]
fn test_init_named_key() {
    let dir = make_test_repo();

    let out = gitveil(dir.path(), &["init", "-k", "backend"]);
    assert_success(&out, "gitveil init -k backend");

    let key_path = dir.path().join(".git/git-crypt/keys/backend");
    assert!(key_path.exists(), "named key should exist");

    let filter = git(
        dir.path(),
        &["config", "--get", "filter.git-crypt-backend.smudge"],
    );
    assert_success(&filter, "named key filter should be configured");
}

#[test]
fn test_full_encrypt_decrypt_roundtrip() {
    let dir = make_test_repo();
    let key_file = dir.path().join("exported-key");
    let secret_content = "DATABASE_URL=postgres://admin:secret@db/prod\n";

    // 1. Init
    assert_success(&gitveil(dir.path(), &["init"]), "init");

    // 2. Set up .gitattributes and secret file
    fs::write(
        dir.path().join(".gitattributes"),
        "*.secret filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();
    fs::write(dir.path().join("creds.secret"), secret_content).unwrap();

    assert_success(
        &git(dir.path(), &["add", ".gitattributes", "creds.secret"]),
        "git add",
    );
    assert_success(
        &git(dir.path(), &["commit", "-m", "add secrets"]),
        "git commit",
    );

    // 3. Verify blob is encrypted
    let blob = git(dir.path(), &["show", ":creds.secret"]);
    assert_success(&blob, "git show blob");
    assert!(
        blob.stdout.starts_with(b"\x00GITCRYPT\x00"),
        "blob should start with GITCRYPT header"
    );

    // 4. Working copy should still be plaintext
    let content = fs::read_to_string(dir.path().join("creds.secret")).unwrap();
    assert_eq!(content, secret_content, "working copy should be plaintext");

    // 5. Export key
    assert_success(
        &gitveil(dir.path(), &["export-key", key_file.to_str().unwrap()]),
        "export-key",
    );
    assert!(key_file.exists(), "exported key file should exist");

    // 6. Lock — working copy should become encrypted
    assert_success(&gitveil(dir.path(), &["lock", "--force"]), "lock");
    let locked_content = fs::read(dir.path().join("creds.secret")).unwrap();
    assert!(
        locked_content.starts_with(b"\x00GITCRYPT\x00"),
        "locked file should start with GITCRYPT header"
    );

    // 7. Unlock — working copy should be plaintext again
    assert_success(
        &gitveil(dir.path(), &["unlock", key_file.to_str().unwrap()]),
        "unlock",
    );
    let unlocked_content = fs::read_to_string(dir.path().join("creds.secret")).unwrap();
    assert_eq!(
        unlocked_content, secret_content,
        "unlocked content should match original"
    );
}

#[test]
fn test_status_shows_encrypted_files() {
    let dir = make_test_repo();

    assert_success(&gitveil(dir.path(), &["init"]), "init");

    fs::write(
        dir.path().join(".gitattributes"),
        "*.secret filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();
    fs::write(dir.path().join("a.secret"), "secret-a\n").unwrap();
    fs::write(dir.path().join("b.secret"), "secret-b\n").unwrap();
    fs::write(dir.path().join("public.txt"), "public\n").unwrap();

    assert_success(
        &git(
            dir.path(),
            &[
                "add",
                ".gitattributes",
                "a.secret",
                "b.secret",
                "public.txt",
            ],
        ),
        "git add",
    );
    assert_success(
        &git(dir.path(), &["commit", "-m", "add files"]),
        "git commit",
    );

    let out = gitveil(dir.path(), &["status"]);
    assert_success(&out, "status");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("a.secret"), "status should list a.secret");
    assert!(stdout.contains("b.secret"), "status should list b.secret");
    assert!(
        !stdout.contains("public.txt"),
        "status should NOT list public.txt"
    );
}

#[test]
fn test_quiet_flag_suppresses_output() {
    let dir = make_test_repo();

    let out = gitveil(dir.path(), &["-q", "init"]);
    assert_success(&out, "quiet init");
    assert!(
        out.stderr.is_empty(),
        "quiet mode should produce no stderr, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn test_lock_without_init_fails() {
    let dir = make_test_repo();

    let out = gitveil(dir.path(), &["lock"]);
    assert!(!out.status.success(), "lock without init should fail");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("gitveil init"),
        "error should suggest gitveil init, got: {}",
        stderr
    );
}

#[test]
fn test_export_key_to_file() {
    let dir = make_test_repo();
    let key_file = dir.path().join("my-key");

    assert_success(&gitveil(dir.path(), &["init"]), "init");

    let out = gitveil(dir.path(), &["export-key", key_file.to_str().unwrap()]);
    assert_success(&out, "export-key");

    // Verify it's a valid key file (starts with GITCRYPTKEY header)
    let key_data = fs::read(&key_file).unwrap();
    assert!(
        key_data.starts_with(b"\x00GITCRYPTKEY"),
        "exported key should start with GITCRYPTKEY header"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&key_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "exported key should be mode 0600");
    }
}

#[test]
fn test_export_key_to_stdout() {
    let dir = make_test_repo();

    assert_success(&gitveil(dir.path(), &["init"]), "init");

    let out = gitveil(dir.path(), &["export-key"]);
    assert_success(&out, "export-key to stdout");
    assert!(
        out.stdout.starts_with(b"\x00GITCRYPTKEY"),
        "stdout should contain key file data"
    );
}

#[test]
fn test_lock_dirty_workdir_rejected() {
    let dir = make_test_repo();

    assert_success(&gitveil(dir.path(), &["init"]), "init");

    // Create uncommitted change
    fs::write(dir.path().join("dirty.txt"), "uncommitted\n").unwrap();
    assert_success(&git(dir.path(), &["add", "dirty.txt"]), "git add");

    let out = gitveil(dir.path(), &["lock"]);
    assert!(!out.status.success(), "lock with dirty workdir should fail");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("dirty") || stderr.contains("--force"),
        "should mention dirty or --force, got: {}",
        stderr
    );
}

#[test]
fn test_lock_force_with_dirty_workdir() {
    let dir = make_test_repo();

    assert_success(&gitveil(dir.path(), &["init"]), "init");

    fs::write(
        dir.path().join(".gitattributes"),
        "*.secret filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();
    fs::write(dir.path().join("s.secret"), "secret\n").unwrap();

    assert_success(
        &git(dir.path(), &["add", ".gitattributes", "s.secret"]),
        "git add",
    );
    assert_success(&git(dir.path(), &["commit", "-m", "add"]), "git commit");

    // Create dirty state
    fs::write(dir.path().join("untracked.txt"), "junk\n").unwrap();

    let out = gitveil(dir.path(), &["lock", "--force"]);
    assert_success(&out, "lock --force should succeed despite dirty workdir");
}

#[test]
fn test_empty_file_roundtrip() {
    let dir = make_test_repo();
    let key_file = dir.path().join("key");

    assert_success(&gitveil(dir.path(), &["init"]), "init");

    fs::write(
        dir.path().join(".gitattributes"),
        "*.secret filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();
    fs::write(dir.path().join("empty.secret"), "").unwrap();

    assert_success(
        &git(dir.path(), &["add", ".gitattributes", "empty.secret"]),
        "git add",
    );
    assert_success(&git(dir.path(), &["commit", "-m", "empty"]), "git commit");

    assert_success(
        &gitveil(dir.path(), &["export-key", key_file.to_str().unwrap()]),
        "export-key",
    );
    assert_success(&gitveil(dir.path(), &["lock", "--force"]), "lock");
    assert_success(
        &gitveil(dir.path(), &["unlock", key_file.to_str().unwrap()]),
        "unlock",
    );

    let content = fs::read_to_string(dir.path().join("empty.secret")).unwrap();
    assert_eq!(content, "", "empty file should survive roundtrip");
}

#[test]
fn test_binary_file_roundtrip() {
    let dir = make_test_repo();
    let key_file = dir.path().join("key");

    assert_success(&gitveil(dir.path(), &["init"]), "init");

    fs::write(
        dir.path().join(".gitattributes"),
        "*.secret filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();

    // Write binary content with null bytes
    let binary_data: Vec<u8> = (0u8..=255).collect();
    fs::write(dir.path().join("bin.secret"), &binary_data).unwrap();

    assert_success(
        &git(dir.path(), &["add", ".gitattributes", "bin.secret"]),
        "git add",
    );
    assert_success(&git(dir.path(), &["commit", "-m", "binary"]), "git commit");

    assert_success(
        &gitveil(dir.path(), &["export-key", key_file.to_str().unwrap()]),
        "export-key",
    );
    assert_success(&gitveil(dir.path(), &["lock", "--force"]), "lock");
    assert_success(
        &gitveil(dir.path(), &["unlock", key_file.to_str().unwrap()]),
        "unlock",
    );

    let content = fs::read(dir.path().join("bin.secret")).unwrap();
    assert_eq!(content, binary_data, "binary file should survive roundtrip");
}

#[test]
fn test_version_flag() {
    let out = Command::new(gitveil_bin())
        .arg("--version")
        .output()
        .expect("failed to run gitveil --version");
    assert_success(&out, "--version");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("gitveil"),
        "--version should mention gitveil, got: {}",
        stdout
    );
}

#[test]
fn test_not_a_git_repo_error() {
    let dir = tempfile::tempdir().expect("cannot create tempdir");
    // Don't init git — just a plain directory

    let out = gitveil(dir.path(), &["init"]);
    assert!(!out.status.success(), "init outside git repo should fail");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("git repo"),
        "should mention git repo, got: {}",
        stderr
    );
}

#[test]
fn test_lock_all_keys() {
    let dir = make_test_repo();
    let key_default = dir.path().join("key-default");
    let key_backend = dir.path().join("key-backend");

    // Init two keys
    assert_success(&gitveil(dir.path(), &["init"]), "init default");
    assert_success(
        &gitveil(dir.path(), &["init", "-k", "backend"]),
        "init backend",
    );

    fs::write(
        dir.path().join(".gitattributes"),
        "*.secret filter=git-crypt diff=git-crypt\n*.back filter=git-crypt-backend diff=git-crypt-backend\n",
    )
    .unwrap();
    fs::write(dir.path().join("a.secret"), "default-secret\n").unwrap();
    fs::write(dir.path().join("b.back"), "backend-secret\n").unwrap();

    assert_success(
        &git(dir.path(), &["add", ".gitattributes", "a.secret", "b.back"]),
        "git add",
    );
    assert_success(&git(dir.path(), &["commit", "-m", "secrets"]), "commit");

    assert_success(
        &gitveil(dir.path(), &["export-key", key_default.to_str().unwrap()]),
        "export default key",
    );
    assert_success(
        &gitveil(
            dir.path(),
            &["export-key", "-k", "backend", key_backend.to_str().unwrap()],
        ),
        "export backend key",
    );

    // Lock all
    assert_success(
        &gitveil(dir.path(), &["lock", "--all", "--force"]),
        "lock --all",
    );

    // Both should be encrypted
    let a = fs::read(dir.path().join("a.secret")).unwrap();
    let b = fs::read(dir.path().join("b.back")).unwrap();
    assert!(
        a.starts_with(b"\x00GITCRYPT\x00"),
        "a.secret should be encrypted"
    );
    assert!(
        b.starts_with(b"\x00GITCRYPT\x00"),
        "b.back should be encrypted"
    );
}
