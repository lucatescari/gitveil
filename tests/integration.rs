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

#[test]
fn test_status_many_files_no_deadlock() {
    // Regression test: the status command used to deadlock on repos with
    // enough encrypted files to overflow the OS pipe buffer (~64 KB).
    // This creates 200 encrypted files to exercise the concurrent I/O path.
    let dir = make_test_repo();

    assert_success(&gitveil(dir.path(), &["init"]), "init");

    fs::write(
        dir.path().join(".gitattributes"),
        "secret-* filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();

    for i in 0..200 {
        fs::write(
            dir.path().join(format!("secret-{:04}.txt", i)),
            format!("sensitive-data-{}\n", i),
        )
        .unwrap();
    }

    // Also add plain files so status has to filter
    for i in 0..200 {
        fs::write(
            dir.path().join(format!("plain-{:04}.txt", i)),
            format!("public-data-{}\n", i),
        )
        .unwrap();
    }

    assert_success(&git(dir.path(), &["add", "-A"]), "git add");
    assert_success(
        &git(dir.path(), &["commit", "-m", "many files"]),
        "git commit",
    );

    // This would hang forever before the deadlock fix
    let out = gitveil(dir.path(), &["status"]);
    assert_success(&out, "status with many files");

    let stdout = String::from_utf8_lossy(&out.stdout);
    // All 200 secret files should appear
    assert!(
        stdout.contains("secret-0000.txt"),
        "should list first encrypted file"
    );
    assert!(
        stdout.contains("secret-0199.txt"),
        "should list last encrypted file"
    );
    // Plain files should not appear (they don't have the filter)
    assert!(
        !stdout.contains("plain-0000.txt"),
        "should not list plain files"
    );
}

#[test]
fn test_status_large_blobs_no_deadlock() {
    // Regression test: even a single large blob can fill the stdout pipe
    // buffer and deadlock if stdin/stdout aren't handled concurrently.
    let dir = make_test_repo();

    assert_success(&gitveil(dir.path(), &["init"]), "init");

    fs::write(
        dir.path().join(".gitattributes"),
        "*.bin filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();

    // Create a 256 KB file — well above the 64 KB pipe buffer
    let large_data: Vec<u8> = (0..256 * 1024).map(|i| (i % 256) as u8).collect();
    fs::write(dir.path().join("asset.bin"), &large_data).unwrap();

    assert_success(&git(dir.path(), &["add", "-A"]), "git add");
    assert_success(
        &git(dir.path(), &["commit", "-m", "large blob"]),
        "git commit",
    );

    let out = gitveil(dir.path(), &["status"]);
    assert_success(&out, "status with large blob");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("asset.bin"),
        "should list the large encrypted file"
    );
}

#[test]
fn test_unlock_many_files_no_deadlock() {
    // Regression test: unlock used to deadlock on repos with enough tracked
    // files to overflow the OS pipe buffer (~64 KB) in get_encrypted_files().
    // The bug was identical to the status deadlock but in a different code path.
    let dir = make_test_repo();
    let key_file = dir.path().join("key");

    assert_success(&gitveil(dir.path(), &["init"]), "init");

    fs::write(
        dir.path().join(".gitattributes"),
        "secret-* filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();

    // Create enough files to overflow the pipe buffer.
    // Only a few are encrypted; the rest are plain — this exercises the
    // attribute-checking path that scans ALL tracked files via stdin.
    for i in 0..20 {
        fs::write(
            dir.path().join(format!("secret-{:04}.txt", i)),
            format!("sensitive-data-{}\n", i),
        )
        .unwrap();
    }
    for i in 0..2000 {
        fs::write(
            dir.path().join(format!("plain-{:04}.txt", i)),
            format!("public-data-{}\n", i),
        )
        .unwrap();
    }

    assert_success(&git(dir.path(), &["add", "-A"]), "git add");
    assert_success(
        &git(dir.path(), &["commit", "-m", "many files"]),
        "git commit",
    );

    assert_success(
        &gitveil(dir.path(), &["export-key", key_file.to_str().unwrap()]),
        "export-key",
    );
    assert_success(&gitveil(dir.path(), &["lock", "--force"]), "lock");

    // Verify files are encrypted
    let locked = fs::read(dir.path().join("secret-0000.txt")).unwrap();
    assert!(
        locked.starts_with(b"\x00GITCRYPT\x00"),
        "secret should be encrypted after lock"
    );

    // This would hang forever before the deadlock fix in get_encrypted_files()
    assert_success(
        &gitveil(dir.path(), &["unlock", key_file.to_str().unwrap()]),
        "unlock with many tracked files",
    );

    // Verify decryption
    let content = fs::read_to_string(dir.path().join("secret-0000.txt")).unwrap();
    assert_eq!(content, "sensitive-data-0\n", "should decrypt correctly");

    let content = fs::read_to_string(dir.path().join("secret-0019.txt")).unwrap();
    assert_eq!(content, "sensitive-data-19\n", "should decrypt last file");
}

#[test]
fn test_lock_many_files_no_deadlock() {
    // Lock also calls get_encrypted_files() — verify it doesn't deadlock either.
    let dir = make_test_repo();
    let key_file = dir.path().join("key");

    assert_success(&gitveil(dir.path(), &["init"]), "init");

    fs::write(
        dir.path().join(".gitattributes"),
        "secret-* filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();

    for i in 0..20 {
        fs::write(
            dir.path().join(format!("secret-{:04}.txt", i)),
            format!("sensitive-data-{}\n", i),
        )
        .unwrap();
    }
    for i in 0..2000 {
        fs::write(
            dir.path().join(format!("plain-{:04}.txt", i)),
            format!("public-data-{}\n", i),
        )
        .unwrap();
    }

    assert_success(&git(dir.path(), &["add", "-A"]), "git add");
    assert_success(
        &git(dir.path(), &["commit", "-m", "many files"]),
        "git commit",
    );

    assert_success(
        &gitveil(dir.path(), &["export-key", key_file.to_str().unwrap()]),
        "export-key",
    );

    // This would hang forever if lock's get_encrypted_files() deadlocked
    assert_success(
        &gitveil(dir.path(), &["lock", "--force"]),
        "lock with many tracked files",
    );

    let locked = fs::read(dir.path().join("secret-0000.txt")).unwrap();
    assert!(
        locked.starts_with(b"\x00GITCRYPT\x00"),
        "secret should be encrypted after lock"
    );
}

// ─── Config Tests ──────────────────────────────────────────────

/// Run gitveil with a custom XDG_CONFIG_HOME for isolated config testing.
fn gitveil_with_config_home(config_home: &Path, dir: &Path, args: &[&str]) -> Output {
    Command::new(gitveil_bin())
        .args(args)
        .current_dir(dir)
        .env("XDG_CONFIG_HOME", config_home)
        .output()
        .unwrap_or_else(|e| panic!("failed to run gitveil {:?}: {}", args, e))
}

#[test]
fn test_config_set_keyring_valid_directory() {
    let config_home = tempfile::tempdir().unwrap();
    let keyring_dir = tempfile::tempdir().unwrap();
    let work_dir = tempfile::tempdir().unwrap();

    let out = gitveil_with_config_home(
        config_home.path(),
        work_dir.path(),
        &[
            "config",
            "set-keyring",
            &keyring_dir.path().to_string_lossy(),
        ],
    );
    assert_success(&out, "config set-keyring");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Set"),
        "should confirm keyring was set: {}",
        stderr
    );

    // Config file should exist
    let config_file = config_home.path().join("gitveil").join("config");
    assert!(config_file.exists(), "config file should be created");
}

#[test]
fn test_config_set_keyring_nonexistent_path_fails() {
    let config_home = tempfile::tempdir().unwrap();
    let work_dir = tempfile::tempdir().unwrap();

    let out = gitveil_with_config_home(
        config_home.path(),
        work_dir.path(),
        &[
            "config",
            "set-keyring",
            "/nonexistent/path/that/does/not/exist",
        ],
    );
    assert!(!out.status.success(), "should fail for nonexistent path");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("does not exist"),
        "should mention path doesn't exist: {}",
        stderr
    );
}

#[test]
fn test_config_set_keyring_file_not_dir_fails() {
    let config_home = tempfile::tempdir().unwrap();
    let work_dir = tempfile::tempdir().unwrap();

    let file = work_dir.path().join("not-a-dir.txt");
    fs::write(&file, "hello").unwrap();

    let out = gitveil_with_config_home(
        config_home.path(),
        work_dir.path(),
        &["config", "set-keyring", &file.to_string_lossy()],
    );
    assert!(!out.status.success(), "should fail when path is a file");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not a directory"),
        "should say not a directory: {}",
        stderr
    );
}

#[test]
fn test_config_set_keyring_show_roundtrip() {
    let config_home = tempfile::tempdir().unwrap();
    let keyring_dir = tempfile::tempdir().unwrap();
    let work_dir = tempfile::tempdir().unwrap();

    // Set
    let out = gitveil_with_config_home(
        config_home.path(),
        work_dir.path(),
        &[
            "config",
            "set-keyring",
            &keyring_dir.path().to_string_lossy(),
        ],
    );
    assert_success(&out, "config set-keyring");

    // Show
    let out = gitveil_with_config_home(config_home.path(), work_dir.path(), &["config", "show"]);
    assert_success(&out, "config show");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The stored path is canonicalized, so compare canonical forms
    let expected = fs::canonicalize(keyring_dir.path()).unwrap();
    assert!(
        stdout.contains(&expected.to_string_lossy().to_string()),
        "show should display keyring path.\nExpected to contain: {}\nGot: {}",
        expected.display(),
        stdout
    );
}

#[test]
fn test_config_unset_keyring() {
    let config_home = tempfile::tempdir().unwrap();
    let keyring_dir = tempfile::tempdir().unwrap();
    let work_dir = tempfile::tempdir().unwrap();

    // Set
    let out = gitveil_with_config_home(
        config_home.path(),
        work_dir.path(),
        &[
            "config",
            "set-keyring",
            &keyring_dir.path().to_string_lossy(),
        ],
    );
    assert_success(&out, "config set-keyring");

    // Unset
    let out = gitveil_with_config_home(
        config_home.path(),
        work_dir.path(),
        &["config", "unset-keyring"],
    );
    assert_success(&out, "config unset-keyring");

    // Show should report not set
    let out = gitveil_with_config_home(config_home.path(), work_dir.path(), &["config", "show"]);
    assert_success(&out, "config show after unset");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("not set"),
        "should say not set after unset: {}",
        stdout
    );
}

#[test]
fn test_config_show_no_config() {
    let config_home = tempfile::tempdir().unwrap();
    let work_dir = tempfile::tempdir().unwrap();

    let out = gitveil_with_config_home(config_home.path(), work_dir.path(), &["config", "show"]);
    assert_success(&out, "config show with no config");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("not set"),
        "should say not set when no config exists: {}",
        stdout
    );
}

#[cfg(unix)]
#[test]
fn test_config_file_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let config_home = tempfile::tempdir().unwrap();
    let keyring_dir = tempfile::tempdir().unwrap();
    let work_dir = tempfile::tempdir().unwrap();

    let out = gitveil_with_config_home(
        config_home.path(),
        work_dir.path(),
        &[
            "config",
            "set-keyring",
            &keyring_dir.path().to_string_lossy(),
        ],
    );
    assert_success(&out, "config set-keyring");

    let config_file = config_home.path().join("gitveil").join("config");
    let mode = fs::metadata(&config_file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "config file should be 0o600, got 0o{:o}", mode);
}

#[cfg(unix)]
#[test]
fn test_config_dir_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let config_home = tempfile::tempdir().unwrap();
    let keyring_dir = tempfile::tempdir().unwrap();
    let work_dir = tempfile::tempdir().unwrap();

    let out = gitveil_with_config_home(
        config_home.path(),
        work_dir.path(),
        &[
            "config",
            "set-keyring",
            &keyring_dir.path().to_string_lossy(),
        ],
    );
    assert_success(&out, "config set-keyring");

    let config_dir = config_home.path().join("gitveil");
    let mode = fs::metadata(&config_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "config dir should be 0o700, got 0o{:o}", mode);
}

#[test]
fn test_config_set_keyring_overwrites() {
    let config_home = tempfile::tempdir().unwrap();
    let keyring_dir1 = tempfile::tempdir().unwrap();
    let keyring_dir2 = tempfile::tempdir().unwrap();
    let work_dir = tempfile::tempdir().unwrap();

    // Set first
    let out = gitveil_with_config_home(
        config_home.path(),
        work_dir.path(),
        &[
            "config",
            "set-keyring",
            &keyring_dir1.path().to_string_lossy(),
        ],
    );
    assert_success(&out, "config set-keyring first");

    // Set second (overwrite)
    let out = gitveil_with_config_home(
        config_home.path(),
        work_dir.path(),
        &[
            "config",
            "set-keyring",
            &keyring_dir2.path().to_string_lossy(),
        ],
    );
    assert_success(&out, "config set-keyring second");

    // Show should have second path
    let out = gitveil_with_config_home(config_home.path(), work_dir.path(), &["config", "show"]);
    assert_success(&out, "config show after overwrite");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let expected = fs::canonicalize(keyring_dir2.path()).unwrap();
    assert!(
        stdout.contains(&expected.to_string_lossy().to_string()),
        "should show second path.\nExpected: {}\nGot: {}",
        expected.display(),
        stdout
    );
}

#[test]
fn test_config_set_keyring_path_canonicalized() {
    let config_home = tempfile::tempdir().unwrap();
    let keyring_dir = tempfile::tempdir().unwrap();
    let work_dir = tempfile::tempdir().unwrap();

    // Use a path with .. component
    let subdir = keyring_dir.path().join("sub");
    fs::create_dir(&subdir).unwrap();
    let dotdot_path = subdir.join("..");

    let out = gitveil_with_config_home(
        config_home.path(),
        work_dir.path(),
        &["config", "set-keyring", &dotdot_path.to_string_lossy()],
    );
    assert_success(&out, "config set-keyring with ..");

    // Read raw config to verify it's canonicalized (no ..)
    let config_file = config_home.path().join("gitveil").join("config");
    let content = fs::read_to_string(&config_file).unwrap();
    assert!(
        !content.contains(".."),
        "stored path should be canonicalized (no '..'): {}",
        content
    );
}

#[cfg(unix)]
#[test]
fn test_config_set_keyring_symlink_resolved() {
    let config_home = tempfile::tempdir().unwrap();
    let real_dir = tempfile::tempdir().unwrap();
    let work_dir = tempfile::tempdir().unwrap();

    // Create a symlink to the real directory
    let symlink_path = work_dir.path().join("keyring-link");
    std::os::unix::fs::symlink(real_dir.path(), &symlink_path).unwrap();

    let out = gitveil_with_config_home(
        config_home.path(),
        work_dir.path(),
        &["config", "set-keyring", &symlink_path.to_string_lossy()],
    );
    assert_success(&out, "config set-keyring symlink");

    // Read raw config — should contain the real path, not the symlink
    let config_file = config_home.path().join("gitveil").join("config");
    let content = fs::read_to_string(&config_file).unwrap();
    let expected = fs::canonicalize(real_dir.path()).unwrap();
    assert_eq!(
        content.trim(),
        expected.to_string_lossy().as_ref(),
        "stored path should be the real path, not the symlink"
    );
}

#[cfg(unix)]
#[test]
fn test_config_set_keyring_rejects_symlink_to_file() {
    let config_home = tempfile::tempdir().unwrap();
    let work_dir = tempfile::tempdir().unwrap();

    // Create a regular file
    let file = work_dir.path().join("not-a-dir.txt");
    fs::write(&file, "hello").unwrap();

    // Create symlink to that file
    let symlink_path = work_dir.path().join("link-to-file");
    std::os::unix::fs::symlink(&file, &symlink_path).unwrap();

    let out = gitveil_with_config_home(
        config_home.path(),
        work_dir.path(),
        &["config", "set-keyring", &symlink_path.to_string_lossy()],
    );
    assert!(!out.status.success(), "should reject symlink to file");
}

// ─── add-gpg-user Keyring Fallback Tests ───────────────────────

#[test]
fn test_add_gpg_user_no_args_no_keyring_shows_error() {
    let dir = make_test_repo();
    let config_home = tempfile::tempdir().unwrap();

    // Init so the repo has keys
    assert_success(
        &gitveil_with_config_home(config_home.path(), dir.path(), &["init"]),
        "gitveil init",
    );

    // No args, no keyring configured
    let out = gitveil_with_config_home(config_home.path(), dir.path(), &["add-gpg-user"]);
    assert!(
        !out.status.success(),
        "should fail with no args and no keyring"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("GPG user ID is required") || stderr.contains("set-keyring"),
        "should mention GPG user ID or keyring setup: {}",
        stderr
    );
}

#[test]
fn test_add_gpg_user_no_args_keyring_configured_but_empty_dir_errors() {
    let dir = make_test_repo();
    let config_home = tempfile::tempdir().unwrap();
    let empty_keyring = tempfile::tempdir().unwrap();

    // Init
    assert_success(
        &gitveil_with_config_home(config_home.path(), dir.path(), &["init"]),
        "gitveil init",
    );

    // Configure keyring to empty dir
    assert_success(
        &gitveil_with_config_home(
            config_home.path(),
            dir.path(),
            &[
                "config",
                "set-keyring",
                &empty_keyring.path().to_string_lossy(),
            ],
        ),
        "config set-keyring",
    );

    // add-gpg-user with no args should try keyring, find nothing
    let out = gitveil_with_config_home(config_home.path(), dir.path(), &["add-gpg-user"]);
    assert!(
        !out.status.success(),
        "should fail when keyring dir is empty"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no GPG public key files found"),
        "should say no keys found: {}",
        stderr
    );
}

#[test]
fn test_add_gpg_user_no_args_keyring_dir_gone_errors() {
    let dir = make_test_repo();
    let config_home = tempfile::tempdir().unwrap();
    let keyring = tempfile::tempdir().unwrap();
    let keyring_path = keyring.path().to_path_buf();

    // Init
    assert_success(
        &gitveil_with_config_home(config_home.path(), dir.path(), &["init"]),
        "gitveil init",
    );

    // Configure keyring
    assert_success(
        &gitveil_with_config_home(
            config_home.path(),
            dir.path(),
            &["config", "set-keyring", &keyring_path.to_string_lossy()],
        ),
        "config set-keyring",
    );

    // Delete the keyring directory
    drop(keyring);
    assert!(!keyring_path.exists(), "keyring dir should be deleted");

    // add-gpg-user should report the dir is gone
    let out = gitveil_with_config_home(config_home.path(), dir.path(), &["add-gpg-user"]);
    assert!(
        !out.status.success(),
        "should fail when keyring dir is deleted"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no longer exists"),
        "should say keyring path no longer exists: {}",
        stderr
    );
}

#[test]
fn test_add_gpg_user_from_still_takes_precedence() {
    let dir = make_test_repo();
    let config_home = tempfile::tempdir().unwrap();
    let keyring = tempfile::tempdir().unwrap();
    let from_dir = tempfile::tempdir().unwrap();

    // Init
    assert_success(
        &gitveil_with_config_home(config_home.path(), dir.path(), &["init"]),
        "gitveil init",
    );

    // Configure keyring
    assert_success(
        &gitveil_with_config_home(
            config_home.path(),
            dir.path(),
            &["config", "set-keyring", &keyring.path().to_string_lossy()],
        ),
        "config set-keyring",
    );

    // --from with an empty dir should use --from, not keyring
    let out = gitveil_with_config_home(
        config_home.path(),
        dir.path(),
        &["add-gpg-user", "--from", &from_dir.path().to_string_lossy()],
    );
    assert!(!out.status.success(), "should fail (empty --from dir)");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no GPG public key files found"),
        "--from should take precedence over keyring: {}",
        stderr
    );
}

#[test]
fn test_add_gpg_user_userid_still_takes_precedence() {
    let dir = make_test_repo();
    let config_home = tempfile::tempdir().unwrap();
    let keyring = tempfile::tempdir().unwrap();

    // Init
    assert_success(
        &gitveil_with_config_home(config_home.path(), dir.path(), &["init"]),
        "gitveil init",
    );

    // Configure keyring
    assert_success(
        &gitveil_with_config_home(
            config_home.path(),
            dir.path(),
            &["config", "set-keyring", &keyring.path().to_string_lossy()],
        ),
        "config set-keyring",
    );

    // Provide a bogus user ID — should attempt GPG lookup, not keyring scan
    let out = gitveil_with_config_home(
        config_home.path(),
        dir.path(),
        &["add-gpg-user", "nonexistent-user@test.invalid"],
    );
    assert!(
        !out.status.success(),
        "should fail (user not in GPG keyring)"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Should be a GPG error, not a keyring/scan error
    assert!(
        stderr.to_lowercase().contains("gpg"),
        "error should be from GPG lookup, not keyring scan: {}",
        stderr
    );
}

// ─── Scan Security Tests ───────────────────────────────────────

#[test]
fn test_scan_skips_non_key_extensions() {
    let dir = make_test_repo();
    let config_home = tempfile::tempdir().unwrap();
    let keyring = tempfile::tempdir().unwrap();

    // Create files with non-key extensions
    fs::write(keyring.path().join("readme.txt"), "not a key").unwrap();
    fs::write(keyring.path().join("notes.md"), "not a key").unwrap();
    fs::write(keyring.path().join("data.json"), "not a key").unwrap();

    // Init
    assert_success(
        &gitveil_with_config_home(config_home.path(), dir.path(), &["init"]),
        "gitveil init",
    );

    // Configure keyring
    assert_success(
        &gitveil_with_config_home(
            config_home.path(),
            dir.path(),
            &["config", "set-keyring", &keyring.path().to_string_lossy()],
        ),
        "config set-keyring",
    );

    // Should report no keys found (non-key extensions ignored)
    let out = gitveil_with_config_home(config_home.path(), dir.path(), &["add-gpg-user"]);
    assert!(!out.status.success(), "should fail with only non-key files");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no GPG public key files found"),
        "should report no keys found: {}",
        stderr
    );
}

#[test]
fn test_scan_empty_directory() {
    let dir = make_test_repo();
    let config_home = tempfile::tempdir().unwrap();
    let keyring = tempfile::tempdir().unwrap();

    // Init
    assert_success(
        &gitveil_with_config_home(config_home.path(), dir.path(), &["init"]),
        "gitveil init",
    );

    // Configure empty keyring
    assert_success(
        &gitveil_with_config_home(
            config_home.path(),
            dir.path(),
            &["config", "set-keyring", &keyring.path().to_string_lossy()],
        ),
        "config set-keyring",
    );

    let out = gitveil_with_config_home(config_home.path(), dir.path(), &["add-gpg-user"]);
    assert!(!out.status.success(), "should fail with empty keyring dir");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no GPG public key files found"),
        "should say no keys: {}",
        stderr
    );
}

#[cfg(unix)]
#[test]
fn test_scan_skips_symlinks() {
    let dir = make_test_repo();
    let config_home = tempfile::tempdir().unwrap();
    let keyring = tempfile::tempdir().unwrap();

    // Create a symlinked .asc file (should be skipped)
    let target = tempfile::tempdir().unwrap();
    let target_file = target.path().join("target.asc");
    fs::write(&target_file, "fake key content").unwrap();
    let symlink = keyring.path().join("linked.asc");
    std::os::unix::fs::symlink(&target_file, &symlink).unwrap();

    // Init
    assert_success(
        &gitveil_with_config_home(config_home.path(), dir.path(), &["init"]),
        "gitveil init",
    );

    // Configure keyring
    assert_success(
        &gitveil_with_config_home(
            config_home.path(),
            dir.path(),
            &["config", "set-keyring", &keyring.path().to_string_lossy()],
        ),
        "config set-keyring",
    );

    // Should skip the symlinked file and find no valid keys
    let out = gitveil_with_config_home(config_home.path(), dir.path(), &["add-gpg-user"]);
    assert!(
        !out.status.success(),
        "should fail (symlinked files skipped)"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no GPG public key files found"),
        "should find no keys (symlink skipped): {}",
        stderr
    );
}
