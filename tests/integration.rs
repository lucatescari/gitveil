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
    // Default output is focused on filter-marked files.
    assert!(
        stdout.contains("encrypted:") && stdout.contains("a.secret"),
        "should list a.secret as encrypted, got: {}",
        stdout
    );
    assert!(stdout.contains("b.secret"), "should list b.secret");
    // Non-filter files are NOT shown by default (use --all for that).
    assert!(
        !stdout.contains("public.txt"),
        "default output should not list non-filter public.txt, got: {}",
        stdout,
    );
    assert!(
        !stdout.contains("README"),
        "default output should not list non-filter README, got: {}",
        stdout,
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
    // All 200 secret files should appear under "encrypted:"
    assert!(
        stdout.contains("secret-0000.txt"),
        "should list first encrypted file"
    );
    assert!(
        stdout.contains("secret-0199.txt"),
        "should list last encrypted file"
    );
    // Plain files (no filter) are excluded from the default focused output.
    assert!(
        !stdout.contains("plain-0000.txt"),
        "default output should not list non-filter plain files"
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

// ─── Status: tracked / untracked / warning coverage ────────────

#[test]
fn test_status_shows_untracked_filter_matched_file() {
    // gitveil status used to ignore untracked files entirely; git-crypt
    // shows them so the user sees what *will* be encrypted on staging.
    // We annotate the entry with "(untracked)" so the user can tell the
    // file isn't actually encrypted yet — it just *will be* on staging.
    let dir = make_test_repo();
    assert_success(&gitveil(dir.path(), &["init"]), "init");
    fs::write(
        dir.path().join(".gitattributes"),
        "*.secret filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();
    fs::write(dir.path().join("new.secret"), "fresh untracked secret\n").unwrap();

    let out = gitveil(dir.path(), &["status"]);
    assert_success(&out, "status");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("encrypted:") && stdout.contains("new.secret"),
        "untracked filter-matched file should appear as encrypted, got: {}",
        stdout,
    );
    assert!(
        stdout.contains("(untracked)"),
        "untracked filter file must be marked '(untracked)' to distinguish \
         it from a file whose committed blob is already encrypted, got: {}",
        stdout,
    );
    // Untracked: no blob to verify, so no WARNING.
    assert!(
        !stdout.contains("WARNING"),
        "untracked file should not produce a WARNING, got: {}",
        stdout,
    );
}

#[test]
fn test_status_tracked_filter_file_has_no_untracked_marker() {
    // Negative pairing for the (untracked) marker: a tracked filter file
    // whose blob is encrypted must not be tagged "(untracked)".
    let dir = make_test_repo();
    assert_success(&gitveil(dir.path(), &["init"]), "init");
    fs::write(
        dir.path().join(".gitattributes"),
        "*.secret filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();
    fs::write(dir.path().join("done.secret"), "fully encrypted\n").unwrap();
    assert_success(&git(dir.path(), &["add", "."]), "git add");
    assert_success(&git(dir.path(), &["commit", "-m", "add"]), "commit");

    let out = gitveil(dir.path(), &["status"]);
    assert_success(&out, "status");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("done.secret"),
        "tracked file should appear, got: {}",
        stdout,
    );
    assert!(
        !stdout.contains("(untracked)"),
        "tracked filter+encrypted file must not be tagged (untracked), \
         got: {}",
        stdout,
    );
}

#[test]
fn test_status_default_hides_non_filter_files() {
    // Default output is focused on filter-matched files. README (tracked,
    // no filter) and plain.txt (untracked, no filter) should NOT appear.
    let dir = make_test_repo();
    assert_success(&gitveil(dir.path(), &["init"]), "init");
    fs::write(dir.path().join("plain.txt"), "public\n").unwrap();

    let out = gitveil(dir.path(), &["status"]);
    assert_success(&out, "status");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("plain.txt"),
        "default should hide non-filter plain.txt, got: {}",
        stdout,
    );
    assert!(
        !stdout.contains("README"),
        "default should hide non-filter README, got: {}",
        stdout,
    );
}

#[test]
fn test_status_a_flag_lists_non_filter_files() {
    // -a / --all surfaces files without the git-crypt filter, matching the
    // git-crypt-style verbose listing.
    let dir = make_test_repo();
    assert_success(&gitveil(dir.path(), &["init"]), "init");
    fs::write(dir.path().join("plain.txt"), "public\n").unwrap();

    let out = gitveil(dir.path(), &["status", "-a"]);
    assert_success(&out, "status -a");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("not encrypted:") && stdout.contains("plain.txt"),
        "-a should list untracked non-filter plain.txt, got: {}",
        stdout,
    );
    assert!(
        stdout.contains("README"),
        "-a should list tracked non-filter README, got: {}",
        stdout,
    );
}

#[test]
fn test_status_a_long_flag_alias() {
    // --all is the long alias for -a.
    let dir = make_test_repo();
    assert_success(&gitveil(dir.path(), &["init"]), "init");
    fs::write(dir.path().join("plain.txt"), "public\n").unwrap();

    let out = gitveil(dir.path(), &["status", "--all"]);
    assert_success(&out, "status --all");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("plain.txt"),
        "--all should behave like -a, got: {}",
        stdout,
    );
}

#[test]
fn test_status_warning_for_filter_with_plain_blob() {
    // File committed BEFORE the filter was set → its blob is plaintext
    // even though the filter now applies → must emit WARNING.
    let dir = make_test_repo();
    assert_success(&gitveil(dir.path(), &["init"]), "init");

    fs::write(dir.path().join("secret.dat"), "plaintext-content\n").unwrap();
    assert_success(&git(dir.path(), &["add", "secret.dat"]), "add pre-filter");
    assert_success(
        &git(dir.path(), &["commit", "-m", "commit pre-filter"]),
        "commit",
    );

    fs::write(
        dir.path().join(".gitattributes"),
        "secret.dat filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();
    assert_success(
        &git(dir.path(), &["add", ".gitattributes"]),
        "add .gitattributes",
    );
    assert_success(
        &git(dir.path(), &["commit", "-m", "add filter"]),
        "commit filter",
    );

    let out = gitveil(dir.path(), &["status"]);
    assert_success(&out, "status");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("secret.dat") && stdout.contains("WARNING"),
        "filter-marked file with plaintext blob must show WARNING, got: {}",
        stdout,
    );
    assert!(
        stderr.contains("Warning") || stderr.contains("warning"),
        "should print summary about running -f, got stderr: {}",
        stderr,
    );
}

#[test]
fn test_status_no_warning_when_all_correctly_encrypted() {
    let dir = make_test_repo();
    assert_success(&gitveil(dir.path(), &["init"]), "init");
    fs::write(
        dir.path().join(".gitattributes"),
        "*.secret filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();
    fs::write(dir.path().join("a.secret"), "secret-a\n").unwrap();
    assert_success(&git(dir.path(), &["add", "."]), "git add");
    assert_success(&git(dir.path(), &["commit", "-m", "add"]), "commit");

    let out = gitveil(dir.path(), &["status"]);
    assert_success(&out, "status");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.contains("WARNING"),
        "no WARNING expected, got: {}",
        stdout,
    );
    assert!(
        !stderr.to_lowercase().contains("warning:"),
        "no Warning summary expected, got: {}",
        stderr,
    );
}

#[test]
fn test_status_e_flag_only_encrypted_blobs() {
    // -e: only files whose blob is encrypted (i.e., everything is fine).
    // WARNING files (filter + plaintext blob) are excluded.
    let dir = make_test_repo();
    assert_success(&gitveil(dir.path(), &["init"]), "init");

    // bad.secret: committed plaintext before filter — its blob is plain.
    fs::write(dir.path().join("bad.secret"), "plain\n").unwrap();
    assert_success(&git(dir.path(), &["add", "bad.secret"]), "add bad");
    assert_success(&git(dir.path(), &["commit", "-m", "pre"]), "commit");

    fs::write(
        dir.path().join(".gitattributes"),
        "*.secret filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();
    fs::write(dir.path().join("good.secret"), "encrypt-me\n").unwrap();
    fs::write(dir.path().join("public.txt"), "public\n").unwrap();
    // Use explicit paths: `git add .` would re-stage bad.secret through
    // the now-active clean filter, accidentally erasing the WARNING state.
    assert_success(
        &git(
            dir.path(),
            &["add", ".gitattributes", "good.secret", "public.txt"],
        ),
        "git add new files only",
    );
    assert_success(&git(dir.path(), &["commit", "-m", "add"]), "commit");

    let out = gitveil(dir.path(), &["status", "-e"]);
    assert_success(&out, "status -e");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("good.secret"),
        "-e should list filter+encrypted good.secret, got: {}",
        stdout,
    );
    assert!(
        !stdout.contains("bad.secret"),
        "-e should NOT list filter+plaintext bad.secret (the WARNING set), got: {}",
        stdout,
    );
    assert!(
        !stdout.contains("public.txt") && !stdout.contains("README"),
        "-e should NOT list non-filter files, got: {}",
        stdout,
    );
}

#[test]
fn test_status_u_flag_only_warning_files() {
    // -u: only files marked for encryption whose blob is plaintext (the
    // set that needs re-encryption — pair with -f). Restores the
    // pre-PR meaning of -u.
    let dir = make_test_repo();
    assert_success(&gitveil(dir.path(), &["init"]), "init");

    fs::write(dir.path().join("bad.secret"), "plain\n").unwrap();
    assert_success(&git(dir.path(), &["add", "bad.secret"]), "add bad");
    assert_success(&git(dir.path(), &["commit", "-m", "pre"]), "commit");

    fs::write(
        dir.path().join(".gitattributes"),
        "*.secret filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();
    fs::write(dir.path().join("good.secret"), "encrypt-me\n").unwrap();
    fs::write(dir.path().join("public.txt"), "public\n").unwrap();
    // Use explicit paths: `git add .` would re-stage bad.secret through
    // the now-active clean filter, accidentally erasing the WARNING state.
    assert_success(
        &git(
            dir.path(),
            &["add", ".gitattributes", "good.secret", "public.txt"],
        ),
        "git add new files only",
    );
    assert_success(&git(dir.path(), &["commit", "-m", "add"]), "commit");

    let out = gitveil(dir.path(), &["status", "-u"]);
    assert_success(&out, "status -u");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("bad.secret") && stdout.contains("WARNING"),
        "-u should list bad.secret as a WARNING (filter+plain), got: {}",
        stdout,
    );
    assert!(
        !stdout.contains("good.secret"),
        "-u should NOT list good.secret (filter+encrypted), got: {}",
        stdout,
    );
    assert!(
        !stdout.contains("public.txt") && !stdout.contains("README"),
        "-u should NOT list non-filter files, got: {}",
        stdout,
    );
}

#[test]
fn test_status_fix_restages_only_warning_files() {
    // -f should re-stage tracked files with filter but plaintext blob,
    // and must NOT auto-add untracked files (privacy / user intent).
    let dir = make_test_repo();
    assert_success(&gitveil(dir.path(), &["init"]), "init");

    fs::write(dir.path().join("bad.secret"), "should-be-encrypted\n").unwrap();
    assert_success(&git(dir.path(), &["add", "bad.secret"]), "add pre-filter");
    assert_success(&git(dir.path(), &["commit", "-m", "pre-filter"]), "commit");

    fs::write(
        dir.path().join(".gitattributes"),
        "*.secret filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();
    assert_success(&git(dir.path(), &["add", ".gitattributes"]), "add attrs");
    assert_success(&git(dir.path(), &["commit", "-m", "attrs"]), "commit attrs");

    // Untracked filter-matched file
    fs::write(dir.path().join("new.secret"), "fresh\n").unwrap();

    let out = gitveil(dir.path(), &["status", "-f"]);
    assert_success(&out, "status -f");

    let staged = git(dir.path(), &["diff", "--cached", "--name-only"]);
    let staged_out = String::from_utf8_lossy(&staged.stdout);
    // Diagnostic-heavy message — this test has flaked once during local runs
    // with `staged_out` empty; capturing full state makes any future flake
    // immediately debuggable.
    assert!(
        staged_out.contains("bad.secret"),
        "bad.secret (tracked + filter + plain blob) should be re-staged by -f.\n\
         gitveil status -f stdout:\n{}\n\
         gitveil status -f stderr:\n{}\n\
         git diff --cached --name-only stdout: {:?}\n\
         git diff --cached --name-only stderr: {:?}\n\
         git status --porcelain:\n{}\n\
         --- discriminating evidence ---\n\
         index entry (git ls-files -s):   {}\
         HEAD blob  (rev-parse HEAD:..):  {}\
         index blob first bytes:          {:?}\n\
         git check-attr filter bad.secret: {}\
         filter.git-crypt.clean:          {}\
         filter.git-crypt.required:       {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
        staged_out,
        String::from_utf8_lossy(&staged.stderr),
        String::from_utf8_lossy(&git(dir.path(), &["status", "--porcelain"]).stdout),
        String::from_utf8_lossy(&git(dir.path(), &["ls-files", "-s", "bad.secret"]).stdout),
        String::from_utf8_lossy(&git(dir.path(), &["rev-parse", "HEAD:bad.secret"]).stdout),
        git(dir.path(), &["show", ":bad.secret"])
            .stdout
            .iter()
            .take(10)
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        String::from_utf8_lossy(&git(dir.path(), &["check-attr", "filter", "bad.secret"]).stdout),
        String::from_utf8_lossy(
            &git(dir.path(), &["config", "--get", "filter.git-crypt.clean"]).stdout
        ),
        String::from_utf8_lossy(
            &git(
                dir.path(),
                &["config", "--get", "filter.git-crypt.required"]
            )
            .stdout
        ),
    );
    assert!(
        !staged_out.contains("new.secret"),
        "untracked new.secret should NOT be auto-staged by -f, got: {}",
        staged_out,
    );

    // Re-staged blob should now be encrypted via the clean filter.
    let blob = git(dir.path(), &["show", ":bad.secret"]);
    assert!(
        blob.stdout.starts_with(b"\0GITCRYPT\0"),
        "re-staged bad.secret blob should be encrypted now",
    );
}

#[test]
fn test_status_fix_skips_file_deleted_from_working_tree() {
    // A tracked filter-marked file with a plaintext blob whose working-copy
    // has been deleted: -f must NOT stage that, because `git add <missing>`
    // stages the *deletion* (removing the file from the index). The intent
    // of -f is to re-encrypt, not to silently remove tracked files.
    let dir = make_test_repo();
    assert_success(&gitveil(dir.path(), &["init"]), "init");

    fs::write(dir.path().join("bad.secret"), "plaintext\n").unwrap();
    assert_success(&git(dir.path(), &["add", "bad.secret"]), "add bad");
    assert_success(&git(dir.path(), &["commit", "-m", "pre"]), "commit bad");

    fs::write(
        dir.path().join(".gitattributes"),
        "*.secret filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();
    assert_success(&git(dir.path(), &["add", ".gitattributes"]), "add attrs");
    assert_success(&git(dir.path(), &["commit", "-m", "attrs"]), "commit attrs");

    // Delete from working tree (still tracked in index).
    fs::remove_file(dir.path().join("bad.secret")).unwrap();

    let out = gitveil(dir.path(), &["status", "-f"]);
    assert_success(&out, "status -f on deleted file");

    let staged = git(dir.path(), &["diff", "--cached", "--name-status"]);
    let staged_out = String::from_utf8_lossy(&staged.stdout);
    assert!(
        !staged_out.contains("bad.secret"),
        "-f must NOT stage anything for a file deleted from the working \
         tree (would stage the deletion). Got: {}",
        staged_out,
    );
    let stderr = String::from_utf8_lossy(&out.stderr).to_lowercase();
    assert!(
        stderr.contains("skip") || stderr.contains("deleted") || stderr.contains("no longer"),
        "should emit a diagnostic explaining the skip, got stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn test_status_excludes_gitignored_files() {
    // --exclude-standard makes git ls-files --others skip files matched by
    // .gitignore. Regression guard via -a (which would include them
    // otherwise — they are non-filter files).
    let dir = make_test_repo();
    assert_success(&gitveil(dir.path(), &["init"]), "init");

    fs::write(dir.path().join(".gitignore"), "ignored.txt\n*.tmp\n").unwrap();
    fs::write(dir.path().join("ignored.txt"), "skip me\n").unwrap();
    fs::write(dir.path().join("draft.tmp"), "skip me\n").unwrap();
    fs::write(dir.path().join("public.txt"), "include me\n").unwrap();

    let out = gitveil(dir.path(), &["status", "-a"]);
    assert_success(&out, "status -a");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("public.txt"),
        "non-ignored file should appear with -a, got: {}",
        stdout,
    );
    assert!(
        !stdout.contains("ignored.txt"),
        "gitignored file should not appear even with -a, got: {}",
        stdout,
    );
    assert!(
        !stdout.contains("draft.tmp"),
        "gitignored pattern file should not appear even with -a, got: {}",
        stdout,
    );
}

#[test]
fn test_status_not_a_git_repo_clear_error() {
    let dir = tempfile::tempdir().unwrap();
    let out = gitveil(dir.path(), &["status"]);
    assert!(
        !out.status.success(),
        "status outside any git repo should fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr).to_lowercase();
    assert!(
        stderr.contains("not a git repository") || stderr.contains("not in a git"),
        "should give clean 'not a git repository' error, got: {}",
        stderr,
    );
}

#[test]
fn test_status_works_without_gitveil_init() {
    // Status is informational: it lets users inspect filter coverage even
    // before running `gitveil init`. Without init, filter-marked files
    // were committed without the clean filter, so their blobs are
    // plaintext → WARNING fires, surfacing the misconfiguration.
    let dir = make_test_repo();
    fs::write(
        dir.path().join(".gitattributes"),
        "*.secret filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();
    fs::write(dir.path().join("file.secret"), "x\n").unwrap();
    assert_success(&git(dir.path(), &["add", "."]), "git add");
    assert_success(&git(dir.path(), &["commit", "-m", "add"]), "commit");

    let out = gitveil(dir.path(), &["status"]);
    assert_success(&out, "status before gitveil init must still work");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("file.secret") && stdout.contains("WARNING"),
        "without init, filter-marked file should appear with WARNING, \
         got stdout: {}",
        stdout,
    );
    assert!(
        stderr.to_lowercase().contains("warning"),
        "should print summary, got stderr: {}",
        stderr,
    );
}

#[test]
fn test_status_handles_filename_with_spaces() {
    // Regression guard: NUL-delimited parsing means filenames with
    // whitespace are preserved as a single entry. Use a filter-matched
    // file so it appears in the default focused output.
    let dir = make_test_repo();
    assert_success(&gitveil(dir.path(), &["init"]), "init");
    fs::write(
        dir.path().join(".gitattributes"),
        "*.secret filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();
    fs::write(dir.path().join("file with space.secret"), "x\n").unwrap();

    let out = gitveil(dir.path(), &["status"]);
    assert_success(&out, "status");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("file with space.secret"),
        "should list the file with spaces in one piece, got: {}",
        stdout,
    );
}

#[test]
fn test_status_named_key_filter() {
    // Named keys use filter=git-crypt-<keyname>. Status must recognize
    // these too (not just the default `git-crypt`).
    let dir = make_test_repo();
    assert_success(&gitveil(dir.path(), &["init", "-k", "backend"]), "init -k");
    fs::write(
        dir.path().join(".gitattributes"),
        "*.bsec filter=git-crypt-backend diff=git-crypt-backend\n",
    )
    .unwrap();
    fs::write(dir.path().join("api.bsec"), "key\n").unwrap();
    assert_success(&git(dir.path(), &["add", "."]), "git add");
    assert_success(&git(dir.path(), &["commit", "-m", "add"]), "commit");

    let out = gitveil(dir.path(), &["status"]);
    assert_success(&out, "status");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("encrypted:") && stdout.contains("api.bsec"),
        "named-key filter should be recognized, got: {}",
        stdout,
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
    let gpg_home = tempfile::tempdir().unwrap();

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

    // Provide a bogus user ID — should attempt GPG lookup, not keyring scan.
    // Set GNUPGHOME to an empty temp dir so GPG fails fast on all platforms
    // (prevents hangs on Windows where GPG may try to initialize a default keyring).
    let out = Command::new(gitveil_bin())
        .args(["add-gpg-user", "nonexistent-user@test.invalid"])
        .current_dir(dir.path())
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("GNUPGHOME", gpg_home.path())
        .output()
        .unwrap();
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
