//! GPG integration tests for gitveil.
//!
//! These tests exercise real GPG operations: key generation, encryption,
//! decryption, and user management. Each test creates a temporary GPG
//! home directory with test keys, fully isolated from the system keyring.
//!
//! Tests skip automatically at runtime when GPG is not available.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

// ─── Helpers ───────────────────────────────────────────────────

/// Check whether gpg is available and fully functional on this system.
/// This tests more than just `gpg --version` — it verifies GPG can actually
/// operate with a custom GNUPGHOME (temp directory). On Windows CI without
/// standalone GPG, the Git-bundled GPG fails on real operations due to
/// MSYS2 path translation issues.
fn gpg_available() -> bool {
    // First check: binary exists
    let version_ok = Command::new("gpg")
        .args(["--version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !version_ok {
        return false;
    }

    // Second check: GPG can actually work with a temp GNUPGHOME.
    // Run --list-keys which creates the keyring files if GNUPGHOME works.
    let tmp = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return false,
    };
    let _ = Command::new("gpg")
        .args(["--batch", "--list-keys"])
        .env("GNUPGHOME", tmp.path())
        .output();

    // Proof that GPG handled the path: it created a keyring file.
    tmp.path().join("trustdb.gpg").exists() || tmp.path().join("pubring.kbx").exists()
}

/// Early-return from a test when gpg is not functional.
macro_rules! skip_without_gpg {
    () => {
        if !gpg_available() {
            eprintln!("SKIPPED: gpg not functional (not installed or GNUPGHOME broken)");
            return;
        }
    };
}

/// Get the path to the compiled gitveil binary.
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

/// Run gitveil with a custom GNUPGHOME for isolated GPG testing.
fn gitveil_gpg(gpg_home: &Path, dir: &Path, args: &[&str]) -> Output {
    Command::new(gitveil_bin())
        .args(args)
        .current_dir(dir)
        .env("GNUPGHOME", gpg_home)
        .output()
        .unwrap_or_else(|e| panic!("failed to run gitveil {:?}: {}", args, e))
}

/// Run gitveil with a custom GNUPGHOME, feeding `input` to its stdin.
/// Needed by the interactive key picker (`add-gpg-user --from <directory>`),
/// which reads a selection from stdin.
fn gitveil_gpg_stdin(gpg_home: &Path, dir: &Path, args: &[&str], input: &str) -> Output {
    use std::io::Write;
    let mut child = Command::new(gitveil_bin())
        .args(args)
        .current_dir(dir)
        .env("GNUPGHOME", gpg_home)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn gitveil {:?}: {}", args, e));
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("gitveil failed")
}

/// Run git in a directory.
fn git(dir: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|e| panic!("failed to run git {:?}: {}", args, e))
}

/// Run gpg with a custom GNUPGHOME.
fn gpg(gpg_home: &Path, args: &[&str]) -> Output {
    Command::new("gpg")
        .args(args)
        .env("GNUPGHOME", gpg_home)
        .output()
        .unwrap_or_else(|e| panic!("failed to run gpg {:?}: {}", args, e))
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

/// Create a temp directory with an initialized git repo + gitveil init.
fn make_initialized_repo(gpg_home: &Path) -> tempfile::TempDir {
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
    // Initialize gitveil
    assert_success(
        &gitveil_gpg(gpg_home, dir.path(), &["init"]),
        "gitveil init",
    );
    dir
}

/// Generate a GPG test key in the given GNUPGHOME. Returns the fingerprint.
fn generate_test_key(gpg_home: &Path, name: &str, email: &str) -> String {
    generate_test_key_inner(gpg_home, name, email, None)
}

/// Generate a passphrase-protected GPG test key. Returns the fingerprint.
fn generate_test_key_with_passphrase(
    gpg_home: &Path,
    name: &str,
    email: &str,
    passphrase: &str,
) -> String {
    generate_test_key_inner(gpg_home, name, email, Some(passphrase))
}

fn generate_test_key_inner(
    gpg_home: &Path,
    name: &str,
    email: &str,
    passphrase: Option<&str>,
) -> String {
    let key_spec = match passphrase {
        None => format!(
            "%no-protection\nKey-Type: RSA\nKey-Length: 2048\nName-Real: {}\nName-Email: {}\nExpire-Date: 0\n%commit\n",
            name, email
        ),
        Some(pw) => format!(
            "Key-Type: RSA\nKey-Length: 2048\nName-Real: {}\nName-Email: {}\nExpire-Date: 0\nPassphrase: {}\n%commit\n",
            name, email, pw
        ),
    };

    // For passphrase-protected keys, loopback mode keeps gpg from invoking
    // pinentry while generating the key in CI without a TTY.
    let mut args: Vec<&str> = vec!["--batch", "--gen-key"];
    if passphrase.is_some() {
        args.extend_from_slice(&["--pinentry-mode", "loopback"]);
    }

    let mut child = Command::new("gpg")
        .args(&args)
        .env("GNUPGHOME", gpg_home)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn gpg");

    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(key_spec.as_bytes())
        .expect("failed to write key spec");

    let output = child.wait_with_output().expect("gpg gen-key failed");
    assert!(
        output.status.success(),
        "gpg key generation failed:\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Get the fingerprint
    let list_output = gpg(
        gpg_home,
        &["--with-colons", "--list-keys", "--fingerprint", email],
    );
    assert_success(&list_output, "gpg list-keys");

    let stdout = String::from_utf8_lossy(&list_output.stdout);
    for line in stdout.lines() {
        if line.starts_with("fpr:") {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() > 9 {
                return parts[9].to_string();
            }
        }
    }
    panic!("could not find fingerprint for generated key {}", email);
}

/// Export a GPG public key to a file.
fn export_key_to_file(gpg_home: &Path, email: &str, output_path: &Path) {
    let out = Command::new("gpg")
        .args(["--armor", "--export", email])
        .env("GNUPGHOME", gpg_home)
        .output()
        .expect("failed to export key");
    assert_success(&out, "gpg export");
    fs::write(output_path, &out.stdout).expect("failed to write key file");
}

/// Count .gpg files in .git-crypt/keys/<key_name>/0/
fn count_gpg_files(repo_dir: &Path, key_name: &str) -> usize {
    let gpg_dir = repo_dir
        .join(".git-crypt")
        .join("keys")
        .join(key_name)
        .join("0");
    if !gpg_dir.is_dir() {
        return 0;
    }
    fs::read_dir(&gpg_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "gpg")
                .unwrap_or(false)
        })
        .count()
}

/// Get the number of commits in the repo.
fn commit_count(dir: &Path) -> usize {
    let out = git(dir, &["rev-list", "--count", "HEAD"]);
    assert_success(&out, "git rev-list --count");
    String::from_utf8_lossy(&out.stdout).trim().parse().unwrap()
}

// ─── add-gpg-user Tests ────────────────────────────────────────

#[test]
fn test_add_gpg_user_by_email() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    let fingerprint = generate_test_key(gpg_home.path(), "Alice Test", "alice@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());

    let out = gitveil_gpg(
        gpg_home.path(),
        dir.path(),
        &["add-gpg-user", "--trusted", "alice@gitveil.test"],
    );
    assert_success(&out, "add-gpg-user by email");

    // Verify .gpg file was created
    let gpg_file = dir
        .path()
        .join(".git-crypt")
        .join("keys")
        .join("default")
        .join("0")
        .join(format!("{}.gpg", fingerprint));
    assert!(
        gpg_file.exists(),
        "encrypted key file should exist at {}",
        gpg_file.display()
    );

    // Verify it was committed
    let log_out = git(dir.path(), &["log", "--oneline", "-1"]);
    let log_msg = String::from_utf8_lossy(&log_out.stdout);
    assert!(
        log_msg.contains("gitveil collaborator"),
        "commit message should mention collaborator: {}",
        log_msg
    );
}

#[test]
fn test_add_gpg_user_by_fingerprint() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    let fingerprint = generate_test_key(gpg_home.path(), "Bob Test", "bob@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());

    let out = gitveil_gpg(
        gpg_home.path(),
        dir.path(),
        &["add-gpg-user", "--trusted", &fingerprint],
    );
    assert_success(&out, "add-gpg-user by fingerprint");

    assert_eq!(count_gpg_files(dir.path(), "default"), 1);
}

#[test]
fn test_add_gpg_user_trusted_flag() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    generate_test_key(gpg_home.path(), "Carol Test", "carol@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());

    // Without --trusted, GPG may reject the key due to trust level.
    // With --trusted, it should always work.
    let out = gitveil_gpg(
        gpg_home.path(),
        dir.path(),
        &["add-gpg-user", "--trusted", "carol@gitveil.test"],
    );
    assert_success(&out, "add-gpg-user --trusted");
    assert_eq!(count_gpg_files(dir.path(), "default"), 1);
}

#[test]
fn test_add_gpg_user_no_commit_flag() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    generate_test_key(gpg_home.path(), "Dave Test", "dave@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());

    let commits_before = commit_count(dir.path());

    let out = gitveil_gpg(
        gpg_home.path(),
        dir.path(),
        &[
            "add-gpg-user",
            "--trusted",
            "--no-commit",
            "dave@gitveil.test",
        ],
    );
    assert_success(&out, "add-gpg-user --no-commit");

    // .gpg file should exist
    assert_eq!(count_gpg_files(dir.path(), "default"), 1);

    // But no new commit should have been created
    let commits_after = commit_count(dir.path());
    assert_eq!(
        commits_before, commits_after,
        "--no-commit should not create a git commit"
    );
}

#[test]
fn test_add_gpg_user_named_key() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    generate_test_key(gpg_home.path(), "Eve Test", "eve@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());

    // Init a named key
    assert_success(
        &gitveil_gpg(gpg_home.path(), dir.path(), &["init", "-k", "backend"]),
        "gitveil init -k backend",
    );

    let out = gitveil_gpg(
        gpg_home.path(),
        dir.path(),
        &[
            "add-gpg-user",
            "--trusted",
            "-k",
            "backend",
            "eve@gitveil.test",
        ],
    );
    assert_success(&out, "add-gpg-user -k backend");

    // Should be under the named key, not default
    assert_eq!(count_gpg_files(dir.path(), "backend"), 1);
    assert_eq!(count_gpg_files(dir.path(), "default"), 0);
}

#[test]
fn test_add_gpg_user_from_file() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    let fingerprint = generate_test_key(gpg_home.path(), "Frank Test", "frank@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());

    // Export the public key to a .asc file
    let key_file = dir.path().join("frank.asc");
    export_key_to_file(gpg_home.path(), "frank@gitveil.test", &key_file);
    assert!(key_file.exists(), "exported key file should exist");

    let out = gitveil_gpg(
        gpg_home.path(),
        dir.path(),
        &[
            "add-gpg-user",
            "--trusted",
            "--from",
            &key_file.to_string_lossy(),
        ],
    );
    assert_success(&out, "add-gpg-user --from file");

    // Verify .gpg file was created with the right fingerprint
    let gpg_file = dir
        .path()
        .join(".git-crypt")
        .join("keys")
        .join("default")
        .join("0")
        .join(format!("{}.gpg", fingerprint));
    assert!(gpg_file.exists(), "encrypted key file should exist");
}

// ─── rm-gpg-user Tests ─────────────────────────────────────────

#[test]
fn test_rm_gpg_user() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    generate_test_key(gpg_home.path(), "Grace Test", "grace@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());

    // Add user first
    assert_success(
        &gitveil_gpg(
            gpg_home.path(),
            dir.path(),
            &["add-gpg-user", "--trusted", "grace@gitveil.test"],
        ),
        "add-gpg-user",
    );
    assert_eq!(count_gpg_files(dir.path(), "default"), 1);

    // Remove user
    let out = gitveil_gpg(
        gpg_home.path(),
        dir.path(),
        &["rm-gpg-user", "grace@gitveil.test"],
    );
    assert_success(&out, "rm-gpg-user");

    // .gpg file should be gone
    assert_eq!(count_gpg_files(dir.path(), "default"), 0);

    // Should have committed the removal
    let log_out = git(dir.path(), &["log", "--oneline", "-1"]);
    let log_msg = String::from_utf8_lossy(&log_out.stdout);
    assert!(
        log_msg.contains("Remove") || log_msg.contains("remove"),
        "commit message should mention removal: {}",
        log_msg
    );
}

#[test]
fn test_rm_gpg_user_no_commit() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    generate_test_key(gpg_home.path(), "Heidi Test", "heidi@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());

    // Add user
    assert_success(
        &gitveil_gpg(
            gpg_home.path(),
            dir.path(),
            &["add-gpg-user", "--trusted", "heidi@gitveil.test"],
        ),
        "add-gpg-user",
    );

    let commits_before = commit_count(dir.path());

    // Remove with --no-commit
    let out = gitveil_gpg(
        gpg_home.path(),
        dir.path(),
        &["rm-gpg-user", "--no-commit", "heidi@gitveil.test"],
    );
    assert_success(&out, "rm-gpg-user --no-commit");

    // File should be gone
    assert_eq!(count_gpg_files(dir.path(), "default"), 0);

    // No new commit
    let commits_after = commit_count(dir.path());
    assert_eq!(
        commits_before, commits_after,
        "--no-commit should not create a git commit"
    );
}

#[test]
fn test_rm_gpg_user_not_found() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    generate_test_key(gpg_home.path(), "Ivan Test", "ivan@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());

    // Add a user first (so .git-crypt/keys exists)
    assert_success(
        &gitveil_gpg(
            gpg_home.path(),
            dir.path(),
            &["add-gpg-user", "--trusted", "ivan@gitveil.test"],
        ),
        "add-gpg-user",
    );

    // Try to remove a different (nonexistent) user — need a key that exists in GPG
    // but was never added as a gitveil collaborator
    generate_test_key(gpg_home.path(), "Nobody Test", "nobody@gitveil.test");
    let out = gitveil_gpg(
        gpg_home.path(),
        dir.path(),
        &["rm-gpg-user", "nobody@gitveil.test"],
    );
    assert!(
        !out.status.success(),
        "should fail when user not found as collaborator"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("No encrypted key found") || stderr.contains("not found"),
        "error should say user not found: {}",
        stderr
    );
}

// ─── ls-gpg-users Tests ────────────────────────────────────────

#[test]
fn test_ls_gpg_users() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    let fingerprint = generate_test_key(gpg_home.path(), "Judy Test", "judy@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());

    // Add user
    assert_success(
        &gitveil_gpg(
            gpg_home.path(),
            dir.path(),
            &["add-gpg-user", "--trusted", "judy@gitveil.test"],
        ),
        "add-gpg-user",
    );

    // List users
    let out = gitveil_gpg(gpg_home.path(), dir.path(), &["ls-gpg-users"]);
    assert_success(&out, "ls-gpg-users");

    let stdout = String::from_utf8_lossy(&out.stdout);
    // Should show the fingerprint (at least partial)
    let fp_short = &fingerprint[..16];
    assert!(
        stdout.contains(fp_short) || stdout.contains("Judy Test"),
        "ls-gpg-users should show the user's fingerprint or name.\nExpected '{}' or 'Judy Test' in:\n{}",
        fp_short,
        stdout
    );
}

#[test]
fn test_ls_gpg_users_no_users() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    let dir = make_initialized_repo(gpg_home.path());

    // List users when none configured
    let out = gitveil_gpg(gpg_home.path(), dir.path(), &["ls-gpg-users"]);
    // This should either succeed with "no GPG users" or fail gracefully
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        combined.contains("no GPG users") || combined.contains("No GPG users"),
        "should indicate no users configured: {}",
        combined
    );
}

#[test]
fn test_ls_gpg_users_named_key() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    generate_test_key(gpg_home.path(), "Karl Test", "karl@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());

    // Init named key and add user to it
    assert_success(
        &gitveil_gpg(gpg_home.path(), dir.path(), &["init", "-k", "backend"]),
        "gitveil init -k backend",
    );
    assert_success(
        &gitveil_gpg(
            gpg_home.path(),
            dir.path(),
            &[
                "add-gpg-user",
                "--trusted",
                "-k",
                "backend",
                "karl@gitveil.test",
            ],
        ),
        "add-gpg-user -k backend",
    );

    // List only the named key
    let out = gitveil_gpg(
        gpg_home.path(),
        dir.path(),
        &["ls-gpg-users", "-k", "backend"],
    );
    assert_success(&out, "ls-gpg-users -k backend");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("backend"),
        "should show the backend key name: {}",
        stdout
    );
}

// ─── GPG Unlock Roundtrip ──────────────────────────────────────

#[test]
fn test_gpg_unlock_roundtrip() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    generate_test_key(gpg_home.path(), "Liam Test", "liam@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());

    // Set up encrypted file
    let gitattributes = dir.path().join(".gitattributes");
    fs::write(&gitattributes, "*.secret filter=git-crypt diff=git-crypt\n").unwrap();
    let secret_file = dir.path().join("data.secret");
    fs::write(&secret_file, "super-secret-value-42\n").unwrap();
    assert_success(&git(dir.path(), &["add", "."]), "git add");
    assert_success(
        &git(dir.path(), &["commit", "-m", "add secrets"]),
        "git commit secrets",
    );

    // Verify file is encrypted in the blob
    let show_out = git(dir.path(), &["show", ":data.secret"]);
    let blob = show_out.stdout;
    assert!(
        blob.starts_with(b"\0GITCRYPT\0"),
        "file should be encrypted in blob"
    );

    // Add GPG user
    assert_success(
        &gitveil_gpg(
            gpg_home.path(),
            dir.path(),
            &["add-gpg-user", "--trusted", "liam@gitveil.test"],
        ),
        "add-gpg-user",
    );

    // Lock
    assert_success(
        &gitveil_gpg(gpg_home.path(), dir.path(), &["lock", "--force"]),
        "gitveil lock",
    );

    // Verify file is now encrypted in working copy
    let locked_content = fs::read(&secret_file).unwrap();
    assert!(
        locked_content.starts_with(b"\0GITCRYPT\0"),
        "locked file should start with GITCRYPT header"
    );

    // Unlock via GPG (no key file argument!)
    let out = gitveil_gpg(gpg_home.path(), dir.path(), &["unlock"]);
    assert_success(&out, "gitveil unlock (GPG)");

    // Verify file is decrypted
    let decrypted = fs::read_to_string(&secret_file).unwrap();
    assert_eq!(
        decrypted, "super-secret-value-42\n",
        "file should be decrypted back to original plaintext"
    );
}

// ─── Multi-User Scenario ───────────────────────────────────────

#[test]
fn test_add_and_remove_multiple_users() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    generate_test_key(gpg_home.path(), "Mia Test", "mia@gitveil.test");
    generate_test_key(gpg_home.path(), "Noah Test", "noah@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());

    // Add both users
    assert_success(
        &gitveil_gpg(
            gpg_home.path(),
            dir.path(),
            &["add-gpg-user", "--trusted", "mia@gitveil.test"],
        ),
        "add mia",
    );
    assert_success(
        &gitveil_gpg(
            gpg_home.path(),
            dir.path(),
            &["add-gpg-user", "--trusted", "noah@gitveil.test"],
        ),
        "add noah",
    );
    assert_eq!(count_gpg_files(dir.path(), "default"), 2);

    // Remove one
    assert_success(
        &gitveil_gpg(
            gpg_home.path(),
            dir.path(),
            &["rm-gpg-user", "mia@gitveil.test"],
        ),
        "rm mia",
    );
    assert_eq!(count_gpg_files(dir.path(), "default"), 1);

    // List should show 1 user
    let out = gitveil_gpg(gpg_home.path(), dir.path(), &["ls-gpg-users"]);
    assert_success(&out, "ls-gpg-users");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("1 user"),
        "should show 1 user remaining: {}",
        stdout
    );
}

// ─── Passphrase Prompt Regression ──────────────────────────────

/// Verifies that gitveil unlock works when the user's GPG private key is
/// passphrase-protected. The earlier implementation passed `--batch` to gpg
/// during decryption, which suppressed pinentry and failed with
/// "Inappropriate ioctl for device". Pinentry can't run in CI, so the test
/// supplies the passphrase via gpg's loopback `passphrase-file` mechanism —
/// the same code path gpg uses when pinentry is unavailable.
#[test]
fn test_gpg_unlock_with_passphrase_protected_key() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();

    // Configure gpg-agent and gpg to accept a passphrase via file (no TTY).
    let passphrase = "test-gitveil-passphrase";
    let passphrase_file = gpg_home.path().join("passphrase.txt");
    fs::write(&passphrase_file, passphrase).unwrap();
    fs::write(
        gpg_home.path().join("gpg-agent.conf"),
        "allow-loopback-pinentry\n",
    )
    .unwrap();
    // Forward slashes work on every platform GnuPG runs on, including
    // Windows; backslashes can be interpreted as escapes in gpg.conf.
    let pw_path_gpgconf = passphrase_file.display().to_string().replace('\\', "/");
    fs::write(
        gpg_home.path().join("gpg.conf"),
        format!(
            "pinentry-mode loopback\npassphrase-file {}\n",
            pw_path_gpgconf
        ),
    )
    .unwrap();

    generate_test_key_with_passphrase(gpg_home.path(), "Pat Test", "pat@gitveil.test", passphrase);
    let dir = make_initialized_repo(gpg_home.path());

    // Track an encrypted file
    let gitattributes = dir.path().join(".gitattributes");
    fs::write(&gitattributes, "*.secret filter=git-crypt diff=git-crypt\n").unwrap();
    let secret_file = dir.path().join("data.secret");
    fs::write(&secret_file, "pinentry-roundtrip-secret\n").unwrap();
    assert_success(&git(dir.path(), &["add", "."]), "git add");
    assert_success(
        &git(dir.path(), &["commit", "-m", "add secrets"]),
        "git commit secrets",
    );

    assert_success(
        &gitveil_gpg(
            gpg_home.path(),
            dir.path(),
            &["add-gpg-user", "--trusted", "pat@gitveil.test"],
        ),
        "add-gpg-user",
    );
    assert_success(
        &gitveil_gpg(gpg_home.path(), dir.path(), &["lock", "--force"]),
        "gitveil lock",
    );

    let locked = fs::read(&secret_file).unwrap();
    assert!(
        locked.starts_with(b"\0GITCRYPT\0"),
        "file should be encrypted after lock"
    );

    // The actual regression: unlock used to fail with "Inappropriate ioctl
    // for device" against a passphrase-protected key. With --batch removed
    // and stdio inherited, gpg can use the agent (loopback in this test).
    let out = gitveil_gpg(gpg_home.path(), dir.path(), &["unlock"]);
    assert_success(&out, "gitveil unlock (passphrase-protected key)");

    let decrypted = fs::read_to_string(&secret_file).unwrap();
    assert_eq!(decrypted, "pinentry-roundtrip-secret\n");
}

// ─── Missing Secret Key ────────────────────────────────────────

/// When the local GPG keyring holds no secret key matching any collaborator,
/// unlock should fail with a clear, actionable error — not loop through every
/// .gpg file calling pinentry and burying the user under "no secret key"
/// noise on stderr.
#[test]
fn test_gpg_unlock_no_matching_secret_key_gives_clear_error() {
    skip_without_gpg!();

    // Alice's keyring (has the private key).
    let alice_home = tempfile::tempdir().unwrap();
    generate_test_key(
        alice_home.path(),
        "Alice Test",
        "alice-nomatch@gitveil.test",
    );
    let alice_pub = alice_home.path().join("alice.asc");
    export_key_to_file(alice_home.path(), "alice-nomatch@gitveil.test", &alice_pub);

    // Bob's keyring: imports Alice's *public* key but has no private key
    // matching any collaborator.
    let bob_home = tempfile::tempdir().unwrap();
    let import_out = Command::new("gpg")
        .args(["--batch", "--import"])
        .arg(&alice_pub)
        .env("GNUPGHOME", bob_home.path())
        .output()
        .expect("import alice pubkey into bob");
    assert_success(&import_out, "import alice public key into bob");

    let dir = make_initialized_repo(bob_home.path());
    assert_success(
        &gitveil_gpg(
            bob_home.path(),
            dir.path(),
            &["add-gpg-user", "--trusted", "alice-nomatch@gitveil.test"],
        ),
        "add Alice as collaborator",
    );

    let out = gitveil_gpg(bob_home.path(), dir.path(), &["unlock"]);
    assert!(
        !out.status.success(),
        "unlock should fail when no secret key matches"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no GPG secret key") || stderr.contains("secret key"),
        "error should mention missing secret key, got: {}",
        stderr,
    );
}

// ─── Malicious Repository Content ──────────────────────────────

/// Regression: repository content must never reach a git filter command.
///
/// `unlock` derives the key name from a directory name under
/// `.git-crypt/keys/`, which is attacker-controlled repository content, and
/// feeds it to `git config filter.<name>.smudge`. git runs those filter
/// commands through a shell, so an unvalidated name is remote code execution
/// on every collaborator who unlocks the repository.
#[test]
fn test_gpg_unlock_rejects_key_dir_name_with_shell_metacharacters() {
    skip_without_gpg!();

    // `${IFS}` supplies the argument separator without a literal space:
    // the payload has to be valid both as a path component and as a
    // .gitattributes attribute value.
    const EVIL: &str = "x$(touch${IFS}pwned)";

    let gpg_home = tempfile::tempdir().unwrap();
    generate_test_key(gpg_home.path(), "Vic Test", "vic-evil@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());

    // The victim is a legitimate collaborator, so the .gpg file really does
    // decrypt with their secret key.
    assert_success(
        &gitveil_gpg(
            gpg_home.path(),
            dir.path(),
            &["add-gpg-user", "--trusted", "vic-evil@gitveil.test"],
        ),
        "add-gpg-user",
    );

    // Attacker-supplied repository content: a key directory whose name is a
    // shell payload, plus a file routed through the matching filter so that
    // unlock's `git checkout` triggers it.
    let keys_dir = dir.path().join(".git-crypt").join("keys");
    fs::rename(keys_dir.join("default"), keys_dir.join(EVIL))
        .expect("rename key dir to payload name");
    fs::write(
        dir.path().join(".gitattributes"),
        format!("*.secret filter=git-crypt-{EVIL} diff=git-crypt-{EVIL}\n"),
    )
    .unwrap();
    fs::write(dir.path().join("data.secret"), "secret\n").unwrap();
    assert_success(&git(dir.path(), &["add", "-A"]), "git add payload");
    assert_success(
        &git(dir.path(), &["commit", "-m", "attacker payload"]),
        "git commit payload",
    );

    let out = gitveil_gpg(gpg_home.path(), dir.path(), &["unlock"]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !dir.path().join("pwned").exists(),
        "REMOTE CODE EXECUTION: the key directory name was executed by git.\nstderr: {stderr}",
    );

    let cfg = git(dir.path(), &["config", "--get-regexp", "^filter\\."]);
    let cfg = String::from_utf8_lossy(&cfg.stdout);
    assert!(
        !cfg.contains("$("),
        "poisoned filter command written to git config:\n{cfg}",
    );

    assert!(
        !out.status.success(),
        "unlock must not report success when the only key directory is unusable",
    );
    assert!(
        stderr.contains("invalid name"),
        "expected a diagnostic naming the rejected directory, got: {stderr}",
    );
}

/// `add-gpg-user --from <git URL>` clones the keyring into a temp directory
/// and runs the interactive picker over it. The branch had no coverage at
/// all; it is also the consumer of `create_private_temp_dir`, so this pins
/// the whole clone → scan → pick → import → add path.
///
/// A local path ending in `.git` satisfies `is_git_url`, so the clone stays
/// offline.
#[test]
fn test_add_gpg_user_from_git_url() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    generate_test_key(gpg_home.path(), "Willow Test", "willow@gitveil.test");

    // A keyring repository holding one exported public key.
    let keyring_parent = tempfile::tempdir().unwrap();
    let keyring = keyring_parent.path().join("keyring.git");
    fs::create_dir(&keyring).unwrap();
    assert_success(&git(&keyring, &["init"]), "git init keyring");
    assert_success(
        &git(&keyring, &["config", "user.email", "test@gitveil.test"]),
        "keyring config email",
    );
    assert_success(
        &git(&keyring, &["config", "user.name", "Test"]),
        "keyring config name",
    );
    export_key_to_file(
        gpg_home.path(),
        "willow@gitveil.test",
        &keyring.join("willow.asc"),
    );
    assert_success(&git(&keyring, &["add", "willow.asc"]), "keyring add");
    assert_success(
        &git(&keyring, &["commit", "-m", "add key"]),
        "keyring commit",
    );

    let dir = make_initialized_repo(gpg_home.path());
    let out = gitveil_gpg_stdin(
        gpg_home.path(),
        dir.path(),
        &[
            "add-gpg-user",
            "--trusted",
            "--from",
            &keyring.to_string_lossy(),
        ],
        "all\n",
    );
    assert_success(&out, "add-gpg-user --from git URL");

    assert_eq!(
        count_gpg_files(dir.path(), "default"),
        1,
        "the cloned key should have been added as a collaborator"
    );

    // The clone is cleaned up, and never under the old guessable name.
    let leftovers: Vec<_> = fs::read_dir(std::env::temp_dir())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with("gitveil-keyring-"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "temp clone directories left behind: {leftovers:?}"
    );
}
