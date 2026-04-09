//! Cross-tool compatibility tests between gitveil and git-crypt.
//!
//! These tests verify that gitveil and git-crypt are fully interoperable:
//! key files, encrypted blobs, lock/unlock all work across both tools.
//!
//! Tests skip automatically at runtime when git-crypt is not installed.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

// ─── Helpers ───────────────────────────────────────────────────

/// Check whether git-crypt is available on this system.
fn git_crypt_available() -> bool {
    Command::new("git-crypt")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Early-return from a test when git-crypt is not installed.
macro_rules! skip_without_git_crypt {
    () => {
        if !git_crypt_available() {
            eprintln!("SKIPPED: git-crypt not found in PATH");
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

/// Run git-crypt with the given args in the given directory.
fn git_crypt(dir: &Path, args: &[&str]) -> Output {
    Command::new("git-crypt")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|e| panic!("failed to run git-crypt {:?}: {}", args, e))
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

/// Create a temp directory with an initialized git repo and initial commit.
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
    let readme = dir.path().join("README");
    fs::write(&readme, "test repo\n").unwrap();
    assert_success(&git(dir.path(), &["add", "README"]), "git add README");
    assert_success(
        &git(dir.path(), &["commit", "-m", "initial"]),
        "git commit initial",
    );
    dir
}

// ─── Tests ─────────────────────────────────────────────────────

#[test]
fn test_git_crypt_key_loaded_by_gitveil() {
    skip_without_git_crypt!();

    let dir = make_test_repo();
    let key_file = dir.path().join("exported-key");

    // git-crypt initializes the repo and exports its key
    assert_success(&git_crypt(dir.path(), &["init"]), "git-crypt init");
    assert_success(
        &git_crypt(dir.path(), &["export-key", key_file.to_str().unwrap()]),
        "git-crypt export-key",
    );

    // Set up an encrypted file
    fs::write(
        dir.path().join(".gitattributes"),
        "*.secret filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();
    fs::write(dir.path().join("creds.secret"), "DB_PASS=hunter2\n").unwrap();
    assert_success(
        &git(dir.path(), &["add", ".gitattributes", "creds.secret"]),
        "git add",
    );
    assert_success(
        &git(dir.path(), &["commit", "-m", "add secrets"]),
        "git commit",
    );

    // Lock with git-crypt, unlock with gitveil
    assert_success(&git_crypt(dir.path(), &["lock"]), "git-crypt lock");
    assert_success(
        &gitveil(dir.path(), &["unlock", key_file.to_str().unwrap()]),
        "gitveil unlock with git-crypt key",
    );

    let content = fs::read_to_string(dir.path().join("creds.secret")).unwrap();
    assert_eq!(content, "DB_PASS=hunter2\n");
}

#[test]
fn test_gitveil_key_loaded_by_git_crypt() {
    skip_without_git_crypt!();

    let dir = make_test_repo();
    let key_file = dir.path().join("exported-key");

    // gitveil initializes the repo and exports its key
    assert_success(&gitveil(dir.path(), &["init"]), "gitveil init");
    assert_success(
        &gitveil(dir.path(), &["export-key", key_file.to_str().unwrap()]),
        "gitveil export-key",
    );

    // Set up an encrypted file
    fs::write(
        dir.path().join(".gitattributes"),
        "*.secret filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();
    fs::write(dir.path().join("creds.secret"), "API_KEY=abc123\n").unwrap();
    assert_success(
        &git(dir.path(), &["add", ".gitattributes", "creds.secret"]),
        "git add",
    );
    assert_success(
        &git(dir.path(), &["commit", "-m", "add secrets"]),
        "git commit",
    );

    // Lock with gitveil, unlock with git-crypt
    assert_success(&gitveil(dir.path(), &["lock", "--force"]), "gitveil lock");
    assert_success(
        &git_crypt(dir.path(), &["unlock", key_file.to_str().unwrap()]),
        "git-crypt unlock with gitveil key",
    );

    let content = fs::read_to_string(dir.path().join("creds.secret")).unwrap();
    assert_eq!(content, "API_KEY=abc123\n");
}

#[test]
fn test_git_crypt_encrypted_decrypted_by_gitveil() {
    skip_without_git_crypt!();

    let dir = make_test_repo();
    let key_file = dir.path().join("exported-key");
    let secret_content = "DATABASE_URL=postgres://admin:secret@db/prod\n";

    // Encrypt with git-crypt
    assert_success(&git_crypt(dir.path(), &["init"]), "git-crypt init");

    fs::write(
        dir.path().join(".gitattributes"),
        "*.secret filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();
    fs::write(dir.path().join("config.secret"), secret_content).unwrap();
    assert_success(
        &git(dir.path(), &["add", ".gitattributes", "config.secret"]),
        "git add",
    );
    assert_success(&git(dir.path(), &["commit", "-m", "secrets"]), "git commit");

    // Verify blob is encrypted by git-crypt
    let blob = git(dir.path(), &["show", ":config.secret"]);
    assert_success(&blob, "git show blob");
    assert!(
        blob.stdout.starts_with(b"\x00GITCRYPT\x00"),
        "blob should be encrypted by git-crypt"
    );

    // Export key and lock with git-crypt
    assert_success(
        &git_crypt(dir.path(), &["export-key", key_file.to_str().unwrap()]),
        "git-crypt export-key",
    );
    assert_success(&git_crypt(dir.path(), &["lock"]), "git-crypt lock");

    // Decrypt with gitveil
    assert_success(
        &gitveil(dir.path(), &["unlock", key_file.to_str().unwrap()]),
        "gitveil unlock",
    );

    let content = fs::read_to_string(dir.path().join("config.secret")).unwrap();
    assert_eq!(
        content, secret_content,
        "gitveil should decrypt git-crypt content"
    );
}

#[test]
fn test_gitveil_encrypted_decrypted_by_git_crypt() {
    skip_without_git_crypt!();

    let dir = make_test_repo();
    let key_file = dir.path().join("exported-key");
    let secret_content = "STRIPE_KEY=sk_live_abc123def456\n";

    // Encrypt with gitveil
    assert_success(&gitveil(dir.path(), &["init"]), "gitveil init");

    fs::write(
        dir.path().join(".gitattributes"),
        "*.secret filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();
    fs::write(dir.path().join("payment.secret"), secret_content).unwrap();
    assert_success(
        &git(dir.path(), &["add", ".gitattributes", "payment.secret"]),
        "git add",
    );
    assert_success(&git(dir.path(), &["commit", "-m", "secrets"]), "git commit");

    // Verify blob is encrypted by gitveil
    let blob = git(dir.path(), &["show", ":payment.secret"]);
    assert_success(&blob, "git show blob");
    assert!(
        blob.stdout.starts_with(b"\x00GITCRYPT\x00"),
        "blob should be encrypted by gitveil"
    );

    // Export key and lock with gitveil
    assert_success(
        &gitveil(dir.path(), &["export-key", key_file.to_str().unwrap()]),
        "gitveil export-key",
    );
    assert_success(&gitveil(dir.path(), &["lock", "--force"]), "gitveil lock");

    // Decrypt with git-crypt
    assert_success(
        &git_crypt(dir.path(), &["unlock", key_file.to_str().unwrap()]),
        "git-crypt unlock",
    );

    let content = fs::read_to_string(dir.path().join("payment.secret")).unwrap();
    assert_eq!(
        content, secret_content,
        "git-crypt should decrypt gitveil content"
    );
}

#[test]
fn test_cross_tool_named_key() {
    skip_without_git_crypt!();

    let dir = make_test_repo();
    let key_file = dir.path().join("exported-key");
    let secret_content = "BACKEND_SECRET=xyzzy\n";

    // Init named key with gitveil
    assert_success(
        &gitveil(dir.path(), &["init", "-k", "backend"]),
        "gitveil init -k backend",
    );

    fs::write(
        dir.path().join(".gitattributes"),
        "*.back filter=git-crypt-backend diff=git-crypt-backend\n",
    )
    .unwrap();
    fs::write(dir.path().join("api.back"), secret_content).unwrap();
    assert_success(
        &git(dir.path(), &["add", ".gitattributes", "api.back"]),
        "git add",
    );
    assert_success(
        &git(dir.path(), &["commit", "-m", "backend secrets"]),
        "git commit",
    );

    // Export and lock with gitveil
    assert_success(
        &gitveil(
            dir.path(),
            &["export-key", "-k", "backend", key_file.to_str().unwrap()],
        ),
        "gitveil export-key -k backend",
    );
    assert_success(
        &gitveil(dir.path(), &["lock", "-k", "backend", "--force"]),
        "gitveil lock -k backend",
    );

    // Unlock with git-crypt
    assert_success(
        &git_crypt(dir.path(), &["unlock", key_file.to_str().unwrap()]),
        "git-crypt unlock named key",
    );

    let content = fs::read_to_string(dir.path().join("api.back")).unwrap();
    assert_eq!(
        content, secret_content,
        "git-crypt should decrypt gitveil named key content"
    );
}

#[test]
fn test_cross_tool_binary_file() {
    skip_without_git_crypt!();

    let dir = make_test_repo();
    let key_file = dir.path().join("exported-key");

    // Binary content with all byte values
    let binary_data: Vec<u8> = (0u8..=255).collect();

    // Encrypt with git-crypt
    assert_success(&git_crypt(dir.path(), &["init"]), "git-crypt init");

    fs::write(
        dir.path().join(".gitattributes"),
        "*.bin filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();
    fs::write(dir.path().join("data.bin"), &binary_data).unwrap();
    assert_success(
        &git(dir.path(), &["add", ".gitattributes", "data.bin"]),
        "git add",
    );
    assert_success(
        &git(dir.path(), &["commit", "-m", "binary data"]),
        "git commit",
    );

    // Export key and lock with git-crypt
    assert_success(
        &git_crypt(dir.path(), &["export-key", key_file.to_str().unwrap()]),
        "git-crypt export-key",
    );
    assert_success(&git_crypt(dir.path(), &["lock"]), "git-crypt lock");

    // Decrypt with gitveil
    assert_success(
        &gitveil(dir.path(), &["unlock", key_file.to_str().unwrap()]),
        "gitveil unlock",
    );

    let content = fs::read(dir.path().join("data.bin")).unwrap();
    assert_eq!(
        content, binary_data,
        "binary data should survive cross-tool encrypt/decrypt"
    );
}
