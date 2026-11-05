//! Security integration tests for the clean / smudge / diff filters, run
//! through the compiled binary inside a real repository.
//!
//! These cover the integrity guarantees git-crypt provides and gitveil must
//! match or exceed: a modified ciphertext, or a file encrypted under a
//! different key, must fail the filter with a non-zero exit and must not
//! emit any plaintext.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

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

/// Run gitveil with `input` on stdin.
fn gitveil_stdin(dir: &Path, args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(gitveil_bin())
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn gitveil {:?}: {}", args, e));
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
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

/// A git repo with gitveil initialized.
fn make_initialized_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("cannot create tempdir");
    let p = dir.path();
    assert_success(&git(p, &["init"]), "git init");
    assert_success(
        &git(p, &["config", "user.email", "t@gitveil.test"]),
        "email",
    );
    assert_success(&git(p, &["config", "user.name", "Test"]), "name");
    fs::write(p.join("README"), "test\n").unwrap();
    assert_success(&git(p, &["add", "README"]), "add");
    assert_success(&git(p, &["commit", "-m", "initial"]), "commit");
    assert_success(&gitveil(p, &["init"]), "gitveil init");
    dir
}

fn encrypt(dir: &Path, plaintext: &[u8]) -> Vec<u8> {
    let out = gitveil_stdin(dir, &["clean"], plaintext);
    assert_success(&out, "gitveil clean");
    assert!(out.stdout.starts_with(b"\0GITCRYPT\0"));
    out.stdout
}

#[test]
fn smudge_roundtrip_through_binary() {
    let repo = make_initialized_repo();
    let enc = encrypt(repo.path(), b"api_key=abc123\n");
    let out = gitveil_stdin(repo.path(), &["smudge"], &enc);
    assert_success(&out, "gitveil smudge");
    assert_eq!(out.stdout, b"api_key=abc123\n");
}

#[test]
fn smudge_rejects_bit_flipped_ciphertext() {
    let repo = make_initialized_repo();
    let mut enc = encrypt(repo.path(), b"enabled=false\n");
    // CTR malleability: flipping ciphertext bits flips the same plaintext
    // bits. Without the HMAC check this would silently decrypt to a
    // controlled change.
    let i = 22; // first body byte ('e')
    enc[i] ^= b'e' ^ b'E';
    let out = gitveil_stdin(repo.path(), &["smudge"], &enc);
    assert!(!out.status.success(), "tampered file must fail smudge");
    assert!(out.stdout.is_empty(), "no plaintext may be emitted");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("tampered"), "stderr: {err}");
}

#[test]
fn smudge_rejects_file_from_another_key() {
    let a = make_initialized_repo();
    let b = make_initialized_repo();
    let enc = encrypt(a.path(), b"only repo A can read this");
    let out = gitveil_stdin(b.path(), &["smudge"], &enc);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
}

#[test]
fn smudge_passes_through_plaintext_with_warning() {
    let repo = make_initialized_repo();
    let out = gitveil_stdin(repo.path(), &["smudge"], b"not encrypted\n");
    assert_success(&out, "smudge plaintext");
    assert_eq!(out.stdout, b"not encrypted\n");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("not encrypted"), "stderr: {err}");
}

#[test]
fn diff_rejects_tampered_file() {
    let repo = make_initialized_repo();
    let mut enc = encrypt(repo.path(), b"secret for diff\n");
    let last = enc.len() - 1;
    enc[last] ^= 1;
    let f = repo.path().join("tampered.bin");
    fs::write(&f, &enc).unwrap();
    let out = gitveil(repo.path(), &["diff", f.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
}

#[test]
fn diff_passes_through_short_plaintext_file() {
    let repo = make_initialized_repo();
    let f = repo.path().join("short.txt");
    fs::write(&f, b"abc").unwrap();
    let out = gitveil(repo.path(), &["diff", f.to_str().unwrap()]);
    assert_success(&out, "diff short file");
    assert_eq!(out.stdout, b"abc");
}

#[test]
fn checkout_of_tampered_blob_does_not_write_plaintext() {
    let repo = make_initialized_repo();
    let p = repo.path();
    fs::write(
        p.join(".gitattributes"),
        "secret.txt filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();
    fs::write(p.join("secret.txt"), "password=hunter2\n").unwrap();
    assert_success(&git(p, &["add", ".gitattributes", "secret.txt"]), "add");
    assert_success(&git(p, &["commit", "-m", "secret"]), "commit");

    // Attacker with push access but no key: rewrite the stored blob.
    let blob = git(p, &["cat-file", "blob", "HEAD:secret.txt"]).stdout;
    assert!(blob.starts_with(b"\0GITCRYPT\0"), "blob must be encrypted");
    let mut tampered = blob.clone();
    tampered[22] ^= 0x01;
    let mut child = Command::new("git")
        .args(["hash-object", "-w", "--stdin", "--no-filters"])
        .current_dir(p)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&tampered).unwrap();
    let out = child.wait_with_output().unwrap();
    assert_success(&out, "hash-object");
    let oid = String::from_utf8(out.stdout).unwrap().trim().to_string();

    // `git cat-file --filters` runs the smudge filter on the blob, exactly
    // as checkout would.
    let out = git(p, &["cat-file", "--filters", "--path=secret.txt", &oid]);
    assert!(
        !out.status.success(),
        "smudge of tampered blob must fail; stdout: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("password"));
}

#[test]
fn key_name_path_traversal_is_rejected_everywhere() {
    let repo = make_initialized_repo();
    let p = repo.path();
    for args in [
        // Filter plumbing takes the key name positionally (as git invokes it).
        vec!["clean", "../../evil"],
        vec!["smudge", "../evil"],
        vec!["diff", "a/b", "README"],
        vec!["export-key", "-k", "../x", "out.key"],
        vec!["lock", "-k", "..", "--force"],
        vec!["ls-gpg-users", "-k", "../x"],
        vec![
            "rm-gpg-user",
            "-k",
            "../x",
            "ABCDEF0123456789ABCDEF0123456789ABCDEF01",
        ],
        vec!["add-gpg-user", "-k", "x/../../y", "someone@example.com"],
    ] {
        let out = gitveil_stdin(p, &args, b"");
        assert!(!out.status.success(), "{args:?} must fail");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.to_lowercase().contains("invalid key name"),
            "{args:?}: {err}"
        );
    }
    // Nothing was written outside the repo's key dirs.
    assert!(!p.join("out.key").exists());
}

#[test]
fn git_diff_textconv_works_for_default_key() {
    // Regression: git runs the default-key textconv as `gitveil diff <file>`;
    // the lone argument used to be taken as a key name and every
    // `git diff` of an encrypted file failed.
    let repo = make_initialized_repo();
    let p = repo.path();
    fs::write(
        p.join(".gitattributes"),
        "f.txt filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();
    fs::write(p.join("f.txt"), "one\n").unwrap();
    assert_success(&git(p, &["add", "."]), "add");
    assert_success(&git(p, &["commit", "-m", "s"]), "commit");
    fs::write(p.join("f.txt"), "two\n").unwrap();
    let out = git(p, &["diff"]);
    assert_success(&out, "git diff");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("-one") && text.contains("+two"),
        "diff: {text}"
    );
}

#[test]
fn git_diff_textconv_works_for_named_key() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    assert_success(&git(p, &["init"]), "git init");
    assert_success(
        &git(p, &["config", "user.email", "t@gitveil.test"]),
        "email",
    );
    assert_success(&git(p, &["config", "user.name", "Test"]), "name");
    assert_success(&gitveil(p, &["init", "-k", "ops"]), "init -k ops");
    fs::write(
        p.join(".gitattributes"),
        "f.txt filter=git-crypt-ops diff=git-crypt-ops\n",
    )
    .unwrap();
    fs::write(p.join("f.txt"), "one\n").unwrap();
    assert_success(&git(p, &["add", "."]), "add");
    assert_success(&git(p, &["commit", "-m", "s"]), "commit");
    fs::write(p.join("f.txt"), "two\n").unwrap();
    let out = git(p, &["diff"]);
    assert_success(&out, "git diff");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("-one") && text.contains("+two"),
        "diff: {text}"
    );
}

#[test]
fn symmetric_unlock_with_wrong_key_changes_nothing() {
    let repo = make_initialized_repo();
    let p = repo.path();
    fs::write(
        p.join(".gitattributes"),
        "secret.txt filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();
    fs::write(p.join("secret.txt"), "password=hunter2\n").unwrap();
    assert_success(&git(p, &["add", "."]), "add");
    assert_success(&git(p, &["commit", "-m", "s"]), "commit");
    assert_success(&gitveil(p, &["lock"]), "lock");

    // A key from an unrelated repository.
    let other = make_initialized_repo();
    let wrong = other.path().join("wrong.key");
    assert_success(
        &gitveil(other.path(), &["export-key", wrong.to_str().unwrap()]),
        "export-key",
    );

    let out = gitveil(p, &["unlock", wrong.to_str().unwrap()]);
    assert!(!out.status.success(), "wrong key must be refused");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("does not decrypt"), "stderr: {err}");
    assert!(!p.join(".git/git-crypt/keys/default").exists());
    let status = git(p, &["status", "--porcelain"]);
    assert!(String::from_utf8_lossy(&status.stdout).trim().is_empty());
    assert!(fs::read(p.join("secret.txt"))
        .unwrap()
        .starts_with(b"\0GITCRYPT\0"));
}
