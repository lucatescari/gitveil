//! Security regression tests for the GPG collaborator commands.
//!
//! Everything under `.git-crypt/` is repository content: anyone with push
//! access controls it. These tests plant hostile content there (unencrypted
//! or passphrase-only key files, mismatched key names, symlinks, odd file
//! names) and check that `unlock`, `add-gpg-user`, `rm-gpg-user` and
//! `ls-gpg-users` refuse it or handle it safely. They also cover ambiguous
//! GPG user IDs and multi-key `--from` files.
//!
//! Each test uses its own temporary GNUPGHOME and skips automatically when
//! gpg is not functional. Helpers are copied from `gpg_integration.rs`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

// ─── Helpers ───────────────────────────────────────────────────

/// Check whether gpg is available and fully functional with a temp
/// GNUPGHOME (see `gpg_integration.rs` for why `--version` is not enough).
fn gpg_available() -> bool {
    let version_ok = Command::new("gpg")
        .args(["--version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !version_ok {
        return false;
    }
    let tmp = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return false,
    };
    let _ = Command::new("gpg")
        .args(["--batch", "--list-keys"])
        .env("GNUPGHOME", tmp.path())
        .output();
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

fn gitveil_gpg(gpg_home: &Path, dir: &Path, args: &[&str]) -> Output {
    Command::new(gitveil_bin())
        .args(args)
        .current_dir(dir)
        .env("GNUPGHOME", gpg_home)
        .env("NO_COLOR", "1")
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

fn gpg(gpg_home: &Path, args: &[&str]) -> Output {
    Command::new("gpg")
        .args(args)
        .env("GNUPGHOME", gpg_home)
        .output()
        .unwrap_or_else(|e| panic!("failed to run gpg {:?}: {}", args, e))
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

/// Assert a command failed cleanly (non-zero exit, no Rust panic).
fn assert_clean_failure(output: &Output, context: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "{} should have failed:\nstdout: {}\nstderr: {}",
        context,
        String::from_utf8_lossy(&output.stdout),
        stderr,
    );
    assert!(
        !stderr.contains("panicked"),
        "{} panicked: {}",
        context,
        stderr
    );
}

fn make_git_repo() -> tempfile::TempDir {
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
    fs::write(dir.path().join("README"), "test repo\n").unwrap();
    assert_success(&git(dir.path(), &["add", "README"]), "git add README");
    assert_success(
        &git(dir.path(), &["commit", "-m", "initial"]),
        "git commit initial",
    );
    dir
}

/// Create a temp directory with an initialized git repo + gitveil init.
fn make_initialized_repo(gpg_home: &Path) -> tempfile::TempDir {
    let dir = make_git_repo();
    assert_success(
        &gitveil_gpg(gpg_home, dir.path(), &["init"]),
        "gitveil init",
    );
    dir
}

/// Generate an unprotected GPG test key. Returns the primary fingerprint.
fn generate_test_key(gpg_home: &Path, name: &str, email: &str) -> String {
    let key_spec = format!(
        "%no-protection\nKey-Type: RSA\nKey-Length: 2048\nName-Real: {}\nName-Email: {}\nExpire-Date: 0\n%commit\n",
        name, email
    );
    let mut child = Command::new("gpg")
        .args(["--batch", "--gen-key"])
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
    assert_success(&output, "gpg gen-key");

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

fn version_dir(repo: &Path, key_name: &str) -> PathBuf {
    repo.join(".git-crypt")
        .join("keys")
        .join(key_name)
        .join("0")
}

fn local_key_path(repo: &Path) -> PathBuf {
    repo.join(".git")
        .join("git-crypt")
        .join("keys")
        .join("default")
}

/// Produce a symmetric key file from an unrelated repository — the key an
/// attacker wants the victim to adopt.
fn make_attacker_key(gpg_home: &Path) -> (tempfile::TempDir, PathBuf) {
    let attacker_repo = make_initialized_repo(gpg_home);
    let key_file = attacker_repo.path().join("attacker.key");
    assert_success(
        &gitveil_gpg(
            gpg_home,
            attacker_repo.path(),
            &["export-key", &key_file.to_string_lossy()],
        ),
        "export attacker key",
    );
    (attacker_repo, key_file)
}

/// Commit everything under `.git-crypt/` (as an attacker pushing it would)
/// and drop the local key, simulating a fresh clone about to be unlocked.
fn commit_planted_and_forget_local_key(repo: &Path) {
    assert_success(&git(repo, &["add", "--", ".git-crypt"]), "git add planted");
    assert_success(
        &git(repo, &["commit", "-m", "planted"]),
        "git commit planted",
    );
    fs::remove_dir_all(repo.join(".git").join("git-crypt")).unwrap();
}

/// After a refused unlock, no key must have been installed.
fn assert_no_key_installed(repo: &Path) {
    assert!(
        !local_key_path(repo).exists(),
        "a planted key must not be installed as the repository key"
    );
}

// ─── unlock: planted key files ─────────────────────────────────

/// `gpg -d` happily "decrypts" a bare literal-data packet. Without checking
/// how gpg decrypted the file, a planted unencrypted key would be trusted.
#[test]
fn unlock_rejects_unencrypted_literal_key_file() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    let fp = generate_test_key(gpg_home.path(), "Victim", "victim@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());
    let (_attacker_repo, attacker_key) = make_attacker_key(gpg_home.path());

    let vdir = version_dir(dir.path(), "default");
    fs::create_dir_all(&vdir).unwrap();
    let planted = vdir.join(format!("{}.gpg", fp));
    assert_success(
        &gpg(
            gpg_home.path(),
            &[
                "--batch",
                "--compress-algo",
                "none",
                "-o",
                &planted.to_string_lossy(),
                "--store",
                &attacker_key.to_string_lossy(),
            ],
        ),
        "gpg --store",
    );
    commit_planted_and_forget_local_key(dir.path());

    let out = gitveil_gpg(gpg_home.path(), dir.path(), &["unlock"]);
    assert_clean_failure(&out, "unlock with literal-packet key file");
    assert_no_key_installed(dir.path());
}

/// ASCII-armored input skips the packet pre-check, so this exercises the
/// verification of gpg's status output on its own.
#[test]
fn unlock_rejects_armored_unencrypted_key_file() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    let fp = generate_test_key(gpg_home.path(), "Victim", "victim@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());
    let (_attacker_repo, attacker_key) = make_attacker_key(gpg_home.path());

    let vdir = version_dir(dir.path(), "default");
    fs::create_dir_all(&vdir).unwrap();
    let planted = vdir.join(format!("{}.gpg", fp));
    assert_success(
        &gpg(
            gpg_home.path(),
            &[
                "--batch",
                "--armor",
                "-o",
                &planted.to_string_lossy(),
                "--store",
                &attacker_key.to_string_lossy(),
            ],
        ),
        "gpg --armor --store",
    );
    commit_planted_and_forget_local_key(dir.path());

    let out = gitveil_gpg(gpg_home.path(), dir.path(), &["unlock"]);
    assert_clean_failure(&out, "unlock with armored literal key file");
    assert_no_key_installed(dir.path());
}

/// A user whose gpg.conf says `armor` gets ASCII-armored collaborator
/// files; those must still unlock.
#[test]
fn unlock_accepts_an_armored_collaborator_key() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    generate_test_key(gpg_home.path(), "Victim", "victim@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());
    fs::write(gpg_home.path().join("gpg.conf"), "armor\n").unwrap();
    assert_success(
        &gitveil_gpg(
            gpg_home.path(),
            dir.path(),
            &["add-gpg-user", "--trusted", "victim@gitveil.test"],
        ),
        "add-gpg-user (armored)",
    );
    let original = fs::read(local_key_path(dir.path())).unwrap();
    fs::remove_dir_all(dir.path().join(".git").join("git-crypt")).unwrap();

    assert_success(
        &gitveil_gpg(gpg_home.path(), dir.path(), &["unlock"]),
        "unlock (armored)",
    );
    assert_eq!(fs::read(local_key_path(dir.path())).unwrap(), original);
}

/// Same attack using a compressed (but still unencrypted) packet.
#[test]
fn unlock_rejects_compressed_unencrypted_key_file() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    let fp = generate_test_key(gpg_home.path(), "Victim", "victim@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());
    let (_attacker_repo, attacker_key) = make_attacker_key(gpg_home.path());

    let vdir = version_dir(dir.path(), "default");
    fs::create_dir_all(&vdir).unwrap();
    let planted = vdir.join(format!("{}.gpg", fp));
    assert_success(
        &gpg(
            gpg_home.path(),
            &[
                "--batch",
                "--compress-algo",
                "zlib",
                "-o",
                &planted.to_string_lossy(),
                "--store",
                &attacker_key.to_string_lossy(),
            ],
        ),
        "gpg --store (compressed)",
    );
    commit_planted_and_forget_local_key(dir.path());

    let out = gitveil_gpg(gpg_home.path(), dir.path(), &["unlock"]);
    assert_clean_failure(&out, "unlock with compressed key file");
    assert_no_key_installed(dir.path());
}

/// A passphrase-only (symmetric) message decrypts without the victim's
/// secret key; it must be refused. The GNUPGHOME's gpg.conf supplies the
/// passphrase non-interactively so that, were the file handed to gpg, it
/// would decrypt instead of prompting — the refusal must come from gitveil.
#[test]
fn unlock_rejects_symmetrically_encrypted_key_file() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    let fp = generate_test_key(gpg_home.path(), "Victim", "victim@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());
    let (_attacker_repo, attacker_key) = make_attacker_key(gpg_home.path());

    let vdir = version_dir(dir.path(), "default");
    fs::create_dir_all(&vdir).unwrap();
    let planted = vdir.join(format!("{}.gpg", fp));
    assert_success(
        &gpg(
            gpg_home.path(),
            &[
                "--batch",
                "--passphrase",
                "x",
                "--pinentry-mode",
                "loopback",
                "-o",
                &planted.to_string_lossy(),
                "-c",
                &attacker_key.to_string_lossy(),
            ],
        ),
        "gpg -c",
    );
    commit_planted_and_forget_local_key(dir.path());

    fs::write(
        gpg_home.path().join("gpg.conf"),
        "batch\npinentry-mode loopback\npassphrase x\n",
    )
    .unwrap();

    let out = gitveil_gpg(gpg_home.path(), dir.path(), &["unlock"]);
    assert_clean_failure(&out, "unlock with symmetric key file");
    assert_no_key_installed(dir.path());
}

/// A genuinely encrypted key whose embedded key name does not match the
/// directory it sits in must be rejected (git-crypt does the same).
#[test]
fn unlock_rejects_key_name_mismatch() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    let fp = generate_test_key(gpg_home.path(), "Victim", "victim@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());

    // A named key "other", exported and encrypted to the victim, planted
    // as if it were the default key.
    assert_success(
        &gitveil_gpg(gpg_home.path(), dir.path(), &["init", "-k", "other"]),
        "init -k other",
    );
    let other_key = dir.path().join("other.key");
    assert_success(
        &gitveil_gpg(
            gpg_home.path(),
            dir.path(),
            &["export-key", "-k", "other", &other_key.to_string_lossy()],
        ),
        "export-key -k other",
    );

    let vdir = version_dir(dir.path(), "default");
    fs::create_dir_all(&vdir).unwrap();
    let planted = vdir.join(format!("{}.gpg", fp));
    assert_success(
        &gpg(
            gpg_home.path(),
            &[
                "--batch",
                "--trust-model",
                "always",
                "-e",
                "-r",
                &fp,
                "-o",
                &planted.to_string_lossy(),
                &other_key.to_string_lossy(),
            ],
        ),
        "gpg -e",
    );
    fs::remove_file(&other_key).unwrap();
    commit_planted_and_forget_local_key(dir.path());

    let out = gitveil_gpg(gpg_home.path(), dir.path(), &["unlock"]);
    assert_clean_failure(&out, "unlock with mismatched key name");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("expected key name"),
        "error should name the key-name mismatch: {}",
        stderr
    );
    assert_no_key_installed(dir.path());
}

/// Decrypted output is capped, defeating compression bombs.
#[test]
fn unlock_rejects_oversized_decrypted_key() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    let fp = generate_test_key(gpg_home.path(), "Victim", "victim@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());

    let big = dir.path().join("big.bin");
    fs::write(&big, vec![0u8; 256 * 1024]).unwrap();
    let vdir = version_dir(dir.path(), "default");
    fs::create_dir_all(&vdir).unwrap();
    let planted = vdir.join(format!("{}.gpg", fp));
    assert_success(
        &gpg(
            gpg_home.path(),
            &[
                "--batch",
                "--trust-model",
                "always",
                "-e",
                "-r",
                &fp,
                "-o",
                &planted.to_string_lossy(),
                &big.to_string_lossy(),
            ],
        ),
        "gpg -e big",
    );
    fs::remove_file(&big).unwrap();
    commit_planted_and_forget_local_key(dir.path());

    let out = gitveil_gpg(gpg_home.path(), dir.path(), &["unlock"]);
    assert_clean_failure(&out, "unlock with oversized key");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("exceeds"),
        "should mention the cap: {stderr}"
    );
    assert_no_key_installed(dir.path());
}

/// Control: a legitimately added collaborator key still unlocks after the
/// local key is dropped.
#[test]
fn unlock_accepts_a_legitimate_collaborator_key() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    generate_test_key(gpg_home.path(), "Victim", "victim@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());
    assert_success(
        &gitveil_gpg(
            gpg_home.path(),
            dir.path(),
            &["add-gpg-user", "--trusted", "victim@gitveil.test"],
        ),
        "add-gpg-user",
    );
    let original = fs::read(local_key_path(dir.path())).unwrap();
    fs::remove_dir_all(dir.path().join(".git").join("git-crypt")).unwrap();

    assert_success(
        &gitveil_gpg(gpg_home.path(), dir.path(), &["unlock"]),
        "unlock",
    );
    assert_eq!(fs::read(local_key_path(dir.path())).unwrap(), original);
}

// ─── Ambiguous user IDs ────────────────────────────────────────

#[test]
fn add_gpg_user_rejects_ambiguous_user_id() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    generate_test_key(gpg_home.path(), "Alice One", "alice1@gitveil.test");
    generate_test_key(gpg_home.path(), "Alice Two", "alice2@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());

    let out = gitveil_gpg(
        gpg_home.path(),
        dir.path(),
        &["add-gpg-user", "--trusted", "alice"],
    );
    assert_clean_failure(&out, "add-gpg-user with ambiguous id");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("More than one public key matches"),
        "unexpected error: {}",
        stderr
    );
    assert!(
        !version_dir(dir.path(), "default").exists(),
        "no key file may be written for an ambiguous id"
    );
}

#[test]
fn rm_gpg_user_rejects_ambiguous_user_id() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    let fp1 = generate_test_key(gpg_home.path(), "Alice One", "alice1@gitveil.test");
    generate_test_key(gpg_home.path(), "Alice Two", "alice2@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());
    assert_success(
        &gitveil_gpg(
            gpg_home.path(),
            dir.path(),
            &["add-gpg-user", "--trusted", "alice1@gitveil.test"],
        ),
        "add alice1",
    );

    let out = gitveil_gpg(gpg_home.path(), dir.path(), &["rm-gpg-user", "alice"]);
    assert_clean_failure(&out, "rm-gpg-user with ambiguous id");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("More than one public key matches"),
        "unexpected error: {}",
        stderr
    );
    assert!(
        version_dir(dir.path(), "default")
            .join(format!("{}.gpg", fp1))
            .exists(),
        "no key file may be removed for an ambiguous id"
    );
}

// ─── --from with multiple keys ─────────────────────────────────

/// `gpg --import` imports every key in a file, but the preview shows only
/// one. A multi-key file must be refused before anything is imported.
#[test]
fn add_gpg_user_from_rejects_multi_key_file() {
    skip_without_gpg!();
    let source_home = tempfile::tempdir().unwrap();
    generate_test_key(source_home.path(), "Shown", "shown@gitveil.test");
    generate_test_key(source_home.path(), "Hidden", "hidden@gitveil.test");
    let export = gpg(source_home.path(), &["--armor", "--export"]);
    assert_success(&export, "gpg export");

    let gpg_home = tempfile::tempdir().unwrap();
    let dir = make_initialized_repo(gpg_home.path());
    let key_file = dir.path().join("keys.asc");
    fs::write(&key_file, &export.stdout).unwrap();

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
    assert_clean_failure(&out, "add-gpg-user --from multi-key file");
    assert!(
        !version_dir(dir.path(), "default").exists(),
        "no collaborator may be added from a multi-key file"
    );

    let listed = gpg(
        gpg_home.path(),
        &["--batch", "--with-colons", "--list-keys"],
    );
    let listed = String::from_utf8_lossy(&listed.stdout);
    assert!(
        !listed.contains("hidden@gitveil.test") && !listed.contains("shown@gitveil.test"),
        "no key from the multi-key file may be imported: {}",
        listed
    );
}

// ─── rm-gpg-user commits only its own change ───────────────────

#[test]
fn rm_gpg_user_does_not_commit_unrelated_staged_changes() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    let fp = generate_test_key(gpg_home.path(), "Bob", "bob@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());
    assert_success(
        &gitveil_gpg(
            gpg_home.path(),
            dir.path(),
            &["add-gpg-user", "--trusted", "bob@gitveil.test"],
        ),
        "add bob",
    );

    fs::write(dir.path().join("unrelated.txt"), "work in progress\n").unwrap();
    assert_success(
        &git(dir.path(), &["add", "unrelated.txt"]),
        "stage unrelated",
    );

    assert_success(
        &gitveil_gpg(
            gpg_home.path(),
            dir.path(),
            &["rm-gpg-user", "bob@gitveil.test"],
        ),
        "rm-gpg-user",
    );

    let committed = git(dir.path(), &["show", "--name-only", "--format=", "HEAD"]);
    let committed = String::from_utf8_lossy(&committed.stdout);
    assert!(
        committed.contains(&format!("{}.gpg", fp)),
        "removal should be committed: {}",
        committed
    );
    assert!(
        !committed.contains("unrelated.txt"),
        "unrelated staged file must not be committed: {}",
        committed
    );

    let staged = git(dir.path(), &["diff", "--cached", "--name-only"]);
    assert!(
        String::from_utf8_lossy(&staged.stdout).contains("unrelated.txt"),
        "unrelated file should still be staged"
    );
}

// ─── ls-gpg-users with hostile file names ──────────────────────

/// The file stem used to be sliced at byte 16 — a multibyte character
/// there made `ls-gpg-users` panic.
#[test]
fn ls_gpg_users_does_not_panic_on_multibyte_file_name() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    let dir = make_initialized_repo(gpg_home.path());
    let vdir = version_dir(dir.path(), "default");
    fs::create_dir_all(&vdir).unwrap();
    // 15 ASCII bytes then a 2-byte character straddling byte 16.
    fs::write(vdir.join("AAAAAAAAAAAAAAA\u{e9}\u{e9}\u{e9}.gpg"), b"x").unwrap();

    let out = gitveil_gpg(gpg_home.path(), dir.path(), &["ls-gpg-users"]);
    assert_success(&out, "ls-gpg-users with multibyte name");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ignored"),
        "invalid file should be flagged: {stdout}"
    );
}

/// Key directory names are repository content and must not reach the
/// terminal with control characters intact. (Control characters are not
/// valid in Windows file names, hence unix-only.)
#[cfg(unix)]
#[test]
fn ls_gpg_users_escapes_control_characters_in_names() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    let dir = make_initialized_repo(gpg_home.path());
    let vdir = version_dir(dir.path(), "evil\u{1b}[2J");
    fs::create_dir_all(&vdir).unwrap();
    fs::write(vdir.join("\u{1b}]0;pwned\u{7}.gpg"), b"x").unwrap();

    let out = gitveil_gpg(gpg_home.path(), dir.path(), &["ls-gpg-users"]);
    assert_success(&out, "ls-gpg-users with control characters");
    assert!(
        !out.stdout.contains(&0x1b),
        "escape characters must not be printed: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
}

// ─── Symlinks planted under .git-crypt (unix) ──────────────────

#[cfg(unix)]
mod symlinks {
    use super::*;
    use std::os::unix::fs::symlink;

    fn setup() -> (
        tempfile::TempDir,
        String,
        tempfile::TempDir,
        tempfile::TempDir,
    ) {
        let gpg_home = tempfile::tempdir().unwrap();
        let fp = generate_test_key(gpg_home.path(), "Carol", "carol@gitveil.test");
        let dir = make_initialized_repo(gpg_home.path());
        let outside = tempfile::tempdir().unwrap();
        (gpg_home, fp, dir, outside)
    }

    fn add_carol(gpg_home: &Path, dir: &Path) -> Output {
        gitveil_gpg(
            gpg_home,
            dir,
            &["add-gpg-user", "--trusted", "carol@gitveil.test"],
        )
    }

    fn assert_empty(dir: &Path) {
        let entries: Vec<_> = fs::read_dir(dir).unwrap().collect();
        assert!(
            entries.is_empty(),
            "nothing may be written outside the repo"
        );
    }

    #[test]
    fn add_refuses_symlinked_git_crypt_dir() {
        skip_without_gpg!();
        let (gpg_home, _fp, dir, outside) = setup();
        symlink(outside.path(), dir.path().join(".git-crypt")).unwrap();

        let out = add_carol(gpg_home.path(), dir.path());
        assert_clean_failure(&out, "add-gpg-user through symlinked .git-crypt");
        assert_empty(outside.path());
    }

    #[test]
    fn add_refuses_symlinked_key_dir() {
        skip_without_gpg!();
        let (gpg_home, _fp, dir, outside) = setup();
        let keys = dir.path().join(".git-crypt").join("keys");
        fs::create_dir_all(&keys).unwrap();
        symlink(outside.path(), keys.join("default")).unwrap();

        let out = add_carol(gpg_home.path(), dir.path());
        assert_clean_failure(&out, "add-gpg-user through symlinked key dir");
        assert_empty(outside.path());
    }

    #[test]
    fn add_refuses_symlinked_version_dir() {
        skip_without_gpg!();
        let (gpg_home, _fp, dir, outside) = setup();
        let key_dir = dir.path().join(".git-crypt").join("keys").join("default");
        fs::create_dir_all(&key_dir).unwrap();
        symlink(outside.path(), key_dir.join("0")).unwrap();

        let out = add_carol(gpg_home.path(), dir.path());
        assert_clean_failure(&out, "add-gpg-user through symlinked version dir");
        assert_empty(outside.path());
    }

    #[test]
    fn add_refuses_symlinked_gpg_file() {
        skip_without_gpg!();
        let (gpg_home, fp, dir, outside) = setup();
        let vdir = version_dir(dir.path(), "default");
        fs::create_dir_all(&vdir).unwrap();
        let target = outside.path().join("precious.txt");
        fs::write(&target, "precious\n").unwrap();
        symlink(&target, vdir.join(format!("{}.gpg", fp))).unwrap();

        let out = add_carol(gpg_home.path(), dir.path());
        assert_clean_failure(&out, "add-gpg-user through symlinked .gpg file");
        assert_eq!(fs::read_to_string(&target).unwrap(), "precious\n");
    }

    #[test]
    fn add_refuses_dangling_gitattributes_symlink() {
        skip_without_gpg!();
        let (gpg_home, _fp, dir, outside) = setup();
        let crypt_dir = dir.path().join(".git-crypt");
        fs::create_dir_all(&crypt_dir).unwrap();
        let target = outside.path().join("created-by-gitveil");
        symlink(&target, crypt_dir.join(".gitattributes")).unwrap();

        let out = add_carol(gpg_home.path(), dir.path());
        assert_clean_failure(&out, "add-gpg-user with dangling .gitattributes link");
        assert!(
            !target.exists(),
            "must not create a file through a dangling symlink"
        );
    }

    #[test]
    fn rm_refuses_symlinked_version_dir() {
        skip_without_gpg!();
        let (gpg_home, fp, dir, outside) = setup();
        let key_dir = dir.path().join(".git-crypt").join("keys").join("default");
        fs::create_dir_all(&key_dir).unwrap();
        symlink(outside.path(), key_dir.join("0")).unwrap();
        let victim = outside.path().join(format!("{}.gpg", fp));
        fs::write(&victim, "not yours\n").unwrap();

        let out = gitveil_gpg(
            gpg_home.path(),
            dir.path(),
            &["rm-gpg-user", "--no-commit", "carol@gitveil.test"],
        );
        assert_clean_failure(&out, "rm-gpg-user through symlinked version dir");
        assert!(victim.exists(), "file outside the repo must not be deleted");
    }
}

// ─── unlock: valid-but-foreign key encrypted to the victim ─────

/// Commit an encrypted secret so there is real ciphertext to check keys
/// against.
fn commit_encrypted_secret(gpg_home: &Path, repo: &Path) {
    let _ = gpg_home;
    fs::write(
        repo.join(".gitattributes"),
        "secret.txt filter=git-crypt diff=git-crypt\n",
    )
    .unwrap();
    fs::write(repo.join("secret.txt"), "password=hunter2\n").unwrap();
    assert_success(&git(repo, &["add", ".gitattributes", "secret.txt"]), "add");
    assert_success(&git(repo, &["commit", "-m", "secret"]), "commit secret");
}

/// Encrypt `key_file` to `fp` and write it over `dest`.
fn encrypt_key_to(gpg_home: &Path, fp: &str, key_file: &Path, dest: &Path) {
    let _ = fs::remove_file(dest);
    assert_success(
        &gpg(
            gpg_home,
            &[
                "--batch",
                "--trust-model",
                "always",
                "-e",
                "-r",
                fp,
                "-o",
                &dest.to_string_lossy(),
                &key_file.to_string_lossy(),
            ],
        ),
        "gpg -e attacker key",
    );
}

/// The attack that survives every packet/status check: the file really is
/// public-key encrypted to the victim — just with the attacker's key inside.
/// Installing it would make the victim encrypt future secrets to a key the
/// attacker knows. unlock must check the key against real ciphertext first.
#[test]
fn unlock_rejects_foreign_key_encrypted_to_victim_public_key() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    let fp = generate_test_key(gpg_home.path(), "Victim", "victim@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());
    assert_success(
        &gitveil_gpg(
            gpg_home.path(),
            dir.path(),
            &["add-gpg-user", "--trusted", "victim@gitveil.test"],
        ),
        "add-gpg-user",
    );
    commit_encrypted_secret(gpg_home.path(), dir.path());
    assert_success(&gitveil_gpg(gpg_home.path(), dir.path(), &["lock"]), "lock");

    // Attacker (push access, no repo key) swaps in their own key.
    let (_attacker_repo, attacker_key) = make_attacker_key(gpg_home.path());
    let planted = version_dir(dir.path(), "default").join(format!("{}.gpg", fp));
    encrypt_key_to(gpg_home.path(), &fp, &attacker_key, &planted);
    assert_success(&git(dir.path(), &["add", "--", ".git-crypt"]), "add");
    assert_success(&git(dir.path(), &["commit", "-m", "swap"]), "commit");

    let out = gitveil_gpg(gpg_home.path(), dir.path(), &["unlock"]);
    assert_clean_failure(&out, "unlock with foreign key");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("does not decrypt the files in this repository"),
        "stderr: {stderr}"
    );
    assert_no_key_installed(dir.path());
    // Nothing was deleted or half-checked-out.
    let status = git(dir.path(), &["status", "--porcelain"]);
    assert!(
        String::from_utf8_lossy(&status.stdout).trim().is_empty(),
        "working tree must be untouched: {}",
        String::from_utf8_lossy(&status.stdout)
    );
    assert!(fs::read(dir.path().join("secret.txt"))
        .unwrap()
        .starts_with(b"\0GITCRYPT\0"));
}

/// If one collaborator file the user can decrypt is bad, unlock must move on
/// to another one rather than abort (or worse, install the bad one).
#[test]
fn unlock_falls_back_to_next_collaborator_file_after_foreign_key() {
    skip_without_gpg!();
    let gpg_home = tempfile::tempdir().unwrap();
    let fp_a = generate_test_key(gpg_home.path(), "Victim A", "a@gitveil.test");
    let _fp_b = generate_test_key(gpg_home.path(), "Victim B", "b@gitveil.test");
    let dir = make_initialized_repo(gpg_home.path());
    for id in ["a@gitveil.test", "b@gitveil.test"] {
        assert_success(
            &gitveil_gpg(
                gpg_home.path(),
                dir.path(),
                &["add-gpg-user", "--trusted", id],
            ),
            "add-gpg-user",
        );
    }
    commit_encrypted_secret(gpg_home.path(), dir.path());
    let original = fs::read(local_key_path(dir.path())).unwrap();
    assert_success(&gitveil_gpg(gpg_home.path(), dir.path(), &["lock"]), "lock");

    let (_attacker_repo, attacker_key) = make_attacker_key(gpg_home.path());
    let planted = version_dir(dir.path(), "default").join(format!("{}.gpg", fp_a));
    encrypt_key_to(gpg_home.path(), &fp_a, &attacker_key, &planted);
    assert_success(&git(dir.path(), &["add", "--", ".git-crypt"]), "add");
    assert_success(&git(dir.path(), &["commit", "-m", "swap A"]), "commit");

    assert_success(
        &gitveil_gpg(gpg_home.path(), dir.path(), &["unlock"]),
        "unlock via the intact collaborator file",
    );
    assert_eq!(fs::read(local_key_path(dir.path())).unwrap(), original);
    assert_eq!(
        fs::read_to_string(dir.path().join("secret.txt")).unwrap(),
        "password=hunter2\n"
    );
}
