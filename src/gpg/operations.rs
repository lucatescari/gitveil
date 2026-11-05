use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

use crate::crypto::random::generate_random_bytes;
use crate::error::GitVeilError;
use crate::git::config::get_git_config;
use crate::gpg::display::sanitize_for_display;
use crate::tempdir::create_private_temp_dir;

/// Upper bound on the plaintext accepted from `gpg -d` when decrypting a
/// collaborator key file. A real key file is a few hundred bytes; the cap
/// stops a compressed "bomb" planted in the repository from exhausting
/// memory.
pub const MAX_DECRYPTED_KEY_LEN: usize = 64 * 1024;

/// Get the GPG program to use (respects git config gpg.program).
pub fn get_gpg_program() -> String {
    get_git_config("gpg.program")
        .ok()
        .flatten()
        .unwrap_or_else(|| "gpg".to_string())
}

/// Extract the *primary* key fingerprints from `gpg --with-colons` output.
///
/// `primary_tag` is `pub` for public listings or `sec` for secret listings.
/// In colon format the primary key's fingerprint is the `fpr` record that
/// immediately follows its `pub`/`sec` record; subkey fingerprints follow
/// `sub`/`ssb` records and are ignored. Results are de-duplicated (in
/// listing order) and invalid fingerprints are dropped.
pub fn parse_primary_fingerprints(colon_output: &str, primary_tag: &str) -> Vec<String> {
    let mut fingerprints: Vec<String> = Vec::new();
    let mut expect_primary_fpr = false;

    for line in colon_output.lines() {
        let record = line.split(':').next().unwrap_or("");
        if record == primary_tag {
            expect_primary_fpr = true;
        } else if record == "fpr" {
            if expect_primary_fpr {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() > 9 {
                    let fp = parts[9].to_ascii_uppercase();
                    if validate_fingerprint(&fp).is_ok() && !fingerprints.contains(&fp) {
                        fingerprints.push(fp);
                    }
                }
            }
            expect_primary_fpr = false;
        } else if record != "grp" {
            // Any other record (sub, ssb, uid, ...) ends the window in which
            // an `fpr` would belong to the primary key.
            expect_primary_fpr = false;
        }
    }

    fingerprints
}

/// Get the primary-key fingerprint(s) matching a GPG user ID.
///
/// `gpg --list-keys <id>` matches substrings, short key IDs and subkeys, so
/// this can legitimately return several keys. Callers that need exactly one
/// key should use [`gpg_get_primary_fingerprint`].
pub fn gpg_get_fingerprints(user_id: &str) -> Result<Vec<String>, GitVeilError> {
    let gpg = get_gpg_program();

    let output = Command::new(&gpg)
        .args(["--with-colons", "--fingerprint", "--batch", "--list-keys"])
        // `--` stops a user ID beginning with `-` from being read as an option.
        .arg("--")
        .arg(user_id)
        .output()
        .map_err(|e| GitVeilError::Gpg(format!("failed to run {}: {}", gpg, e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GitVeilError::Gpg(format!(
            "gpg --list-keys failed for '{}': {}",
            sanitize_for_display(user_id),
            stderr
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let fingerprints = parse_primary_fingerprints(&stdout, "pub");

    if fingerprints.is_empty() {
        return Err(GitVeilError::Gpg(format!(
            "no fingerprints found for '{}'",
            sanitize_for_display(user_id)
        )));
    }

    Ok(fingerprints)
}

/// Resolve a GPG user ID to exactly one primary-key fingerprint.
///
/// Mirrors git-crypt: an ambiguous ID is an error rather than silently
/// picking the first match, which could grant (or revoke) access for the
/// wrong person.
pub fn gpg_get_primary_fingerprint(user_id: &str) -> Result<String, GitVeilError> {
    let fingerprints = gpg_get_fingerprints(user_id)?;
    single_fingerprint(user_id, fingerprints)
}

fn single_fingerprint(user_id: &str, fingerprints: Vec<String>) -> Result<String, GitVeilError> {
    match fingerprints.len() {
        1 => Ok(fingerprints.into_iter().next().unwrap()),
        0 => Err(GitVeilError::Gpg(format!(
            "no fingerprints found for '{}'",
            sanitize_for_display(user_id)
        ))),
        _ => Err(GitVeilError::Gpg(format!(
            "More than one public key matches '{}' - please be more specific",
            sanitize_for_display(user_id)
        ))),
    }
}

/// Validate that a GPG fingerprint is a hex string of expected length.
/// Prevents path traversal and command injection via crafted fingerprints.
pub fn validate_fingerprint(fingerprint: &str) -> Result<(), GitVeilError> {
    if !fingerprint.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(GitVeilError::Gpg(format!(
            "invalid fingerprint (non-hex characters): {}",
            sanitize_for_display(fingerprint)
        )));
    }
    // SHA-1 fingerprints are 40 chars, SHA-256 are 64 chars
    if fingerprint.len() < 40 || fingerprint.len() > 64 {
        return Err(GitVeilError::Gpg(format!(
            "invalid fingerprint length ({} chars, expected 40-64): {}",
            fingerprint.len(),
            fingerprint
        )));
    }
    Ok(())
}

fn random_hex(len_bytes: usize) -> String {
    let mut raw = vec![0u8; len_bytes];
    generate_random_bytes(&mut raw);
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

/// Encrypt data to a GPG recipient and write to a file.
///
/// The caller must have created `output_path`'s parent directory and checked
/// that no component of the path is a symlink (see
/// [`crate::gpg::safe_path`]). gpg writes to a fresh, randomly named file in
/// that directory — without `--yes`, so it never overwrites anything — which
/// is then renamed over `output_path`. `rename` replaces a directory entry
/// rather than following it, so even a symlink swapped in at the final name
/// is replaced, not written through.
pub fn gpg_encrypt_to_file(
    data: &[u8],
    fingerprint: &str,
    output_path: &Path,
    trusted: bool,
) -> Result<(), GitVeilError> {
    validate_fingerprint(fingerprint)?;
    let gpg = get_gpg_program();

    let parent = output_path
        .parent()
        .ok_or_else(|| GitVeilError::Other("output path has no parent directory".into()))?;
    match std::fs::symlink_metadata(parent) {
        Ok(meta) if meta.is_dir() => {}
        _ => {
            return Err(GitVeilError::Other(format!(
                "'{}' is not a directory",
                parent.display()
            )))
        }
    }

    let file_name = output_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let tmp_path: PathBuf = parent.join(format!(".{}.tmp-{}", file_name, random_hex(16)));

    let mut cmd = Command::new(&gpg);
    cmd.arg("--batch");

    if trusted {
        cmd.args(["--trust-model", "always"]);
    }

    cmd.args(["-e", "-r", &format!("0x{}", fingerprint), "-o"]);
    cmd.arg(&tmp_path);
    cmd.stdin(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| GitVeilError::Gpg(format!("failed to run {}: {}", gpg, e)))?;

    let write_result = match child.stdin.take() {
        Some(mut stdin) => stdin.write_all(data),
        None => Ok(()),
    };

    let status = child
        .wait()
        .map_err(|e| GitVeilError::Gpg(format!("failed to wait for gpg: {}", e)));

    let cleanup = |e: GitVeilError| {
        let _ = std::fs::remove_file(&tmp_path);
        e
    };

    write_result
        .map_err(|e| GitVeilError::Gpg(format!("failed to write to gpg stdin: {}", e)))
        .map_err(cleanup)?;
    let status = status.map_err(cleanup)?;

    if !status.success() {
        return Err(cleanup(GitVeilError::Gpg(format!(
            "gpg encryption failed for fingerprint {}",
            fingerprint
        ))));
    }

    match std::fs::symlink_metadata(&tmp_path) {
        Ok(meta) if meta.is_file() => {}
        _ => {
            return Err(cleanup(GitVeilError::Gpg(
                "gpg did not produce an encrypted file".into(),
            )))
        }
    }

    std::fs::rename(&tmp_path, output_path).map_err(|e| cleanup(e.into()))?;

    Ok(())
}

/// Build the gpg command line for decrypting a single file.
///
/// This intentionally does NOT pass `--batch`: decrypting a collaborator's
/// key requires the user's private GPG key, which is often passphrase-
/// protected. With `--batch`, gpg-agent refuses to launch pinentry and
/// decryption fails with "Inappropriate ioctl for device". Matching
/// git-crypt's behavior, the caller is responsible for connecting stdin
/// and stderr to the user's terminal so pinentry can prompt.
///
/// Status lines go to `status_file` (not stderr, which belongs to the user's
/// terminal) so the caller can verify *how* the data was decrypted.
fn build_decrypt_command(gpg: &str, path: &Path, status_file: &Path) -> Command {
    let mut cmd = Command::new(gpg);
    cmd.arg("--status-file");
    cmd.arg(status_file);
    cmd.args(["--yes", "-q", "-d", "--"]);
    cmd.arg(path);
    cmd
}

/// Verify gpg's `--status-file` output for a collaborator key decryption.
///
/// `gpg -d` exits successfully on data that was never encrypted at all (a
/// bare literal or compressed packet) and on symmetric (passphrase-only)
/// messages. Either would let anyone with push access plant a key file
/// named after a victim's fingerprint containing a key of their choosing.
/// So the decryption is only trusted when gpg reports:
///
/// - a public-key encrypted session key (`ENC_TO`),
/// - exactly one decryption (`BEGIN_DECRYPTION`) that succeeded
///   (`DECRYPTION_OKAY`) with integrity protection intact,
/// - exactly one plaintext, produced inside that decryption,
/// - no symmetric session key (`NEED_PASSPHRASE_SYM`),
/// - and, when gpg names the decryption key (`DECRYPTION_KEY`), that its
///   primary fingerprint is the one the file is named after.
pub fn verify_decrypt_status(status: &str, expected_fingerprint: &str) -> Result<(), GitVeilError> {
    let mut enc_to = false;
    let mut begin_count = 0usize;
    let mut in_decryption = false;
    let mut okay = false;
    let mut plaintext_count = 0usize;

    let fail = |why: &str| {
        Err(GitVeilError::Gpg(format!(
            "refusing GPG key file: {} (it must be public-key encrypted to your key)",
            why
        )))
    };

    for line in status.lines() {
        let Some(rest) = line.strip_prefix("[GNUPG:] ") else {
            continue;
        };
        let fields: Vec<&str> = rest.split_whitespace().collect();
        let Some(&keyword) = fields.first() else {
            continue;
        };

        match keyword {
            "ENC_TO" => enc_to = true,
            "NEED_PASSPHRASE_SYM" | "SYMKEY_ENC" => {
                return fail("it is symmetrically (passphrase) encrypted")
            }
            "DECRYPTION_FAILED" | "BADMDC" | "DECRYPTION_COMPLIANCE_MODE_FAILED" => {
                return fail("decryption failed")
            }
            "BEGIN_DECRYPTION" => {
                begin_count += 1;
                in_decryption = true;
            }
            "END_DECRYPTION" => in_decryption = false,
            "DECRYPTION_OKAY" => {
                if in_decryption {
                    okay = true;
                }
            }
            "PLAINTEXT" => {
                if !in_decryption {
                    return fail("it contains unencrypted data");
                }
                plaintext_count += 1;
            }
            "DECRYPTION_KEY" => {
                // DECRYPTION_KEY <fpr> <fpr2> <otrust>; fpr2 is the primary.
                let primary = fields.get(2).copied().unwrap_or("");
                if !primary.eq_ignore_ascii_case(expected_fingerprint) {
                    return fail("it was decrypted with a different key than its file name says");
                }
            }
            _ => {}
        }
    }

    if !enc_to {
        return fail("it is not public-key encrypted");
    }
    if begin_count != 1 || !okay {
        return fail("gpg did not report a successful decryption");
    }
    if plaintext_count != 1 {
        return fail("it does not contain exactly one plaintext");
    }
    Ok(())
}

/// How much of a key file [`check_packet_structure`] looks at. Public-key
/// encrypted session key packets are small; the encrypted data packet that
/// follows them is never read past its header.
const PACKET_SCAN_LIMIT: usize = 64 * 1024;

/// Walk the top-level OpenPGP packets of a binary message and require the
/// shape gitveil and git-crypt produce: one or more public-key encrypted
/// session key packets (tag 1) followed by an encrypted data packet
/// (tag 18 SEIPD, 20 AEAD or legacy 9). Literal (11) or compressed (8) data
/// outside encryption, and symmetric session keys (3), are refused. Marker
/// packets (10) are ignored, as RFC 4880 requires.
///
/// ASCII-armored input (e.g. from `armor` in the user's gpg.conf) is not
/// parsed here; [`verify_decrypt_status`] still applies to it.
fn check_packet_structure(data: &[u8]) -> Result<(), GitVeilError> {
    let fail = |why: &str| {
        Err(GitVeilError::Gpg(format!(
            "refusing GPG key file: {} (it must be public-key encrypted to your key)",
            why
        )))
    };

    match data.first() {
        None => return fail("it is empty"),
        Some(b) if b & 0x80 == 0 => return Ok(()), // not binary OpenPGP
        Some(_) => {}
    }

    let byte = |i: usize| data.get(i).map(|b| *b as usize);
    let mut pos = 0usize;
    let mut saw_pkesk = false;

    loop {
        let Some(b) = byte(pos) else {
            return fail("it contains no encrypted data");
        };
        if b & 0x80 == 0 {
            return fail("it is not a valid OpenPGP message");
        }

        // (tag, header length, body length — None for indeterminate/partial)
        let (tag, header_len, body_len): (usize, usize, Option<usize>) = if b & 0x40 != 0 {
            let tag = b & 0x3f;
            match byte(pos + 1) {
                None => return fail("it is truncated"),
                Some(l0) if l0 < 192 => (tag, 2, Some(l0)),
                Some(l0) if l0 < 224 => match byte(pos + 2) {
                    Some(l1) => (tag, 3, Some(((l0 - 192) << 8) + l1 + 192)),
                    None => return fail("it is truncated"),
                },
                Some(255) => match (byte(pos + 2), byte(pos + 3), byte(pos + 4), byte(pos + 5)) {
                    (Some(a), Some(b2), Some(c), Some(d)) => {
                        (tag, 6, Some((a << 24) | (b2 << 16) | (c << 8) | d))
                    }
                    _ => return fail("it is truncated"),
                },
                Some(_) => (tag, 2, None), // partial body length
            }
        } else {
            let tag = (b >> 2) & 0x0f;
            match b & 0x03 {
                0 => match byte(pos + 1) {
                    Some(l) => (tag, 2, Some(l)),
                    None => return fail("it is truncated"),
                },
                1 => match (byte(pos + 1), byte(pos + 2)) {
                    (Some(a), Some(c)) => (tag, 3, Some((a << 8) | c)),
                    _ => return fail("it is truncated"),
                },
                2 => match (byte(pos + 1), byte(pos + 2), byte(pos + 3), byte(pos + 4)) {
                    (Some(a), Some(b2), Some(c), Some(d)) => {
                        (tag, 5, Some((a << 24) | (b2 << 16) | (c << 8) | d))
                    }
                    _ => return fail("it is truncated"),
                },
                _ => (tag, 1, None), // indeterminate length
            }
        };

        match tag {
            1 => saw_pkesk = true,
            10 => {} // marker packet
            9 | 18 | 20 => {
                if !saw_pkesk {
                    return fail("it is not public-key encrypted");
                }
                return Ok(());
            }
            3 => return fail("it is symmetrically (passphrase) encrypted"),
            8 | 11 => return fail("it contains unencrypted data"),
            _ => return fail("it contains unexpected OpenPGP packets"),
        }

        let Some(len) = body_len else {
            return fail("it is not a valid OpenPGP message");
        };
        pos = pos
            .checked_add(header_len)
            .and_then(|p| p.checked_add(len))
            .ok_or_else(|| GitVeilError::Gpg("refusing GPG key file: bad packet length".into()))?;
    }
}

/// Decrypt a GPG-encrypted collaborator key file and return the plaintext.
///
/// Mirrors git-crypt: stdin and stderr are inherited from the parent so
/// pinentry (terminal or graphical) can prompt the user for a passphrase
/// when the secret key is protected. Stdout is piped so the decrypted
/// bytes can be collected (at most [`MAX_DECRYPTED_KEY_LEN`]).
///
/// The result is only returned when gpg's status output proves the file was
/// public-key encrypted to `expected_fingerprint` — see
/// [`verify_decrypt_status`].
///
/// The returned buffer is wrapped in `Zeroizing` to ensure key material
/// is scrubbed from memory when dropped.
pub fn gpg_decrypt_from_file(
    path: &Path,
    expected_fingerprint: &str,
) -> Result<Zeroizing<Vec<u8>>, GitVeilError> {
    // Cheap structural check first, so a planted unencrypted or
    // passphrase-only file is refused before gpg runs — and before it can
    // pop up a passphrase prompt for an attacker's symmetric message.
    let mut head = Vec::new();
    std::fs::File::open(path)?
        .take(PACKET_SCAN_LIMIT as u64)
        .read_to_end(&mut head)?;
    check_packet_structure(&head).map_err(|e| match e {
        GitVeilError::Gpg(msg) => GitVeilError::Gpg(format!("{}: {}", path.display(), msg)),
        other => other,
    })?;

    let gpg = get_gpg_program();

    // Private, unpredictable directory: a status file another local user
    // could pre-create or rewrite would defeat the verification.
    let status_dir = create_private_temp_dir("gitveil-gpg-status")
        .map_err(|e| GitVeilError::Gpg(format!("failed to create temp directory: {}", e)))?;
    let status_path = status_dir.join("status");

    let result = decrypt_with_status(&gpg, path, &status_path, expected_fingerprint);
    let _ = std::fs::remove_dir_all(&status_dir);
    result
}

fn decrypt_with_status(
    gpg: &str,
    path: &Path,
    status_path: &Path,
    expected_fingerprint: &str,
) -> Result<Zeroizing<Vec<u8>>, GitVeilError> {
    let mut cmd = build_decrypt_command(gpg, path, status_path);
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    let mut child = cmd
        .spawn()
        .map_err(|e| GitVeilError::Gpg(format!("failed to run {}: {}", gpg, e)))?;

    let mut buf = Zeroizing::new(Vec::new());
    let mut too_large = false;
    if let Some(mut stdout) = child.stdout.take() {
        // Decrypted key material: read without leaving unzeroized copies.
        let read = crate::crypto::secure_buf::read_to_end_zeroizing(
            &mut (&mut stdout).take(MAX_DECRYPTED_KEY_LEN as u64 + 1),
            u64::MAX,
        )
        .map(|b| buf = b);
        if let Err(e) = read {
            let _ = child.kill();
            let _ = child.wait();
            return Err(GitVeilError::Gpg(format!(
                "failed to read gpg stdout: {}",
                e
            )));
        }
        if buf.len() > MAX_DECRYPTED_KEY_LEN {
            too_large = true;
            let _ = child.kill();
        }
    }

    let status = child
        .wait()
        .map_err(|e| GitVeilError::Gpg(format!("failed to wait for gpg: {}", e)))?;

    if too_large {
        return Err(GitVeilError::Gpg(format!(
            "refusing GPG key file {}: decrypted data exceeds {} bytes",
            path.display(),
            MAX_DECRYPTED_KEY_LEN
        )));
    }

    if !status.success() {
        return Err(GitVeilError::Gpg(format!(
            "gpg decryption failed for {}",
            path.display()
        )));
    }

    // Lossy: status lines may carry user IDs in a non-UTF-8 charset; the
    // keywords and hex fields we check are ASCII either way.
    let status_bytes = std::fs::read(status_path)
        .map_err(|e| GitVeilError::Gpg(format!("failed to read gpg status output: {}", e)))?;
    let status_text = String::from_utf8_lossy(&status_bytes);
    verify_decrypt_status(&status_text, expected_fingerprint).map_err(|e| match e {
        GitVeilError::Gpg(msg) => GitVeilError::Gpg(format!("{}: {}", path.display(), msg)),
        other => other,
    })?;

    Ok(buf)
}

/// List the primary fingerprints of all secret keys in the local GPG keyring.
///
/// Used by `unlock` to skip `.gpg` files we obviously cannot decrypt, so
/// pinentry only fires once (for our own key) and gpg doesn't spam stderr
/// with "no secret key" messages for every other collaborator.
pub fn gpg_list_secret_key_fingerprints() -> Result<Vec<String>, GitVeilError> {
    let gpg = get_gpg_program();

    let output = Command::new(&gpg)
        .args(["--batch", "--with-colons", "--list-secret-keys"])
        .output()
        .map_err(|e| GitVeilError::Gpg(format!("failed to run {}: {}", gpg, e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GitVeilError::Gpg(format!(
            "gpg --list-secret-keys failed: {}",
            stderr.trim()
        )));
    }

    // Only primaries: `add-gpg-user` stores collaborator files keyed by
    // primary fingerprint.
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_primary_fingerprints(&stdout, "sec"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_of(cmd: &Command) -> Vec<String> {
        cmd.get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect()
    }

    #[test]
    fn decrypt_command_does_not_use_batch() {
        let cmd = build_decrypt_command("gpg", Path::new("dummy.gpg"), Path::new("st"));
        let args = args_of(&cmd);
        assert!(
            !args.iter().any(|a| a == "--batch"),
            "decrypt must not use --batch (it suppresses the pinentry passphrase prompt). Args: {:?}",
            args,
        );
    }

    #[test]
    fn decrypt_command_includes_decrypt_and_path() {
        let cmd = build_decrypt_command("gpg", Path::new("some/file.gpg"), Path::new("st"));
        let args = args_of(&cmd);
        assert!(
            args.iter().any(|a| a == "-d" || a == "--decrypt"),
            "decrypt must request decryption. Args: {:?}",
            args,
        );
        assert!(
            args.iter().any(|a| a.ends_with("file.gpg")),
            "decrypt must include the file path. Args: {:?}",
            args,
        );
    }

    #[test]
    fn decrypt_command_separates_path_from_options() {
        let cmd = build_decrypt_command("gpg", Path::new("-evil.gpg"), Path::new("st"));
        let args = args_of(&cmd);
        let dashdash = args.iter().position(|a| a == "--").expect("no --");
        let path = args.iter().position(|a| a == "-evil.gpg").unwrap();
        assert!(dashdash < path);
    }

    #[test]
    fn decrypt_command_requests_status_output() {
        let cmd = build_decrypt_command("gpg", Path::new("f.gpg"), Path::new("st"));
        assert!(args_of(&cmd).iter().any(|a| a == "--status-file"));
    }

    const FP: &str = "47FA77080DD2DA00B2802ECB0D21E23FCC5A4615";

    const PUBKEY_OK: &str = "\
[GNUPG:] ENC_TO 0D21E23FCC5A4615 1 0
[GNUPG:] KEY_CONSIDERED 47FA77080DD2DA00B2802ECB0D21E23FCC5A4615 0
[GNUPG:] DECRYPTION_KEY 47FA77080DD2DA00B2802ECB0D21E23FCC5A4615 47FA77080DD2DA00B2802ECB0D21E23FCC5A4615 u
[GNUPG:] BEGIN_DECRYPTION
[GNUPG:] DECRYPTION_INFO 0 9 2 0
[GNUPG:] PLAINTEXT 62 1793869191 p
[GNUPG:] PLAINTEXT_LENGTH 6
[GNUPG:] DECRYPTION_OKAY
[GNUPG:] GOODMDC
[GNUPG:] END_DECRYPTION
";

    #[test]
    fn accepts_public_key_decryption() {
        verify_decrypt_status(PUBKEY_OK, FP).unwrap();
        verify_decrypt_status(PUBKEY_OK, &FP.to_ascii_lowercase()).unwrap();
    }

    #[test]
    fn rejects_unencrypted_literal_data() {
        let status = "[GNUPG:] PLAINTEXT 62 1793869162 p\n[GNUPG:] PLAINTEXT_LENGTH 6\n";
        assert!(verify_decrypt_status(status, FP).is_err());
    }

    #[test]
    fn rejects_symmetric_encryption() {
        let status = "\
[GNUPG:] NEED_PASSPHRASE_SYM 9 3 8
[GNUPG:] BEGIN_DECRYPTION
[GNUPG:] DECRYPTION_INFO 2 9 0 0
[GNUPG:] PLAINTEXT 62 1793869171 p
[GNUPG:] DECRYPTION_OKAY
[GNUPG:] GOODMDC
[GNUPG:] END_DECRYPTION
";
        assert!(verify_decrypt_status(status, FP).is_err());
    }

    #[test]
    fn rejects_decryption_with_another_key() {
        let other = "AAAABBBBCCCCDDDDEEEEFFFF00001111222233334444";
        assert!(verify_decrypt_status(PUBKEY_OK, other).is_err());
    }

    #[test]
    fn rejects_plaintext_outside_the_decryption() {
        let status = format!("[GNUPG:] PLAINTEXT 62 0 x\n{}", PUBKEY_OK);
        assert!(verify_decrypt_status(&status, FP).is_err());
    }

    #[test]
    fn rejects_missing_decryption_okay() {
        let status = PUBKEY_OK.replace("[GNUPG:] DECRYPTION_OKAY\n", "");
        assert!(verify_decrypt_status(&status, FP).is_err());
    }

    #[test]
    fn rejects_two_decryptions() {
        let status = format!("{}{}", PUBKEY_OK, PUBKEY_OK);
        assert!(verify_decrypt_status(&status, FP).is_err());
    }

    #[test]
    fn packet_check_accepts_pkesk_then_seipd() {
        // old-format PKESK (tag 1, 1-byte length 3) + new-format SEIPD.
        let data = [0x84, 3, 1, 2, 3, 0xD2, 2, 0xAA, 0xBB];
        check_packet_structure(&data).unwrap();
    }

    #[test]
    fn packet_check_accepts_marker_and_new_format_pkesk() {
        let data = [0xCA, 3, b'P', b'G', b'P', 0xC1, 1, 0, 0xD2, 0xE0, 0];
        check_packet_structure(&data).unwrap();
    }

    #[test]
    fn packet_check_rejects_literal_data() {
        // old-format literal data (tag 11)
        assert!(check_packet_structure(&[0xAC, 2, b'b', 0]).is_err());
        // new-format literal data
        assert!(check_packet_structure(&[0xCB, 2, b'b', 0]).is_err());
    }

    #[test]
    fn packet_check_rejects_compressed_data() {
        assert!(check_packet_structure(&[0xA3, 0x01, 0x78]).is_err());
    }

    #[test]
    fn packet_check_rejects_symmetric_session_key() {
        let data = [0x8C, 2, 4, 9, 0xD2, 1, 0];
        assert!(check_packet_structure(&data).is_err());
    }

    #[test]
    fn packet_check_rejects_encrypted_data_without_pkesk() {
        assert!(check_packet_structure(&[0xD2, 1, 0]).is_err());
    }

    #[test]
    fn packet_check_rejects_truncated_or_empty() {
        assert!(check_packet_structure(&[]).is_err());
        assert!(check_packet_structure(&[0x84, 10, 1]).is_err());
    }

    #[test]
    fn packet_check_leaves_armored_input_to_status_checks() {
        check_packet_structure(b"-----BEGIN PGP MESSAGE-----\n").unwrap();
    }

    const TWO_KEYS: &str = "\
pub:u:2048:1:0D21E23FCC5A4615:1793869190:::u:::escarESCA::::::23::0:
fpr:::::::::47FA77080DD2DA00B2802ECB0D21E23FCC5A4615:
uid:u::::1793869190::X::A <alice@x.test>::::::::::0:
sub:u:2048:1:1111111111111111:1793869190::::::e::::::23:
fpr:::::::::BBBBBBBBBBBBBBBBBBBBBBBB1111111111111111:
pub:u:2048:1:A3339BD060D855B2:1793869190:::u:::escarESCA::::::23::0:
fpr:::::::::D29526727F884A84F31332ACA3339BD060D855B2:
";

    #[test]
    fn parses_only_primary_fingerprints() {
        let fps = parse_primary_fingerprints(TWO_KEYS, "pub");
        assert_eq!(
            fps,
            vec![
                "47FA77080DD2DA00B2802ECB0D21E23FCC5A4615".to_string(),
                "D29526727F884A84F31332ACA3339BD060D855B2".to_string()
            ]
        );
    }

    #[test]
    fn deduplicates_primary_fingerprints() {
        let doubled = format!("{}{}", TWO_KEYS, TWO_KEYS);
        assert_eq!(parse_primary_fingerprints(&doubled, "pub").len(), 2);
    }

    #[test]
    fn ambiguous_user_id_is_an_error() {
        let fps = parse_primary_fingerprints(TWO_KEYS, "pub");
        let err = single_fingerprint("alice", fps).unwrap_err().to_string();
        assert!(err.contains("More than one public key matches"), "{err}");
    }

    #[test]
    fn single_match_is_returned() {
        let fps = vec![FP.to_string()];
        assert_eq!(single_fingerprint("a", fps).unwrap(), FP);
    }
}
