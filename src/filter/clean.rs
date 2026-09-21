use std::io::{Cursor, Read, Write};
use zeroize::Zeroizing;

use crate::constants::*;
use crate::crypto::aes_ctr;
use crate::crypto::hmac::derive_nonce;
use crate::error::GitVeilError;
use crate::key::key_file::KeyFile;

/// Run the clean filter: encrypt plaintext from stdin and write to stdout.
/// This is called by git during `git add` to encrypt files before storing in the repo.
///
/// Algorithm:
/// 1. Read all plaintext from input
/// 2. Compute HMAC-SHA1 of plaintext -> take first 12 bytes as nonce
/// 3. Write header: \0GITCRYPT\0 (10 bytes)
/// 4. Write nonce (12 bytes)
/// 5. Encrypt plaintext with AES-256-CTR and write ciphertext
pub fn clean(
    input: &mut dyn Read,
    output: &mut dyn Write,
    key_file: &KeyFile,
) -> Result<(), GitVeilError> {
    let entry = key_file.latest().ok_or(GitVeilError::NoKeyEntries)?;

    // Read all plaintext into memory. This is required because the deterministic
    // nonce is derived from HMAC-SHA1 of the entire file contents — we must hash
    // the complete plaintext before we can begin encryption. This means memory
    // usage is proportional to file size. For very large files (multi-GiB), this
    // could be problematic; a future optimization could stream the HMAC computation
    // and then re-read from a temp file for encryption.
    let mut plaintext = Zeroizing::new(Vec::new());
    input.read_to_end(&mut plaintext)?;

    // Derive deterministic nonce from HMAC-SHA1
    let nonce = derive_nonce(&entry.hmac_key, &plaintext);

    // Write encrypted file header
    output.write_all(ENCRYPTED_FILE_HEADER)?;

    // Write nonce
    output.write_all(&nonce)?;

    // Encrypt and write ciphertext
    let mut plain_cursor = Cursor::new(&plaintext);
    aes_ctr::process_stream(&mut plain_cursor, output, &entry.aes_key, &nonce)?;

    output.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::smudge;
    use std::io::Cursor;

    #[test]
    fn test_clean_produces_valid_header() {
        let kf = KeyFile::generate();
        let plaintext = b"Hello, world!";

        let mut input = Cursor::new(plaintext.as_slice());
        let mut output = Vec::new();

        clean(&mut input, &mut output, &kf).unwrap();

        // Check header
        assert!(output.starts_with(ENCRYPTED_FILE_HEADER));
        // Total: 10 (header) + 12 (nonce) + 13 (ciphertext) = 35
        assert_eq!(
            output.len(),
            ENCRYPTED_FILE_HEADER_LEN + NONCE_LEN + plaintext.len()
        );
    }

    #[test]
    fn test_clean_deterministic() {
        let kf = KeyFile::generate();
        let plaintext = b"Same data";

        let mut out1 = Vec::new();
        let mut out2 = Vec::new();

        clean(&mut Cursor::new(plaintext.as_slice()), &mut out1, &kf).unwrap();
        clean(&mut Cursor::new(plaintext.as_slice()), &mut out2, &kf).unwrap();

        assert_eq!(out1, out2);
    }

    #[test]
    fn test_clean_smudge_roundtrip() {
        let kf = KeyFile::generate();
        let plaintext = b"Roundtrip test data with some content!";

        let mut encrypted = Vec::new();
        clean(&mut Cursor::new(plaintext.as_slice()), &mut encrypted, &kf).unwrap();

        let mut decrypted = Vec::new();
        smudge::smudge(&mut Cursor::new(encrypted.as_slice()), &mut decrypted, &kf).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    /// Known-answer test anchored on **git-crypt 0.8.0**.
    ///
    /// The expected bytes were produced by running `git-crypt clean` with
    /// this exact key and plaintext — not by this implementation — so the
    /// vector remains a genuine cross-tool anchor. Unlike `cross_compat.rs`
    /// it needs no git-crypt installation, so it guards byte compatibility
    /// on every platform, including Windows.
    ///
    /// If this test fails, the on-disk format has changed and existing
    /// repositories can no longer be read by git-crypt.
    #[test]
    fn test_clean_matches_git_crypt_known_answer() {
        // git-crypt key file: format 2, entry version 0,
        // AES key = 0xAA * 32, HMAC key = 0xBB * 64.
        let mut key_bytes: Vec<u8> = Vec::new();
        key_bytes.extend_from_slice(b"\x00GITCRYPTKEY");
        key_bytes.extend_from_slice(&2u32.to_be_bytes());
        key_bytes.extend_from_slice(&0u32.to_be_bytes());
        key_bytes.extend_from_slice(&1u32.to_be_bytes());
        key_bytes.extend_from_slice(&4u32.to_be_bytes());
        key_bytes.extend_from_slice(&0u32.to_be_bytes());
        key_bytes.extend_from_slice(&3u32.to_be_bytes());
        key_bytes.extend_from_slice(&32u32.to_be_bytes());
        key_bytes.extend_from_slice(&[0xAAu8; 32]);
        key_bytes.extend_from_slice(&5u32.to_be_bytes());
        key_bytes.extend_from_slice(&64u32.to_be_bytes());
        key_bytes.extend_from_slice(&[0xBBu8; 64]);
        key_bytes.extend_from_slice(&0u32.to_be_bytes());

        let kf = KeyFile::load(&mut Cursor::new(&key_bytes)).expect("load git-crypt key");

        let mut out = Vec::new();
        clean(
            &mut Cursor::new(b"gitveil known-answer test\n".as_slice()),
            &mut out,
            &kf,
        )
        .unwrap();

        // `git-crypt clean < plaintext` with the key above, git-crypt 0.8.0.
        const GIT_CRYPT_OUTPUT: &str = "0047495443525950540\
                                        09eabeb896520896b76251cdcef1701aa\
                                        abe96c4693e203e90512fb9cf31355dd933ace404701";
        let expected: Vec<u8> = {
            let hex: String = GIT_CRYPT_OUTPUT
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect()
        };

        assert_eq!(
            out, expected,
            "clean filter output diverged from git-crypt 0.8.0 — the on-disk \
             format changed and existing repositories would break"
        );
    }
}
