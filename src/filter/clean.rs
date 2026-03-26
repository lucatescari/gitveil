use std::io::{Cursor, Read, Write};

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
    let entry = key_file
        .latest()
        .ok_or(GitVeilError::NoKeyEntries)?;

    // Read all plaintext (must buffer to compute HMAC before encryption)
    let mut plaintext = Vec::new();
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
        assert_eq!(output.len(), ENCRYPTED_FILE_HEADER_LEN + NONCE_LEN + plaintext.len());
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
}
