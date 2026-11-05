//! Authenticated decryption shared by the smudge and diff filters.
//!
//! git-crypt files are AES-256-CTR with a synthetic nonce: the nonce is the
//! first 12 bytes of HMAC-SHA1(hmac_key, plaintext). CTR alone gives no
//! integrity, so after decrypting we recompute that HMAC and compare it with
//! the stored nonce in constant time — exactly git-crypt's tamper check.
//!
//! Unlike git-crypt, which streams plaintext to stdout and only *then*
//! reports the mismatch, we release nothing unless the check passes. A
//! tampered file or a wrong key therefore never puts attacker-influenced
//! bytes into the working tree or a diff.
//!
//! Memory: the input (stdin for smudge) cannot be rewound, so the
//! *ciphertext* is buffered once — it is not secret. Plaintext only ever
//! exists one small chunk at a time: pass 1 decrypts into the HMAC, pass 2
//! (after verification) decrypts to the output.

use std::io::{Read, Write};
use zeroize::Zeroizing;

use crate::constants::{
    ENCRYPTED_FILE_HEADER, ENCRYPTED_FILE_HEADER_LEN, MAX_CRYPT_BYTES, NONCE_LEN,
    STREAM_BUFFER_SIZE,
};
use crate::crypto::aes_ctr::CtrStream;
use crate::crypto::hmac::NonceVerifier;
use crate::error::GitVeilError;
use crate::key::entry::KeyEntry;
use crate::key::key_file::KeyFile;

/// Read the ciphertext body (everything after the header and nonce) from
/// `input`, find the key entry whose HMAC verifies, and only then write the
/// plaintext to `output`.
pub fn decrypt_verified(
    input: &mut dyn Read,
    output: &mut dyn Write,
    key_file: &KeyFile,
    nonce: &[u8; NONCE_LEN],
) -> Result<(), GitVeilError> {
    let ciphertext = read_ciphertext(input)?;
    let entry = find_verifying_entry(&ciphertext, key_file, nonce)?;

    let mut ctr = CtrStream::new(&entry.aes_key, nonce);
    let mut chunk = Zeroizing::new([0u8; STREAM_BUFFER_SIZE]);
    for c in ciphertext.chunks(STREAM_BUFFER_SIZE) {
        let buf = &mut chunk[..c.len()];
        buf.copy_from_slice(c);
        ctr.apply(buf)?;
        output.write_all(buf)?;
    }
    output.flush()?;
    Ok(())
}

/// Whether `blob` (a complete encrypted file, header included) was encrypted
/// under one of `key_file`'s entries. Used by `unlock` to check a candidate
/// key against real repository content before installing it.
pub fn key_decrypts_blob(key_file: &KeyFile, blob: &[u8]) -> bool {
    let body_start = ENCRYPTED_FILE_HEADER_LEN + NONCE_LEN;
    if blob.len() < body_start || &blob[..ENCRYPTED_FILE_HEADER_LEN] != ENCRYPTED_FILE_HEADER {
        return false;
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&blob[ENCRYPTED_FILE_HEADER_LEN..body_start]);
    find_verifying_entry(&blob[body_start..], key_file, &nonce).is_ok()
}

fn read_ciphertext(input: &mut dyn Read) -> Result<Vec<u8>, GitVeilError> {
    let mut ciphertext = Vec::new();
    input
        .take(MAX_CRYPT_BYTES + 1)
        .read_to_end(&mut ciphertext)?;
    if ciphertext.len() as u64 > MAX_CRYPT_BYTES {
        return Err(GitVeilError::InputTooLarge(MAX_CRYPT_BYTES));
    }
    Ok(ciphertext)
}

/// Try the newest key entry first (the one `clean` encrypts with), then any
/// older ones. git-crypt files carry no key-version field, so the HMAC check
/// is what identifies the right entry.
fn find_verifying_entry<'a>(
    ciphertext: &[u8],
    key_file: &'a KeyFile,
    nonce: &[u8; NONCE_LEN],
) -> Result<&'a KeyEntry, GitVeilError> {
    let mut tried_any = false;
    let mut chunk = Zeroizing::new([0u8; STREAM_BUFFER_SIZE]);
    for entry in key_file.entries_newest_first() {
        tried_any = true;
        let mut ctr = CtrStream::new(&entry.aes_key, nonce);
        let mut mac = NonceVerifier::new(&entry.hmac_key);
        for c in ciphertext.chunks(STREAM_BUFFER_SIZE) {
            let buf = &mut chunk[..c.len()];
            buf.copy_from_slice(c);
            ctr.apply(buf)?;
            mac.update(buf);
        }
        if mac.verify(nonce) {
            return Ok(entry);
        }
    }
    if tried_any {
        Err(GitVeilError::TamperedFile)
    } else {
        Err(GitVeilError::NoKeyEntries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn encrypt(kf: &KeyFile, plaintext: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        crate::filter::clean::clean(&mut Cursor::new(plaintext), &mut out, kf).unwrap();
        out
    }

    #[test]
    fn multi_chunk_roundtrip() {
        let kf = KeyFile::generate();
        let data: Vec<u8> = (0..(STREAM_BUFFER_SIZE * 3 + 17))
            .map(|i| i as u8)
            .collect();
        let enc = encrypt(&kf, &data);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&enc[10..22]);
        let mut out = Vec::new();
        decrypt_verified(&mut Cursor::new(&enc[22..]), &mut out, &kf, &nonce).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn key_decrypts_blob_accepts_own_key_only() {
        let kf = KeyFile::generate();
        let other = KeyFile::generate();
        let enc = encrypt(&kf, b"repo secret");
        assert!(key_decrypts_blob(&kf, &enc));
        assert!(!key_decrypts_blob(&other, &enc));
        assert!(!key_decrypts_blob(&kf, b"plain text, not encrypted"));
        assert!(!key_decrypts_blob(&kf, &enc[..15]));
    }
}
