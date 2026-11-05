//! Authenticated decryption shared by the smudge and diff filters.
//!
//! git-crypt files are AES-256-CTR with a synthetic nonce: the nonce is the
//! first 12 bytes of HMAC-SHA1(hmac_key, plaintext). CTR alone gives no
//! integrity, so after decrypting we recompute that HMAC and compare it with
//! the stored nonce in constant time — exactly git-crypt's tamper check.
//!
//! Unlike git-crypt, which streams plaintext to stdout and only *then*
//! reports the mismatch, we decrypt into a zeroizing buffer and release
//! nothing unless the check passes. A tampered file or a wrong key therefore
//! never puts attacker-influenced bytes into the working tree or a diff.

use std::io::{Read, Write};
use zeroize::Zeroizing;

use crate::constants::{MAX_CRYPT_BYTES, NONCE_LEN};
use crate::crypto::aes_ctr;
use crate::crypto::hmac::verify_nonce;
use crate::crypto::secure_buf::read_to_end_zeroizing;
use crate::error::GitVeilError;
use crate::key::key_file::KeyFile;

/// Read the ciphertext body (everything after the header and nonce) from
/// `input`, decrypt it, verify it, and write the plaintext to `output`.
pub fn decrypt_verified(
    input: &mut dyn Read,
    output: &mut dyn Write,
    key_file: &KeyFile,
    nonce: &[u8; NONCE_LEN],
) -> Result<(), GitVeilError> {
    let ciphertext = read_to_end_zeroizing(input, MAX_CRYPT_BYTES)?;
    let plaintext = decrypt_with_any_entry(&ciphertext, key_file, nonce)?;
    output.write_all(&plaintext)?;
    output.flush()?;
    Ok(())
}

/// Try the newest key entry first (the one `clean` encrypts with), then any
/// older ones. git-crypt files carry no key-version field, so the HMAC check
/// is what identifies the right entry.
fn decrypt_with_any_entry(
    ciphertext: &[u8],
    key_file: &KeyFile,
    nonce: &[u8; NONCE_LEN],
) -> Result<Zeroizing<Vec<u8>>, GitVeilError> {
    let mut tried_any = false;
    for entry in key_file.entries_newest_first() {
        tried_any = true;
        let mut buf = Zeroizing::new(ciphertext.to_vec());
        aes_ctr::process_in_place(&mut buf, &entry.aes_key, nonce)?;
        if verify_nonce(&entry.hmac_key, &buf, nonce) {
            return Ok(buf);
        }
        // `buf` (wrong-key garbage or tampered plaintext) is zeroized here.
    }
    if tried_any {
        Err(GitVeilError::TamperedFile)
    } else {
        Err(GitVeilError::NoKeyEntries)
    }
}
