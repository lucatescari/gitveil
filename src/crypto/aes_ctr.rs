use aes::Aes256;
use cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr32BE;
use std::io::{Read, Write};

use crate::constants::{AES_KEY_LEN, NONCE_LEN, STREAM_BUFFER_SIZE};
use crate::error::GitVeilError;

type Aes256Ctr = Ctr32BE<Aes256>;

/// Encrypt or decrypt a stream using AES-256-CTR.
/// CTR mode is symmetric: encryption and decryption are the same operation.
///
/// The nonce is 12 bytes, and the counter is a 4-byte big-endian integer
/// starting at 0, matching git-crypt's construction.
///
/// # Security Notes
///
/// - CTR mode provides **confidentiality only**, not integrity. An attacker
///   can flip bits in ciphertext to flip corresponding plaintext bits.
/// - The 4-byte counter limits encryption to 2^32 blocks (64 GiB per file).
/// - Nonce reuse with the same key completely breaks confidentiality.
///   This tool derives nonces deterministically from HMAC-SHA1 of the plaintext,
///   which is safe (same plaintext = same nonce = same ciphertext, no leak).
pub fn process_stream(
    input: &mut dyn Read,
    output: &mut dyn Write,
    aes_key: &[u8; AES_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<(), GitVeilError> {
    // Construct the 16-byte IV: 12-byte nonce + 4-byte counter starting at 0
    let mut iv = [0u8; 16];
    iv[..NONCE_LEN].copy_from_slice(nonce);
    // Last 4 bytes are already 0 (counter = 0)

    let mut cipher = Aes256Ctr::new(aes_key.into(), &iv.into());

    let mut buf = [0u8; STREAM_BUFFER_SIZE];
    loop {
        let n = input.read(&mut buf).map_err(GitVeilError::Io)?;
        if n == 0 {
            break;
        }
        cipher.apply_keystream(&mut buf[..n]);
        output.write_all(&buf[..n]).map_err(GitVeilError::Io)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; AES_KEY_LEN];
        let nonce = [0x01u8; NONCE_LEN];
        let plaintext = b"Hello, gitveil! This is a test of AES-256-CTR encryption.";

        // Encrypt
        let mut input = Cursor::new(plaintext.as_slice());
        let mut ciphertext = Vec::new();
        process_stream(&mut input, &mut ciphertext, &key, &nonce).unwrap();

        assert_ne!(ciphertext, plaintext);
        assert_eq!(ciphertext.len(), plaintext.len());

        // Decrypt
        let mut input = Cursor::new(ciphertext.as_slice());
        let mut decrypted = Vec::new();
        process_stream(&mut input, &mut decrypted, &key, &nonce).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_empty_input() {
        let key = [0u8; AES_KEY_LEN];
        let nonce = [0u8; NONCE_LEN];

        let mut input = Cursor::new(Vec::<u8>::new());
        let mut output = Vec::new();
        process_stream(&mut input, &mut output, &key, &nonce).unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn test_deterministic() {
        let key = [0x55u8; AES_KEY_LEN];
        let nonce = [0x66u8; NONCE_LEN];
        let plaintext = b"Deterministic encryption test";

        let mut ct1 = Vec::new();
        let mut ct2 = Vec::new();

        process_stream(
            &mut Cursor::new(plaintext.as_slice()),
            &mut ct1,
            &key,
            &nonce,
        )
        .unwrap();
        process_stream(
            &mut Cursor::new(plaintext.as_slice()),
            &mut ct2,
            &key,
            &nonce,
        )
        .unwrap();

        assert_eq!(ct1, ct2);
    }
}
