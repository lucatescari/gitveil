use std::io::{Read, Write};

use crate::constants::*;
use crate::error::GitVeilError;
use crate::filter::decrypt::decrypt_verified;
use crate::key::key_file::KeyFile;

/// Run the smudge filter: decrypt from stdin and write plaintext to stdout.
/// This is called by git during checkout to decrypt files.
///
/// Algorithm:
/// 1. Read the 10-byte header; verify it matches \0GITCRYPT\0
/// 2. Read the 12-byte nonce
/// 3. Decrypt the remaining data with AES-256-CTR
/// 4. Verify HMAC-SHA1(plaintext) against the nonce in constant time
/// 5. Only if it matches, write plaintext to output
///
/// If the header does not match, pass through the input unchanged
/// (the file is not encrypted) and warn on stderr, as git-crypt does: a
/// plaintext blob where an encrypted one is expected is either an accidental
/// commit of a secret or someone substituting content without the key.
pub fn smudge(
    input: &mut dyn Read,
    output: &mut dyn Write,
    key_file: &KeyFile,
) -> Result<(), GitVeilError> {
    // Read header. If the file is shorter than the header, it's not encrypted —
    // pass through whatever bytes were read.
    let mut header = [0u8; ENCRYPTED_FILE_HEADER_LEN];
    let mut header_bytes_read = 0;
    while header_bytes_read < ENCRYPTED_FILE_HEADER_LEN {
        match input.read(&mut header[header_bytes_read..]) {
            Ok(0) => break, // EOF before full header
            Ok(n) => header_bytes_read += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(GitVeilError::Io(e)),
        }
    }

    if header_bytes_read == 0 {
        return Ok(()); // Empty file
    }

    if header_bytes_read < ENCRYPTED_FILE_HEADER_LEN || header != ENCRYPTED_FILE_HEADER {
        // Not encrypted — pass through header + rest of input unchanged.
        warn_not_encrypted();
        output.write_all(&header[..header_bytes_read])?;
        std::io::copy(input, output)?;
        output.flush()?;
        return Ok(());
    }

    // Read nonce
    let mut nonce = [0u8; NONCE_LEN];
    input
        .read_exact(&mut nonce)
        .map_err(|_| GitVeilError::InvalidEncryptedHeader)?;

    decrypt_verified(input, output, key_file, &nonce)
}

fn warn_not_encrypted() {
    // Same wording intent as git-crypt's smudge warning. Goes to stderr so
    // the file content on stdout is untouched.
    eprintln!(
        "gitveil: warning: file is not encrypted; checking it out as-is.\n\
         gitveil: an encrypted path should never contain plaintext in the repo —\n\
         gitveil: run 'gitveil status' to find unencrypted files and 'gitveil status -f' to fix them."
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_smudge_passthrough_non_encrypted() {
        let kf = KeyFile::generate();
        let data = b"This is not encrypted, just plain text";

        let mut output = Vec::new();
        smudge(&mut Cursor::new(data.as_slice()), &mut output, &kf).unwrap();

        assert_eq!(output, data);
    }

    #[test]
    fn test_smudge_passthrough_empty() {
        let kf = KeyFile::generate();
        let data: &[u8] = b"";

        let mut output = Vec::new();
        smudge(&mut Cursor::new(data), &mut output, &kf).unwrap();

        assert!(output.is_empty());
    }

    #[test]
    fn test_smudge_passthrough_short_file() {
        let kf = KeyFile::generate();
        // File shorter than the 10-byte header — must pass through intact
        let data = b"short";

        let mut output = Vec::new();
        smudge(&mut Cursor::new(data.as_slice()), &mut output, &kf).unwrap();

        assert_eq!(output, data);
    }

    fn encrypt(kf: &KeyFile, plaintext: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        crate::filter::clean::clean(&mut Cursor::new(plaintext), &mut out, kf).unwrap();
        out
    }

    #[test]
    fn test_smudge_rejects_flipped_ciphertext_bit() {
        let kf = KeyFile::generate();
        let mut enc = encrypt(&kf, b"enabled=false");
        // Flip a bit in the body: CTR would turn this into a controlled
        // plaintext change if the HMAC were not checked.
        let last = enc.len() - 1;
        enc[last] ^= 0x01;
        let mut out = Vec::new();
        let err = smudge(&mut Cursor::new(enc), &mut out, &kf).unwrap_err();
        assert!(matches!(err, GitVeilError::TamperedFile), "{err:?}");
        assert!(out.is_empty(), "no plaintext may be released on failure");
    }

    #[test]
    fn test_smudge_rejects_flipped_nonce_bit() {
        let kf = KeyFile::generate();
        let mut enc = encrypt(&kf, b"secret value");
        enc[ENCRYPTED_FILE_HEADER_LEN] ^= 0x80;
        let mut out = Vec::new();
        let err = smudge(&mut Cursor::new(enc), &mut out, &kf).unwrap_err();
        assert!(matches!(err, GitVeilError::TamperedFile));
        assert!(out.is_empty());
    }

    #[test]
    fn test_smudge_rejects_wrong_key() {
        let kf = KeyFile::generate();
        let other = KeyFile::generate();
        let enc = encrypt(&kf, b"secret value");
        let mut out = Vec::new();
        let err = smudge(&mut Cursor::new(enc), &mut out, &other).unwrap_err();
        assert!(matches!(err, GitVeilError::TamperedFile));
        assert!(out.is_empty());
    }

    #[test]
    fn test_smudge_rejects_truncated_body() {
        let kf = KeyFile::generate();
        let mut enc = encrypt(&kf, b"some longer secret value");
        enc.truncate(enc.len() - 3);
        let mut out = Vec::new();
        let err = smudge(&mut Cursor::new(enc), &mut out, &kf).unwrap_err();
        assert!(matches!(err, GitVeilError::TamperedFile));
    }

    #[test]
    fn test_smudge_empty_plaintext_roundtrip() {
        let kf = KeyFile::generate();
        let enc = encrypt(&kf, b"");
        let mut out = Vec::new();
        smudge(&mut Cursor::new(enc), &mut out, &kf).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn test_smudge_truncated_nonce_is_error() {
        let kf = KeyFile::generate();
        let enc = encrypt(&kf, b"x");
        let mut out = Vec::new();
        let err = smudge(
            &mut Cursor::new(&enc[..ENCRYPTED_FILE_HEADER_LEN + 4]),
            &mut out,
            &kf,
        )
        .unwrap_err();
        assert!(matches!(err, GitVeilError::InvalidEncryptedHeader));
        assert!(out.is_empty());
    }

    #[test]
    fn test_smudge_passthrough_one_byte() {
        let kf = KeyFile::generate();
        let data = b"x";

        let mut output = Vec::new();
        smudge(&mut Cursor::new(data.as_slice()), &mut output, &kf).unwrap();

        assert_eq!(output, data);
    }
}
