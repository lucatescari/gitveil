use std::io::{Read, Write};

use crate::constants::*;
use crate::crypto::aes_ctr;
use crate::error::GitVeilError;
use crate::key::key_file::KeyFile;

/// Run the smudge filter: decrypt from stdin and write plaintext to stdout.
/// This is called by git during checkout to decrypt files.
///
/// Algorithm:
/// 1. Read the 10-byte header; verify it matches \0GITCRYPT\0
/// 2. Read the 12-byte nonce
/// 3. Decrypt the remaining data with AES-256-CTR
/// 4. Write plaintext to output
///
/// If the header does not match, pass through the input unchanged
/// (the file is not encrypted).
pub fn smudge(
    input: &mut dyn Read,
    output: &mut dyn Write,
    key_file: &KeyFile,
) -> Result<(), GitVeilError> {
    // Read header
    let mut header = [0u8; ENCRYPTED_FILE_HEADER_LEN];
    match input.read_exact(&mut header) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            // File is shorter than header — not encrypted, pass through
            output.write_all(&header[..0])?;
            return Ok(());
        }
        Err(e) => return Err(GitVeilError::Io(e)),
    }

    if header != ENCRYPTED_FILE_HEADER {
        // Not encrypted — pass through header + rest of input
        output.write_all(&header)?;
        std::io::copy(input, output)?;
        return Ok(());
    }

    let entry = key_file
        .latest()
        .ok_or(GitVeilError::NoKeyEntries)?;

    // Read nonce
    let mut nonce = [0u8; NONCE_LEN];
    input
        .read_exact(&mut nonce)
        .map_err(|_| GitVeilError::InvalidEncryptedHeader)?;

    // Decrypt remaining data
    aes_ctr::process_stream(input, output, &entry.aes_key, &nonce)?;

    output.flush()?;
    Ok(())
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
}
