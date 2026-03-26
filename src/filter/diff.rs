use std::fs::File;
use std::io::{self, BufReader, Write};
use std::path::Path;

use crate::constants::*;
use crate::crypto::aes_ctr;
use crate::error::GitVeilError;
use crate::key::key_file::KeyFile;

/// Run the diff/textconv filter: decrypt a file and write plaintext to stdout.
/// This is called by git for `git diff` to show decrypted content.
///
/// Unlike the smudge filter, this reads from a file path (not stdin).
pub fn diff(file_path: &Path, output: &mut dyn Write, key_file: &KeyFile) -> Result<(), GitVeilError> {
    let file = File::open(file_path)?;
    let mut reader = BufReader::new(file);

    // Read header
    let mut header = [0u8; ENCRYPTED_FILE_HEADER_LEN];
    match io::Read::read_exact(&mut reader, &mut header) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            // File shorter than header — not encrypted, pass through
            return Ok(());
        }
        Err(e) => return Err(GitVeilError::Io(e)),
    }

    if header != ENCRYPTED_FILE_HEADER {
        // Not encrypted — pass through
        output.write_all(&header)?;
        io::copy(&mut reader, output)?;
        return Ok(());
    }

    let entry = key_file
        .latest()
        .ok_or(GitVeilError::NoKeyEntries)?;

    // Read nonce
    let mut nonce = [0u8; NONCE_LEN];
    io::Read::read_exact(&mut reader, &mut nonce)
        .map_err(|_| GitVeilError::InvalidEncryptedHeader)?;

    // Decrypt
    aes_ctr::process_stream(&mut reader, output, &entry.aes_key, &nonce)?;

    output.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::clean;
    use std::io::Cursor;

    #[test]
    fn test_diff_decrypts_encrypted_file() {
        let kf = KeyFile::generate();
        let plaintext = b"Secret data for diff test";

        // Encrypt via clean filter
        let mut encrypted = Vec::new();
        clean::clean(
            &mut Cursor::new(plaintext.as_slice()),
            &mut encrypted,
            &kf,
        )
        .unwrap();

        // Write encrypted data to a temp file
        let dir = std::env::temp_dir().join("gitveil-test-diff");
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("test-encrypted.bin");
        std::fs::write(&file_path, &encrypted).unwrap();

        // Diff should produce the original plaintext
        let mut output = Vec::new();
        diff(&file_path, &mut output, &kf).unwrap();

        assert_eq!(output, plaintext);

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_diff_passthrough_non_encrypted_file() {
        let kf = KeyFile::generate();
        let plaintext = b"This is just a normal text file, not encrypted";

        let dir = std::env::temp_dir().join("gitveil-test-diff-plain");
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("test-plain.txt");
        std::fs::write(&file_path, plaintext).unwrap();

        let mut output = Vec::new();
        diff(&file_path, &mut output, &kf).unwrap();

        assert_eq!(output, plaintext);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
