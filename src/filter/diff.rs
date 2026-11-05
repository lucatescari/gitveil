use std::fs::File;
use std::io::{self, BufReader, Write};
use std::path::Path;

use crate::constants::*;
use crate::error::GitVeilError;
use crate::filter::decrypt::decrypt_verified;
use crate::key::key_file::KeyFile;

/// Run the diff/textconv filter: decrypt a file and write plaintext to stdout.
/// This is called by git for `git diff` to show decrypted content.
///
/// Unlike the smudge filter, this reads from a file path (not stdin).
pub fn diff(
    file_path: &Path,
    output: &mut dyn Write,
    key_file: &KeyFile,
) -> Result<(), GitVeilError> {
    let file = File::open(file_path)?;
    let mut reader = BufReader::new(file);

    // Read header (loop: a short file is valid, just not encrypted)
    let mut header = [0u8; ENCRYPTED_FILE_HEADER_LEN];
    let mut got = 0;
    while got < ENCRYPTED_FILE_HEADER_LEN {
        match io::Read::read(&mut reader, &mut header[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(GitVeilError::Io(e)),
        }
    }

    if got < ENCRYPTED_FILE_HEADER_LEN || header != ENCRYPTED_FILE_HEADER {
        // Not encrypted — pass through everything, including a file shorter
        // than the header (previously dropped, which hid such changes in diffs).
        output.write_all(&header[..got])?;
        io::copy(&mut reader, output)?;
        output.flush()?;
        return Ok(());
    }

    // Read nonce
    let mut nonce = [0u8; NONCE_LEN];
    io::Read::read_exact(&mut reader, &mut nonce)
        .map_err(|_| GitVeilError::InvalidEncryptedHeader)?;

    decrypt_verified(&mut reader, output, key_file, &nonce)
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
        clean::clean(&mut Cursor::new(plaintext.as_slice()), &mut encrypted, &kf).unwrap();

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

    #[test]
    fn test_diff_passthrough_short_file() {
        let kf = KeyFile::generate();
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("short.txt");
        std::fs::write(&p, b"abc").unwrap();
        let mut output = Vec::new();
        diff(&p, &mut output, &kf).unwrap();
        assert_eq!(output, b"abc");
    }

    #[test]
    fn test_diff_rejects_tampered_file() {
        let kf = KeyFile::generate();
        let mut encrypted = Vec::new();
        clean::clean(
            &mut Cursor::new(b"top secret".as_slice()),
            &mut encrypted,
            &kf,
        )
        .unwrap();
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0x20;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.bin");
        std::fs::write(&p, &encrypted).unwrap();
        let mut output = Vec::new();
        let err = diff(&p, &mut output, &kf).unwrap_err();
        assert!(matches!(err, GitVeilError::TamperedFile));
        assert!(output.is_empty());
    }
}
