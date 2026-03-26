use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::Path;

use crate::constants::*;
use crate::error::GitVeilError;
use crate::key::entry::KeyEntry;
use crate::key::format::{is_critical_field, read_field, write_end_field, write_field};

/// A key file containing one or more versioned key entries.
/// Compatible with git-crypt's key file format (FORMAT_VERSION = 2).
pub struct KeyFile {
    key_name: Option<String>,
    /// Entries stored in a BTreeMap keyed by version number.
    entries: BTreeMap<u32, KeyEntry>,
}

impl KeyFile {
    pub fn new() -> Self {
        KeyFile {
            key_name: None,
            entries: BTreeMap::new(),
        }
    }

    /// Generate a new key file with a single version-0 entry.
    pub fn generate() -> Self {
        let mut kf = KeyFile::new();
        kf.entries.insert(0, KeyEntry::generate(0));
        kf
    }

    /// Get the key name. Returns "default" if no name is set.
    pub fn key_name(&self) -> &str {
        self.key_name.as_deref().unwrap_or(DEFAULT_KEY_NAME)
    }

    /// Set the key name.
    pub fn set_key_name(&mut self, name: &str) -> Result<(), GitVeilError> {
        validate_key_name(name)?;
        self.key_name = Some(name.to_string());
        Ok(())
    }

    /// Get the latest (highest version) key entry.
    pub fn latest(&self) -> Option<&KeyEntry> {
        self.entries.values().next_back()
    }

    /// Get a key entry by version.
    #[allow(dead_code)]
    pub fn get(&self, version: u32) -> Option<&KeyEntry> {
        self.entries.get(&version)
    }

    /// Load a key file from a reader.
    pub fn load(reader: &mut dyn Read) -> Result<Self, GitVeilError> {
        // Read and verify header
        let mut header = [0u8; KEY_FILE_HEADER_LEN];
        reader
            .read_exact(&mut header)
            .map_err(|_| GitVeilError::InvalidKeyFile("file too short for header".into()))?;

        if &header != KEY_FILE_HEADER {
            return Err(GitVeilError::InvalidKeyFile(
                "invalid magic header".into(),
            ));
        }

        let format_version = reader
            .read_u32::<BigEndian>()
            .map_err(|_| GitVeilError::InvalidKeyFile("missing format version".into()))?;

        if format_version != FORMAT_VERSION {
            return Err(GitVeilError::InvalidKeyFile(format!(
                "unsupported format version: {} (expected {})",
                format_version, FORMAT_VERSION
            )));
        }

        let mut kf = KeyFile::new();

        // Read header fields
        loop {
            let (field_id, data) = match read_field(reader)? {
                Some(f) => f,
                None => return Ok(kf),
            };

            match field_id {
                HEADER_FIELD_END => break,
                HEADER_FIELD_KEY_NAME => {
                    let name = String::from_utf8(data).map_err(|_| {
                        GitVeilError::InvalidKeyFile("key name is not valid UTF-8".into())
                    })?;
                    if !name.is_empty() {
                        kf.key_name = Some(name);
                    }
                }
                _ => {
                    if is_critical_field(field_id) {
                        return Err(GitVeilError::IncompatibleField(field_id));
                    }
                    // Skip unknown non-critical header fields
                }
            }
        }

        // Read key entries until EOF
        loop {
            // Try to read the first field of the next entry to check for EOF
            let mut peek_buf = [0u8; 8];
            match reader.read_exact(&mut peek_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(GitVeilError::Io(e)),
            }

            // We read 8 bytes (field_id + field_len) — reconstruct a reader
            // that starts with these bytes plus the rest
            let field_id = u32::from_be_bytes([peek_buf[0], peek_buf[1], peek_buf[2], peek_buf[3]]);
            let field_len =
                u32::from_be_bytes([peek_buf[4], peek_buf[5], peek_buf[6], peek_buf[7]]) as usize;

            if field_len > MAX_FIELD_LEN {
                return Err(GitVeilError::InvalidKeyFile("field too large".into()));
            }

            let mut field_data = vec![0u8; field_len];
            reader.read_exact(&mut field_data).map_err(|_| {
                GitVeilError::InvalidKeyFile("truncated entry field".into())
            })?;

            // We need to reconstruct the entry reading. The entry starts with this field.
            // Build a buffer containing this field + read the rest of the entry.
            let mut entry_buf = Vec::new();
            entry_buf.write_u32::<BigEndian>(field_id).unwrap();
            entry_buf.write_u32::<BigEndian>(field_len as u32).unwrap();
            entry_buf.extend_from_slice(&field_data);

            // Read remaining fields for this entry until END
            if field_id != KEY_FIELD_END {
                loop {
                    let mut fid_buf = [0u8; 4];
                    reader.read_exact(&mut fid_buf).map_err(|_| {
                        GitVeilError::InvalidKeyFile("truncated entry".into())
                    })?;
                    let fid = u32::from_be_bytes(fid_buf);

                    let mut flen_buf = [0u8; 4];
                    reader.read_exact(&mut flen_buf).map_err(|_| {
                        GitVeilError::InvalidKeyFile("truncated entry".into())
                    })?;
                    let flen = u32::from_be_bytes(flen_buf) as usize;

                    if flen > MAX_FIELD_LEN {
                        return Err(GitVeilError::InvalidKeyFile(format!(
                            "entry field too large: {} bytes (max {})",
                            flen, MAX_FIELD_LEN
                        )));
                    }

                    let mut fdata = vec![0u8; flen];
                    if flen > 0 {
                        reader.read_exact(&mut fdata).map_err(|_| {
                            GitVeilError::InvalidKeyFile("truncated entry field data".into())
                        })?;
                    }

                    entry_buf.write_u32::<BigEndian>(fid).unwrap();
                    entry_buf.write_u32::<BigEndian>(flen as u32).unwrap();
                    entry_buf.extend_from_slice(&fdata);

                    if fid == KEY_FIELD_END {
                        break;
                    }
                }
            }

            let mut entry_cursor = Cursor::new(&entry_buf);
            let entry = KeyEntry::load(&mut entry_cursor)?;
            kf.entries.insert(entry.version, entry);
        }

        Ok(kf)
    }

    /// Load a key file from a filesystem path.
    pub fn load_from_file(path: &Path) -> Result<Self, GitVeilError> {
        let data = fs::read(path)?;
        let mut cursor = Cursor::new(data);
        Self::load(&mut cursor)
    }

    /// Store the key file to a writer.
    pub fn store(&self, writer: &mut dyn Write) -> Result<(), GitVeilError> {
        // Write header
        writer.write_all(KEY_FILE_HEADER)?;
        writer.write_u32::<BigEndian>(FORMAT_VERSION)?;

        // Write key name header field if set
        if let Some(ref name) = self.key_name {
            write_field(writer, HEADER_FIELD_KEY_NAME, name.as_bytes())?;
        }
        write_end_field(writer)?;

        // Write entries in version order
        for entry in self.entries.values() {
            entry.store(writer)?;
        }

        Ok(())
    }

    /// Store the key file to a filesystem path with restricted permissions (0600).
    /// Key material must never be world-readable.
    pub fn store_to_file(&self, path: &Path) -> Result<(), GitVeilError> {
        use std::io::Write;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut buf = Vec::new();
        self.store(&mut buf)?;

        // Write with mode 0600 (owner read/write only) to protect key material.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(&buf)?;
        }
        #[cfg(not(unix))]
        {
            fs::write(path, &buf)?;
        }

        Ok(())
    }

    /// Serialize to bytes. The returned buffer is wrapped in `Zeroizing`
    /// to ensure key material is scrubbed from memory when dropped.
    pub fn to_bytes(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, GitVeilError> {
        let mut buf = Vec::new();
        self.store(&mut buf)?;
        Ok(zeroize::Zeroizing::new(buf))
    }
}

/// Validate a key name.
fn validate_key_name(name: &str) -> Result<(), GitVeilError> {
    if name.is_empty() {
        return Err(GitVeilError::InvalidKeyName(
            "key name cannot be empty".into(),
        ));
    }
    if name.len() > KEY_NAME_MAX_LEN {
        return Err(GitVeilError::InvalidKeyName(format!(
            "key name too long ({} > {})",
            name.len(),
            KEY_NAME_MAX_LEN
        )));
    }
    if name == DEFAULT_KEY_NAME {
        return Err(GitVeilError::InvalidKeyName(
            "cannot use 'default' as a named key".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(GitVeilError::InvalidKeyName(
            "key name may only contain [a-zA-Z0-9_-]".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_roundtrip() {
        let kf = KeyFile::generate();
        assert!(kf.latest().is_some());
        assert_eq!(kf.latest().unwrap().version, 0);
        assert_eq!(kf.key_name(), DEFAULT_KEY_NAME);

        let mut buf = Vec::new();
        kf.store(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let loaded = KeyFile::load(&mut cursor).unwrap();

        assert_eq!(loaded.key_name(), DEFAULT_KEY_NAME);
        let orig = kf.latest().unwrap();
        let load = loaded.latest().unwrap();
        assert_eq!(orig.version, load.version);
        assert_eq!(orig.aes_key, load.aes_key);
        assert_eq!(orig.hmac_key, load.hmac_key);
    }

    #[test]
    fn test_named_key_roundtrip() {
        let mut kf = KeyFile::generate();
        kf.set_key_name("my-secret-key").unwrap();

        let mut buf = Vec::new();
        kf.store(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let loaded = KeyFile::load(&mut cursor).unwrap();

        assert_eq!(loaded.key_name(), "my-secret-key");
    }

    #[test]
    fn test_invalid_key_names() {
        assert!(validate_key_name("").is_err());
        assert!(validate_key_name("default").is_err());
        assert!(validate_key_name("has spaces").is_err());
        assert!(validate_key_name("has/slash").is_err());
        assert!(validate_key_name(&"a".repeat(KEY_NAME_MAX_LEN + 1)).is_err());
    }

    #[test]
    fn test_valid_key_names() {
        assert!(validate_key_name("my-key").is_ok());
        assert!(validate_key_name("KEY_2").is_ok());
        assert!(validate_key_name("test123").is_ok());
    }

    #[test]
    fn test_header_format() {
        let kf = KeyFile::generate();
        let buf = kf.to_bytes().unwrap();

        // Verify magic header
        assert_eq!(&buf[..KEY_FILE_HEADER_LEN], KEY_FILE_HEADER);

        // Verify format version
        let version = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        assert_eq!(version, FORMAT_VERSION);
    }
}
