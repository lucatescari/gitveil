use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::constants::*;
use crate::crypto::random::generate_random_bytes;
use crate::error::GitVeilError;
use crate::key::format::{is_critical_field, read_field, write_end_field, write_field};

/// A single key entry containing version, AES key, and HMAC key.
///
/// # Security
///
/// Key material (`aes_key`, `hmac_key`) is automatically zeroized when this
/// struct is dropped via `ZeroizeOnDrop`. However, intermediate copies created
/// during serialization/deserialization (e.g., `Vec<u8>` buffers in `read_field`)
/// are **not** automatically zeroized. The `KeyFile::to_bytes()` method wraps its
/// output in `Zeroizing<Vec<u8>>` to mitigate this for the serialization path.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyEntry {
    pub version: u32,
    pub aes_key: [u8; AES_KEY_LEN],
    pub hmac_key: [u8; HMAC_KEY_LEN],
}

impl KeyEntry {
    /// Generate a new key entry with random keys.
    pub fn generate(version: u32) -> Self {
        let mut aes_key = [0u8; AES_KEY_LEN];
        let mut hmac_key = [0u8; HMAC_KEY_LEN];
        generate_random_bytes(&mut aes_key);
        generate_random_bytes(&mut hmac_key);
        KeyEntry {
            version,
            aes_key,
            hmac_key,
        }
    }

    /// Load a key entry from a stream by reading TLV fields until KEY_FIELD_END.
    pub fn load(reader: &mut dyn std::io::Read) -> Result<Self, GitVeilError> {
        // Fill a zeroize-on-drop entry directly, so key bytes never sit in
        // loose `[u8; N]` stack copies that an early `return Err` would leak.
        let mut entry = KeyEntry {
            version: 0,
            aes_key: [0u8; AES_KEY_LEN],
            hmac_key: [0u8; HMAC_KEY_LEN],
        };
        let (mut have_version, mut have_aes, mut have_hmac) = (false, false, false);

        loop {
            // git-crypt treats EOF before KEY_FIELD_END as malformed.
            let (field_id, data) = read_field(reader)?.ok_or_else(|| {
                GitVeilError::InvalidKeyFile("truncated key entry (no end marker)".into())
            })?;
            match field_id {
                KEY_FIELD_END => break,
                KEY_FIELD_VERSION => {
                    if data.len() != 4 {
                        return Err(GitVeilError::InvalidKeyFile(
                            "version field must be 4 bytes".into(),
                        ));
                    }
                    entry.version = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                    have_version = true;
                }
                KEY_FIELD_AES_KEY => {
                    if data.len() != AES_KEY_LEN {
                        return Err(GitVeilError::InvalidKeyFile(format!(
                            "AES key must be {} bytes, got {}",
                            AES_KEY_LEN,
                            data.len()
                        )));
                    }
                    entry.aes_key.copy_from_slice(&data);
                    have_aes = true;
                }
                KEY_FIELD_HMAC_KEY => {
                    if data.len() != HMAC_KEY_LEN {
                        return Err(GitVeilError::InvalidKeyFile(format!(
                            "HMAC key must be {} bytes, got {}",
                            HMAC_KEY_LEN,
                            data.len()
                        )));
                    }
                    entry.hmac_key.copy_from_slice(&data);
                    have_hmac = true;
                }
                _ => {
                    if is_critical_field(field_id) {
                        return Err(GitVeilError::IncompatibleField(field_id));
                    }
                }
            }
        }

        if !have_version {
            return Err(GitVeilError::InvalidKeyFile(
                "missing version field in key entry".into(),
            ));
        }
        if !have_aes {
            return Err(GitVeilError::InvalidKeyFile(
                "missing AES key field in key entry".into(),
            ));
        }
        if !have_hmac {
            return Err(GitVeilError::InvalidKeyFile(
                "missing HMAC key field in key entry".into(),
            ));
        }
        Ok(entry)
    }

    pub fn store(&self, writer: &mut dyn std::io::Write) -> Result<(), GitVeilError> {
        write_field(writer, KEY_FIELD_VERSION, &self.version.to_be_bytes())?;
        write_field(writer, KEY_FIELD_AES_KEY, &self.aes_key)?;
        write_field(writer, KEY_FIELD_HMAC_KEY, &self.hmac_key)?;
        write_end_field(writer)?;
        Ok(())
    }
}

impl std::fmt::Debug for KeyEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyEntry")
            .field("version", &self.version)
            .field("aes_key", &"[REDACTED]")
            .field("hmac_key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_generate_and_roundtrip() {
        let entry = KeyEntry::generate(0);
        assert_eq!(entry.version, 0);

        let mut buf = Vec::new();
        entry.store(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let loaded = KeyEntry::load(&mut cursor).unwrap();

        assert_eq!(loaded.version, entry.version);
        assert_eq!(loaded.aes_key, entry.aes_key);
        assert_eq!(loaded.hmac_key, entry.hmac_key);
    }

    #[test]
    fn test_load_rejects_missing_end_marker() {
        let entry = KeyEntry::generate(0);
        let mut buf = Vec::new();
        entry.store(&mut buf).unwrap();
        buf.truncate(buf.len() - 4); // drop KEY_FIELD_END
        assert!(KeyEntry::load(&mut Cursor::new(&buf)).is_err());
    }

    #[test]
    fn test_store_load_specific_version() {
        let entry = KeyEntry::generate(42);

        let mut buf = Vec::new();
        entry.store(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let loaded = KeyEntry::load(&mut cursor).unwrap();
        assert_eq!(loaded.version, 42);
    }
}
