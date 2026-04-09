use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};
use zeroize::Zeroizing;

use crate::constants::MAX_FIELD_LEN;
use crate::error::GitVeilError;

/// A TLV field: (field_id, field_data). Data is zeroized on drop.
pub type TlvField = (u32, Zeroizing<Vec<u8>>);

/// Read a TLV field from the stream.
/// Returns (field_id, field_data). Returns None at EOF.
///
/// The returned `Vec<u8>` is wrapped in `Zeroizing` so that key material
/// (AES keys, HMAC keys) is automatically scrubbed from memory when the
/// caller drops the buffer after copying into fixed-size arrays.
pub fn read_field(reader: &mut dyn Read) -> Result<Option<TlvField>, GitVeilError> {
    let field_id = match reader.read_u32::<BigEndian>() {
        Ok(id) => id,
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(GitVeilError::Io(e)),
    };

    // End-of-section sentinel: git-crypt writes only field_id=0 with no
    // following field_len. Return immediately to stay compatible.
    if field_id == 0 {
        return Ok(Some((0, Zeroizing::new(Vec::new()))));
    }

    let field_len = reader
        .read_u32::<BigEndian>()
        .map_err(|_| GitVeilError::InvalidKeyFile("truncated field length".into()))?
        as usize;

    if field_len > MAX_FIELD_LEN {
        return Err(GitVeilError::InvalidKeyFile(format!(
            "field too large: {} bytes (max {})",
            field_len, MAX_FIELD_LEN
        )));
    }

    let mut data = Zeroizing::new(vec![0u8; field_len]);
    reader
        .read_exact(&mut data)
        .map_err(|_| GitVeilError::InvalidKeyFile("truncated field data".into()))?;

    Ok(Some((field_id, data)))
}

/// Write a TLV field to the stream.
pub fn write_field(writer: &mut dyn Write, field_id: u32, data: &[u8]) -> Result<(), GitVeilError> {
    let len: u32 = data.len().try_into().map_err(|_| {
        GitVeilError::InvalidKeyFile(format!(
            "field data too large for u32 length: {} bytes",
            data.len()
        ))
    })?;
    writer.write_u32::<BigEndian>(field_id)?;
    writer.write_u32::<BigEndian>(len)?;
    writer.write_all(data)?;
    Ok(())
}

/// Write an end-of-section sentinel (field_id=0 only).
/// git-crypt writes just the 4-byte field_id with no field_len.
pub fn write_end_field(writer: &mut dyn Write) -> Result<(), GitVeilError> {
    writer.write_u32::<BigEndian>(0)?;
    Ok(())
}

/// Check if a field ID is critical (odd = mandatory, even = can be skipped).
pub fn is_critical_field(field_id: u32) -> bool {
    field_id % 2 == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_write_read_field_roundtrip() {
        let mut buf = Vec::new();
        write_field(&mut buf, 42, b"hello").unwrap();

        let mut cursor = Cursor::new(&buf);
        let (id, data) = read_field(&mut cursor).unwrap().unwrap();
        assert_eq!(id, 42);
        assert_eq!(*data, b"hello");
    }

    #[test]
    fn test_write_read_end_field() {
        let mut buf = Vec::new();
        write_end_field(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let (id, data) = read_field(&mut cursor).unwrap().unwrap();
        assert_eq!(id, 0);
        assert!(data.is_empty());
    }

    #[test]
    fn test_read_field_eof() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        assert!(read_field(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn test_is_critical_field() {
        assert!(is_critical_field(1));
        assert!(is_critical_field(3));
        assert!(is_critical_field(5));
        assert!(!is_critical_field(0));
        assert!(!is_critical_field(2));
        assert!(!is_critical_field(4));
    }
}
