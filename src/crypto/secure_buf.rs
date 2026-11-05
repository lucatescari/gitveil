//! Reading secret data into memory without leaving copies behind.
//!
//! `Read::read_to_end` grows its `Vec` by reallocating, and every
//! reallocation frees the old, smaller buffer *without* clearing it. Wrapping
//! the final `Vec` in `Zeroizing` only scrubs the last copy. The helper here
//! grows the buffer by hand and zeroizes each buffer it abandons, so plaintext
//! and key-file bytes never linger in freed heap memory.

use std::io::{ErrorKind, Read};
use zeroize::Zeroizing;

use crate::error::GitVeilError;

const INITIAL_CAPACITY: usize = 8 * 1024;

/// Read `reader` to EOF into a buffer that is zeroized on drop, as is every
/// intermediate buffer used while growing it.
///
/// Fails with [`GitVeilError::InputTooLarge`] once more than `limit` bytes
/// have been read, before allocating beyond that.
pub fn read_to_end_zeroizing(
    reader: &mut dyn Read,
    limit: u64,
) -> Result<Zeroizing<Vec<u8>>, GitVeilError> {
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(INITIAL_CAPACITY));
    let mut chunk = Zeroizing::new([0u8; 8 * 1024]);

    loop {
        let n = match reader.read(&mut chunk[..]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(GitVeilError::Io(e)),
        };

        if (buf.len() as u64).saturating_add(n as u64) > limit {
            return Err(GitVeilError::InputTooLarge(limit));
        }

        if buf.len() + n > buf.capacity() {
            let cap_limit = usize::try_from(limit).unwrap_or(usize::MAX);
            let new_cap = (buf.capacity().max(INITIAL_CAPACITY))
                .saturating_mul(2)
                .min(cap_limit)
                .max(buf.len() + n);
            let mut grown: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(new_cap));
            grown.extend_from_slice(&buf);
            // Dropping the old `Zeroizing<Vec>` scrubs its whole allocation.
            buf = grown;
        }
        // Capacity is guaranteed above, so this never reallocates.
        buf.extend_from_slice(&chunk[..n]);
    }

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn reads_everything_across_growth() {
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let out = read_to_end_zeroizing(&mut Cursor::new(&data), u64::MAX).unwrap();
        assert_eq!(&out[..], &data[..]);
    }

    #[test]
    fn empty_input() {
        let out = read_to_end_zeroizing(&mut Cursor::new(Vec::<u8>::new()), 10).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn exactly_at_limit_is_ok() {
        let out = read_to_end_zeroizing(&mut Cursor::new(vec![1u8; 10]), 10).unwrap();
        assert_eq!(out.len(), 10);
    }

    #[test]
    fn over_limit_is_rejected() {
        let err = read_to_end_zeroizing(&mut Cursor::new(vec![1u8; 11]), 10).unwrap_err();
        assert!(matches!(err, GitVeilError::InputTooLarge(10)));
    }
}
