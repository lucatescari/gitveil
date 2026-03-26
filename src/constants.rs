/// Magic header for encrypted files: \0GITCRYPT\0
pub const ENCRYPTED_FILE_HEADER: &[u8] = b"\x00GITCRYPT\x00";
pub const ENCRYPTED_FILE_HEADER_LEN: usize = 10;

/// Magic header for key files: \0GITCRYPTKEY
pub const KEY_FILE_HEADER: &[u8] = b"\x00GITCRYPTKEY";
pub const KEY_FILE_HEADER_LEN: usize = 12;

/// Key file format version
pub const FORMAT_VERSION: u32 = 2;

/// AES-256 key length in bytes
pub const AES_KEY_LEN: usize = 32;

/// HMAC-SHA1 key length in bytes
pub const HMAC_KEY_LEN: usize = 64;

/// Nonce length (first 12 bytes of HMAC-SHA1 digest)
pub const NONCE_LEN: usize = 12;

/// Maximum field length in key file (1 MiB)
pub const MAX_FIELD_LEN: usize = 1 << 20;

/// Maximum key name length
pub const KEY_NAME_MAX_LEN: usize = 128;

// Header field IDs
pub const HEADER_FIELD_END: u32 = 0;
pub const HEADER_FIELD_KEY_NAME: u32 = 1;

// Key entry field IDs
pub const KEY_FIELD_END: u32 = 0;
pub const KEY_FIELD_VERSION: u32 = 1;
pub const KEY_FIELD_AES_KEY: u32 = 3;
pub const KEY_FIELD_HMAC_KEY: u32 = 5;

/// Buffer size for stream processing
pub const STREAM_BUFFER_SIZE: usize = 4096;

/// The default key name
pub const DEFAULT_KEY_NAME: &str = "default";

/// Filter name prefix used in .gitattributes
#[allow(dead_code)]
pub const FILTER_NAME: &str = "git-crypt";
