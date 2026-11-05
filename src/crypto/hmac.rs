// `new_from_slice` moved from `Mac` to `KeyInit` in the hmac 0.13 /
// digest 0.11 generation; both traits must be in scope.
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

use crate::constants::{HMAC_KEY_LEN, NONCE_LEN};

type HmacSha1 = Hmac<Sha1>;

/// Compute HMAC-SHA1 of data using the given key.
/// Returns the full 20-byte digest.
pub fn compute_hmac_sha1(hmac_key: &[u8; HMAC_KEY_LEN], data: &[u8]) -> [u8; 20] {
    let mut mac = HmacSha1::new_from_slice(hmac_key).expect("HMAC-SHA1 accepts any key length");
    mac.update(data);
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    out
}

/// Derive a 12-byte nonce from the HMAC-SHA1 of plaintext.
/// This is the deterministic IV used for AES-256-CTR encryption,
/// ensuring identical plaintext produces identical ciphertext (required by git).
///
/// # Security
///
/// Deterministic encryption means an attacker can tell if two files have
/// identical content (same ciphertext = same plaintext). This is an inherent
/// trade-off: git's content-addressable storage requires deterministic output
/// to avoid spurious diffs. HMAC-SHA1 remains secure for PRF/MAC usage despite
/// SHA-1's collision weakness.
pub fn derive_nonce(hmac_key: &[u8; HMAC_KEY_LEN], plaintext: &[u8]) -> [u8; NONCE_LEN] {
    let digest = compute_hmac_sha1(hmac_key, plaintext);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&digest[..NONCE_LEN]);
    nonce
}

/// Incremental form of [`verify_nonce`], for checking plaintext produced
/// chunk by chunk without holding all of it in memory.
pub struct NonceVerifier(HmacSha1);

impl NonceVerifier {
    pub fn new(hmac_key: &[u8; HMAC_KEY_LEN]) -> Self {
        NonceVerifier(HmacSha1::new_from_slice(hmac_key).expect("HMAC-SHA1 accepts any key length"))
    }

    pub fn update(&mut self, plaintext_chunk: &[u8]) {
        self.0.update(plaintext_chunk);
    }

    /// Constant-time comparison of the leftmost 12 tag bytes with `nonce`.
    pub fn verify(self, nonce: &[u8; NONCE_LEN]) -> bool {
        self.0.verify_truncated_left(nonce).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha1_known_vector() {
        // RFC 2202 test vector 1
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let mut key_padded = [0u8; HMAC_KEY_LEN];
        key_padded[..20].copy_from_slice(&key);
        let result = compute_hmac_sha1(&key_padded, data);
        let expected: [u8; 20] = [
            0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37,
            0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00,
        ];
        assert_eq!(result, expected);
    }

    fn verifies(key: &[u8; HMAC_KEY_LEN], data: &[u8], nonce: &[u8; NONCE_LEN]) -> bool {
        let mut v = NonceVerifier::new(key);
        v.update(data);
        v.verify(nonce)
    }

    #[test]
    fn test_verifier_rejects_modified_data_nonce_or_key() {
        let key = [7u8; HMAC_KEY_LEN];
        let nonce = derive_nonce(&key, b"payload");
        assert!(verifies(&key, b"payload", &nonce));
        assert!(!verifies(&key, b"paYload", &nonce));
        let mut bad = nonce;
        bad[11] ^= 1;
        assert!(!verifies(&key, b"payload", &bad));
        assert!(!verifies(&[8u8; HMAC_KEY_LEN], b"payload", &nonce));
    }

    #[test]
    fn test_nonce_verifier_matches_one_shot() {
        let key = [9u8; HMAC_KEY_LEN];
        let data = b"chunked plaintext that is split";
        let nonce = derive_nonce(&key, data);
        let mut v = NonceVerifier::new(&key);
        for chunk in data.chunks(5) {
            v.update(chunk);
        }
        assert!(v.verify(&nonce));
        let mut v = NonceVerifier::new(&key);
        v.update(b"different");
        assert!(!v.verify(&nonce));
    }

    #[test]
    fn test_derive_nonce_length() {
        let key = [0u8; HMAC_KEY_LEN];
        let nonce = derive_nonce(&key, b"test data");
        assert_eq!(nonce.len(), NONCE_LEN);
    }

    #[test]
    fn test_derive_nonce_deterministic() {
        let key = [42u8; HMAC_KEY_LEN];
        let nonce1 = derive_nonce(&key, b"same data");
        let nonce2 = derive_nonce(&key, b"same data");
        assert_eq!(nonce1, nonce2);
    }

    #[test]
    fn test_derive_nonce_different_data() {
        let key = [42u8; HMAC_KEY_LEN];
        let nonce1 = derive_nonce(&key, b"data A");
        let nonce2 = derive_nonce(&key, b"data B");
        assert_ne!(nonce1, nonce2);
    }
}
