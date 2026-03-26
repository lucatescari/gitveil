use rand::RngCore;

/// Fill buffer with cryptographically secure random bytes.
pub fn generate_random_bytes(buf: &mut [u8]) {
    rand::rngs::OsRng.fill_bytes(buf);
}
