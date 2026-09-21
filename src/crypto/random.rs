/// Fill buffer with cryptographically secure random bytes straight from the
/// operating system (`getrandom`/`urandom` on unix, `BCryptGenRandom` on
/// Windows).
///
/// # Security
///
/// This is the only source of randomness in gitveil and it is used solely to
/// generate key material. There is deliberately no userspace PRNG in the
/// dependency graph: the OS CSPRNG is the whole requirement, so nothing is
/// seeded, cached, or reused between calls.
///
/// # Panics
///
/// Panics if the OS entropy source is unavailable. Generating a key from a
/// failed or partial draw would silently produce weak key material, so
/// failing loudly is the only safe response. This matches the behaviour of
/// the `rand::rngs::OsRng` this replaced, which also panicked on failure.
pub fn generate_random_bytes(buf: &mut [u8]) {
    getrandom::fill(buf).expect("OS random number generator unavailable");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_buffer_with_random_bytes() {
        let mut buf = [0u8; 32];
        generate_random_bytes(&mut buf);
        assert_ne!(buf, [0u8; 32], "buffer was left zeroed");
    }

    #[test]
    fn successive_calls_produce_different_output() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        generate_random_bytes(&mut a);
        generate_random_bytes(&mut b);
        assert_ne!(a, b, "two draws returned identical bytes");
    }

    /// Guards against a partial fill: only the head of the buffer being
    /// written would leave key material predictable. Pre-fills with a
    /// sentinel and checks the tail was overwritten.
    #[test]
    fn fills_the_entire_buffer() {
        const SENTINEL: u8 = 0xAA;
        let mut buf = [SENTINEL; 256];
        generate_random_bytes(&mut buf);
        assert!(
            buf[128..].iter().any(|&b| b != SENTINEL),
            "tail of the buffer was never written"
        );
    }

    #[test]
    fn empty_buffer_is_a_noop() {
        let mut buf: [u8; 0] = [];
        generate_random_bytes(&mut buf);
    }
}
