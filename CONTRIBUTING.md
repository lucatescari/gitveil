# Contributing to Gitveil

Thanks for your interest in contributing to gitveil! This document covers what you need to know to get started.

## Getting Started

### Prerequisites

- **Rust** (stable, 1.70+): install via [rustup](https://rustup.rs/)
- **Git** (2.20+)
- **GPG** (optional, only needed for GPG-related features)

### Building

```bash
git clone https://github.com/lucatescari/gitveil.git
cd gitveil
cargo build
```

### Running Tests

```bash
cargo test
```

All 43 tests should pass (27 unit + 16 integration). They cover:
- AES-256-CTR encryption/decryption round-trips
- HMAC-SHA1 known-answer vectors
- Key file TLV serialization/deserialization
- Clean/smudge/diff filter round-trips
- Non-encrypted passthrough behavior
- Key name validation
- Full E2E: init → encrypt → lock → unlock (integration)
- Status, export-key, quiet mode, error messages (integration)
- Edge cases: empty files, binary files, multi-key lock (integration)

### Running Manually

```bash
cargo run -- <command> [args]

# Examples:
cargo run -- --help
cargo run -- init
cargo run -- status
```

## Project Layout

```
src/
  crypto/       Core cryptography (AES-CTR, HMAC-SHA1, random)
  key/          Key file format (TLV serialization, entries, key container)
  filter/       Git clean/smudge/diff filters
  commands/     User-facing commands (init, lock, unlock, status, etc.)
  git/          Git repository helpers (config, checkout, repo inspection)
  gpg/          GPG integration (key import, encrypt/decrypt via gpg CLI)
  cli.rs        clap CLI definitions
  constants.rs  Shared constants (magic bytes, sizes, field IDs)
  error.rs      Error types
  main.rs       Entry point
scripts/
  release.sh    Automated release + Homebrew formula update
```

## Development Guidelines

### Code Style

- Run `cargo fmt` before committing
- Run `cargo clippy` and fix any warnings
- Follow standard Rust naming conventions

### Compatibility

This is the most important constraint. Gitveil must remain **byte-compatible** with git-crypt:

- The key file format must match exactly (header magic, FORMAT_VERSION 2, TLV field IDs and sizes)
- The encrypted file format must match exactly (`\0GITCRYPT\0` header, 12-byte HMAC-SHA1 nonce, AES-256-CTR ciphertext)
- Git filter names must be `git-crypt` / `git-crypt-<keyname>` (not `gitveil`)

**If you change anything in `crypto/`, `key/`, or `filter/`, verify compatibility against a real git-crypt installation.** A file encrypted by gitveil must decrypt correctly with git-crypt, and vice versa.

### Error Handling

- All modules use `GitVeilError` from `error.rs` with `thiserror` derive
- User-facing error messages should be clear and actionable
- Errors are printed in red via `colored` in `main.rs`

### Security

- Key material (`aes_key`, `hmac_key`) must be zeroized on drop. The `KeyEntry` struct derives `ZeroizeOnDrop`.
- Never log or print key material, even in debug builds
- Use `rand::rngs::OsRng` for all random generation (not thread-local or seeded RNGs)

### Adding a New Command

1. Create `src/commands/your_command.rs`
2. Add it to `src/commands/mod.rs`
3. Add the CLI variant to `src/cli.rs` in the `Commands` enum
4. Wire it up in `src/main.rs`'s match block

### Adding Tests

- Unit tests go in `#[cfg(test)] mod tests` blocks within the relevant source file
- Integration tests that need a real git repo should go in a `tests/` directory
- For crypto tests, use known-answer vectors where possible

## Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b my-feature`)
3. Make your changes
4. Run `cargo fmt && cargo clippy && cargo test`
5. Commit with a clear message
6. Open a pull request

## Questions?

Open an issue if something is unclear or you need guidance on an approach.
