# Contributing to Gitveil

Thanks for your interest in contributing to gitveil! This document covers what you need to know to get started.

## Getting Started

### Prerequisites

- **Rust** (stable, 1.70+): install via [rustup](https://rustup.rs/)
- **Git** (2.20+)
- **GPG** (optional, only needed for GPG-related features)

### Building

```bash
git clone <this-repo>
cd git-crypt-rust
cargo build
```

### Running Tests

```bash
cargo test
```

All 24 unit tests should pass. They cover:
- AES-256-CTR encryption/decryption round-trips
- HMAC-SHA1 known-answer vectors
- Key file TLV serialization/deserialization
- Clean/smudge filter round-trips
- Non-encrypted passthrough behavior

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
  commands/     User-facing commands (init, lock, unlock, etc.)
  git/          Git repository helpers (config, checkout, repo inspection)
  gpg/          GPG integration (shells out to gpg)
  cli.rs        clap CLI definitions
  constants.rs  Shared constants (magic bytes, sizes, field IDs)
  error.rs      Error types
  main.rs       Entry point
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

- Library modules (`crypto/`, `key/`, `filter/`) use `GitVeilError` from `error.rs`
- Command handlers use `anyhow::Result` is available but currently we propagate `GitVeilError` directly
- User-facing error messages should be clear and actionable

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

## What to Work On

Here are areas where contributions would be especially welcome:

### Good First Issues

- Add `--version` info to the `init` output message
- Improve error messages (e.g., suggest running `gitveil init` when the repo isn't initialized)
- Add `--quiet` / `--verbose` flags

### Medium

- Integration tests using temporary git repos (`tempfile` crate)
- Support for the legacy key format (pre-FORMAT_VERSION 2)
- `gitveil refresh` command to update filter configuration
- Shell completions (clap supports generating them)

### Larger

- Cross-compatibility test suite (encrypt with git-crypt, decrypt with gitveil, and vice versa)
- `gitveil ls-gpg-users` and `gitveil rm-gpg-user` commands
- Windows support (path separator handling, GPG path detection)
- CI/CD pipeline with automated testing

## Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b my-feature`)
3. Make your changes
4. Run `cargo fmt && cargo clippy && cargo test`
5. Commit with a clear message
6. Open a pull request

## Questions?

Open an issue if something is unclear or you need guidance on an approach.
