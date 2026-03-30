# Project Instructions

## Documentation

When adding features, changing CLI flags, modifying commands, or altering behavior:
- Update README.md if user-facing commands, flags, or usage changed
- Update CONTRIBUTING.md if project structure, test count, build steps, or development guidelines changed
- Keep the test count in CONTRIBUTING.md accurate after adding/removing tests

## Code Quality

- Run `cargo clippy` and fix warnings before committing
- Run `cargo test` and ensure all tests pass
- Run `cargo fmt` for consistent formatting

## Compatibility

This project must remain byte-compatible with git-crypt. Never change:
- Key file format (header magic, FORMAT_VERSION 2, TLV field IDs)
- Encrypted file format (`\0GITCRYPT\0` header, HMAC-SHA1 nonce, AES-256-CTR)
- Git filter names (`git-crypt` / `git-crypt-<keyname>`)

## Security

- Key material must be zeroized on drop (ZeroizeOnDrop)
- Never log or print key bytes
- Use OsRng for all randomness
- Validate all external input (fingerprints, key names, paths)
- Skip symlinks in directory traversal

## Branching

- Create feature branches from `dev` (always `git pull origin dev` first)
- Use descriptive branch names: `feat/`, `fix/`, `refactor/`, `docs/`
