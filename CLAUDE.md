# Project Instructions

## Documentation

When adding features, changing CLI flags, modifying commands, or altering behavior:
- Update README.md if user-facing commands, flags, or usage changed
- Update CONTRIBUTING.md if project structure, test count, build steps, or development guidelines changed
- Keep the test count in CONTRIBUTING.md accurate after adding/removing tests

## Testing Requirements

Every command, subcommand, and code path MUST have integration tests. This is non-negotiable for security-critical software.

- **Every CLI command** must have integration tests covering happy path AND error paths
- **Every flag/option** on every command must be tested
- **GPG-dependent commands** (add-gpg-user, rm-gpg-user, ls-gpg-users, unlock via GPG) must have tests that exercise real GPG operations using test keys in a temp GNUPGHOME
- **Tests must run on all 3 CI platforms** (Linux, macOS, Windows). Only use `#[cfg(unix)]` for genuinely Unix-only concepts (file mode bits, Unix symlinks)
- **When adding a new command or feature**: write tests BEFORE or WITH the implementation, never after. No PR should add a command without corresponding tests.
- **When modifying an existing command**: verify existing tests still cover the behavior, add new tests if the change adds flags or code paths
- **GPG tests** should auto-skip gracefully if GPG is not available (use a `skip_without_gpg!()` macro, same pattern as `skip_without_git_crypt!()` in cross_compat.rs)
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
