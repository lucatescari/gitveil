# Gitveil

**Transparent file encryption in git** -- a Rust implementation compatible with [git-crypt](https://github.com/AGWA/git-crypt).

Gitveil lets you store sensitive files (API keys, credentials, private configs) alongside public code in a git repository. Files you mark for encryption are automatically encrypted when committed and decrypted when checked out. Everyone else uses git normally -- they just can't read the encrypted files without the key.

## How It Works

Gitveil hooks into git's [clean/smudge filter](https://git-scm.com/book/en/v2/Customizing-Git-Git-Attributes) mechanism:

- **On `git add`** (clean filter): plaintext is encrypted before being stored in the repository
- **On `git checkout`** (smudge filter): encrypted blobs are decrypted into your working copy
- **On `git diff`** (textconv): encrypted files are decrypted on the fly for readable diffs

This is completely transparent -- after setup, you just use git as usual.

## Compatibility

Gitveil is **byte-compatible** with git-crypt. Repositories encrypted with git-crypt can be unlocked with gitveil and vice versa. They use the same:

- Key file format (FORMAT_VERSION 2, TLV-encoded)
- Encrypted file format (`\0GITCRYPT\0` header + HMAC-SHA1 nonce + AES-256-CTR ciphertext)
- Git filter configuration (`filter=git-crypt`, `diff=git-crypt`)
- `.git-crypt/` directory structure for GPG-encrypted keys

## Cryptography

- **AES-256-CTR** for file encryption
- **HMAC-SHA1** to derive a deterministic nonce from the file contents (so identical plaintext produces identical ciphertext -- required for git to detect unchanged files)
- **32-byte AES key + 64-byte HMAC key** per key entry, generated from OS-level CSPRNG
- Key material is **zeroized on drop** via the `zeroize` crate

## Installation

### From source

```bash
git clone <this-repo>
cd git-crypt-rust
cargo build --release
```

The binary will be at `target/release/gitveil`. Copy it somewhere in your `$PATH`:

```bash
cp target/release/gitveil /usr/local/bin/
```

## Quick Start

### 1. Initialize a repository

```bash
cd my-repo
gitveil init
```

This generates a symmetric key (stored in `.git/git-crypt/keys/default`) and configures git's clean/smudge/diff filters.

### 2. Specify files to encrypt

Create or edit `.gitattributes` in your repo root:

```
# Encrypt all .key files
*.key filter=git-crypt diff=git-crypt

# Encrypt a specific file
secrets.env filter=git-crypt diff=git-crypt

# Encrypt everything in a directory
config/private/** filter=git-crypt diff=git-crypt
```

**Important:** Add `.gitattributes` *before* adding the files you want encrypted. If a file was already committed in plaintext, gitveil cannot retroactively encrypt its history.

### 3. Use git normally

```bash
echo "API_KEY=sk-secret-123" > secrets.env
git add secrets.env
git commit -m "add secrets"
```

The file is encrypted in the repository but appears as plaintext in your working copy.

### 4. Share access

**Option A: Symmetric key** (simpler, you handle secure transport)

```bash
gitveil export-key ~/gitveil-key
# Send the key file securely to your collaborator
```

Your collaborator then runs:

```bash
gitveil unlock ~/gitveil-key
```

**Option B: GPG** (key is encrypted to each user's GPG public key)

```bash
gitveil add-gpg-user collaborator@example.com
```

Your collaborator then runs:

```bash
gitveil unlock
```

GPG decrypts the symmetric key automatically using their private key.

### 5. Lock when done

```bash
gitveil lock
```

This removes the key from your machine and re-encrypts files in your working copy.

## Commands

### `gitveil init`

Generate a key and prepare the repository for encryption.

```
gitveil init [-k <key-name>]
```

| Option | Description |
|--------|-------------|
| `-k, --key-name` | Use a named key instead of `default` |

### `gitveil lock`

Remove the key and re-encrypt files in the working copy.

```
gitveil lock [-k <key-name>] [-a] [-f]
```

| Option | Description |
|--------|-------------|
| `-k, --key-name` | Lock a specific named key |
| `-a, --all` | Lock all keys |
| `-f, --force` | Force lock even with uncommitted changes |

### `gitveil unlock`

Decrypt the repository.

```
gitveil unlock [<key-file>...]
```

Without arguments, attempts GPG-based unlock using keys in `.git-crypt/`. With key file arguments, uses symmetric key files.

### `gitveil add-gpg-user`

Add a GPG user as a collaborator.

```
gitveil add-gpg-user [-k <key-name>] [-n] [--trusted] [--from <path>] [<GPG_USER_ID>]
```

| Option | Description |
|--------|-------------|
| `-k, --key-name` | Use a specific named key |
| `-n, --no-commit` | Don't auto-commit the GPG-encrypted key |
| `--trusted` | Skip GPG Web of Trust verification |
| `--from <path>` | Import GPG key(s) from a file or directory (see below) |

#### Import keys from a shared keyring

If your team stores GPG public keys in a shared repository, you can import them directly:

```bash
# Import a single key file
gitveil add-gpg-user --from /path/to/keys/alice.asc

# Browse a directory and pick interactively
gitveil add-gpg-user --from /path/to/keys/
```

When pointing at a directory, gitveil scans for `.asc`, `.gpg`, `.pub`, and `.key` files, shows a list of found keys (name, email, fingerprint), and lets you select one or more to add as collaborators.

### `gitveil export-key`

Export the symmetric key to a file.

```
gitveil export-key [-k <key-name>] [<output-file>]
```

Omit the output file to write to stdout.

### `gitveil status`

Show encryption status of tracked files.

```
gitveil status [-e] [-u] [-f]
```

| Option | Description |
|--------|-------------|
| `-e` | Show only encrypted files |
| `-u` | Show only unencrypted files |
| `-f, --fix` | Re-encrypt files that should be encrypted but aren't |

## Named Keys

Gitveil supports multiple named keys, allowing you to share different files with different groups of people:

```bash
# Initialize a named key
gitveil init -k team-backend

# Use it in .gitattributes
# db-credentials.env filter=git-crypt-team-backend diff=git-crypt-team-backend

# Share with specific people
gitveil add-gpg-user -k team-backend backend-dev@company.com

# Export the named key
gitveil export-key -k team-backend ~/backend-key
```

## Limitations

- **File contents only.** Gitveil cannot encrypt filenames, commit messages, branch names, or other git metadata.
- **No history rewriting.** If a file was committed in plaintext before adding the `filter=git-crypt` attribute, the plaintext remains in git history.
- **Encrypted files are opaque blobs.** Git cannot compute deltas on encrypted content, so storage efficiency is reduced for encrypted files.
- **No key rotation or revocation.** Removing a collaborator's GPG key does not re-encrypt with a new symmetric key. They still have the old key.

## Security Considerations

### No ciphertext integrity verification

AES-256-CTR provides confidentiality but not integrity. An attacker with push access to the repository can flip bits in the ciphertext, which flips the corresponding bits in the plaintext. The HMAC-SHA1 is used only for deterministic nonce derivation, not for authentication. There is no tamper detection on decryption. This is inherited from git-crypt's design -- adding MAC verification would break compatibility.

### Trust model for `gpg.program`

Gitveil respects the `gpg.program` git config setting, which means the GPG binary is determined by local repository config. An attacker who can modify `.git/config` (e.g., via a malicious clone) could point this to an arbitrary program. This is the same trust model as git itself -- local config is trusted. Be cautious when running gitveil in repositories you did not create.

### Large file memory usage

The clean filter must read the entire file into memory to compute the HMAC-SHA1 nonce before encryption can begin. Very large files (multi-GiB) may cause high memory usage.

## Project Structure

```
src/
  main.rs              # Entry point + CLI dispatch
  cli.rs               # clap CLI definitions
  constants.rs         # Magic bytes, sizes, field IDs
  error.rs             # Error types
  crypto/
    aes_ctr.rs          # AES-256-CTR encryption
    hmac.rs             # HMAC-SHA1 nonce derivation
    random.rs           # Secure random generation
  key/
    format.rs           # TLV field serialization
    entry.rs            # Key entry (version + AES key + HMAC key)
    key_file.rs         # Multi-version key file container
  filter/
    clean.rs            # Encrypt on git add
    smudge.rs           # Decrypt on git checkout
    diff.rs             # Decrypt for git diff
  commands/
    init.rs, lock.rs, unlock.rs, add_gpg_user.rs, export_key.rs, status.rs
  git/
    repo.rs             # Repository inspection
    config.rs           # Git filter configuration
    checkout.rs         # Force checkout for lock/unlock
  gpg/
    operations.rs       # GPG encrypt/decrypt via subprocess
```

## License

GPL-3.0
