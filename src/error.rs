#[derive(Debug, thiserror::Error)]
pub enum GitVeilError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid key file: {0}")]
    InvalidKeyFile(String),

    #[error("Incompatible key file field: field_id={0}")]
    IncompatibleField(u32),

    #[error("GPG error: {0}")]
    Gpg(String),

    #[error("Git error: {0}")]
    Git(String),

    #[error("Not a git repository. Run this command inside a git repo.")]
    NotAGitRepo,

    #[error("Already initialized for key '{0}'")]
    AlreadyInitialized(String),

    #[error("Not initialized. Run 'gitveil init' first.")]
    NotInitialized,

    #[error("Working directory is dirty; use --force to override")]
    DirtyWorkingDir,

    #[error("Invalid key name: {0}")]
    InvalidKeyName(String),

    #[error("Encrypted file has invalid header")]
    InvalidEncryptedHeader,

    /// The HMAC of the decrypted plaintext does not match the nonce stored in
    /// the file header: the ciphertext was modified, or the wrong key is in use.
    #[error(
        "encrypted file has been tampered with, or was encrypted with a different key \
         (HMAC mismatch); refusing to output it"
    )]
    TamperedFile,

    #[error("input is larger than the {0}-byte limit")]
    InputTooLarge(u64),

    #[error("No key entries found")]
    NoKeyEntries,

    #[error("{0}")]
    Other(String),
}
