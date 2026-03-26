use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "gitveil",
    about = "Transparent file encryption in git (git-crypt compatible)",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate a key and prepare the repository for encryption
    Init {
        /// Use a named key instead of the default
        #[arg(short = 'k', long = "key-name")]
        key_name: Option<String>,
    },

    /// Secure the repository by removing keys and re-encrypting files
    Lock {
        /// Lock a specific named key
        #[arg(short = 'k', long = "key-name")]
        key_name: Option<String>,

        /// Lock all keys
        #[arg(short = 'a', long)]
        all: bool,

        /// Force lock even with uncommitted changes
        #[arg(short = 'f', long)]
        force: bool,
    },

    /// Decrypt the repository using a symmetric key file or GPG
    Unlock {
        /// Symmetric key file(s) to unlock with
        #[arg()]
        key_files: Vec<PathBuf>,
    },

    /// Add a GPG user as a collaborator
    #[command(name = "add-gpg-user")]
    AddGpgUser {
        /// Use a specific named key
        #[arg(short = 'k', long = "key-name")]
        key_name: Option<String>,

        /// Don't automatically commit the GPG-encrypted key
        #[arg(short = 'n', long = "no-commit")]
        no_commit: bool,

        /// Trust the GPG key without verification
        #[arg(long)]
        trusted: bool,

        /// GPG user ID (email, key ID, or fingerprint)
        #[arg()]
        gpg_user_id: String,
    },

    /// Export the symmetric key to a file
    #[command(name = "export-key")]
    ExportKey {
        /// Export a specific named key
        #[arg(short = 'k', long = "key-name")]
        key_name: Option<String>,

        /// Output file (omit for stdout)
        #[arg()]
        output_file: Option<PathBuf>,
    },

    /// Display the encryption status of tracked files
    Status {
        /// Show only encrypted files
        #[arg(short = 'e')]
        encrypted_only: bool,

        /// Show only unencrypted files
        #[arg(short = 'u')]
        unencrypted_only: bool,

        /// Re-encrypt files that should be encrypted but aren't
        #[arg(short = 'f', long)]
        fix: bool,
    },

    // -- Plumbing commands (invoked by git, not the user) --

    /// [plumbing] Encrypt stdin (clean filter)
    #[command(hide = true)]
    Clean {
        /// Key name
        #[arg()]
        key_name: Option<String>,
    },

    /// [plumbing] Decrypt stdin (smudge filter)
    #[command(hide = true)]
    Smudge {
        /// Key name
        #[arg()]
        key_name: Option<String>,
    },

    /// [plumbing] Decrypt a file for diff (textconv)
    #[command(hide = true)]
    Diff {
        /// Key name
        #[arg()]
        key_name: Option<String>,

        /// File path to decrypt
        #[arg()]
        file: Option<PathBuf>,
    },
}
