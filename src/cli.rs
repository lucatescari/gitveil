use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

#[derive(Parser)]
#[command(
    name = "gitveil",
    about = "Transparent file encryption in git (git-crypt compatible)",
    version
)]
pub struct Cli {
    /// Suppress all informational output
    #[arg(short, long, global = true)]
    pub quiet: bool,

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

        /// Import GPG key(s) from a file, directory, or git URL
        #[arg(long = "from")]
        from: Option<String>,

        /// GPG user ID (email, key ID, or fingerprint) — not required when using --from with a directory
        #[arg()]
        gpg_user_id: Option<String>,
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

    /// Remove a GPG user's access to the repository
    #[command(name = "rm-gpg-user")]
    RmGpgUser {
        /// Use a specific named key
        #[arg(short = 'k', long = "key-name")]
        key_name: Option<String>,

        /// Don't automatically commit the removal
        #[arg(short = 'n', long = "no-commit")]
        no_commit: bool,

        /// GPG user ID (email, key ID, or fingerprint) to remove
        #[arg()]
        gpg_user_id: String,
    },

    /// List GPG users who have access to the repository
    #[command(name = "ls-gpg-users")]
    LsGpgUsers {
        /// List users for a specific named key only
        #[arg(short = 'k', long = "key-name")]
        key_name: Option<String>,
    },

    /// Manage global gitveil configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Generate shell completions for bash, zsh, or fish
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
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

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Set the global GPG keyring directory
    #[command(name = "set-keyring")]
    SetKeyring {
        /// Path to a directory containing GPG public key files
        #[arg()]
        path: PathBuf,
    },

    /// Remove the global keyring directory setting
    #[command(name = "unset-keyring")]
    UnsetKeyring,

    /// Show current configuration
    Show,
}

/// Generate shell completions and write to stdout.
pub fn print_completions(shell: Shell) {
    clap_complete::generate(
        shell,
        &mut Cli::command(),
        "gitveil",
        &mut std::io::stdout(),
    );
}
