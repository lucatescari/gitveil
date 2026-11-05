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

    /// Display the encryption status of files in the repository
    Status {
        /// Show only files whose blob is encrypted
        #[arg(short = 'e')]
        encrypted_only: bool,

        /// Show only files marked for encryption whose blob is plaintext
        /// (the set needing re-encryption — pair with -f to fix)
        #[arg(short = 'u')]
        unencrypted_only: bool,

        /// Show every file, including files without the git-crypt filter
        /// (verbose git-crypt-style listing)
        #[arg(short = 'a', long = "all")]
        all: bool,

        /// Re-stage files that should be encrypted but aren't
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
    ///
    /// Invoked by git as `gitveil diff [KEY_NAME] FILE`. With a single
    /// argument it is the file and the default key is used.
    #[command(hide = true)]
    Diff {
        /// Key name (or the file, when only one argument is given)
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

impl Commands {
    /// The `-k/--key-name` value of commands that take one.
    pub fn key_name(&self) -> Option<&str> {
        match self {
            Commands::Init { key_name }
            | Commands::Lock { key_name, .. }
            | Commands::AddGpgUser { key_name, .. }
            | Commands::ExportKey { key_name, .. }
            | Commands::RmGpgUser { key_name, .. }
            | Commands::LsGpgUsers { key_name }
            | Commands::Clean { key_name }
            | Commands::Smudge { key_name }
            | Commands::Diff {
                key_name,
                file: Some(_),
            } => key_name.as_deref(),
            // `gitveil diff <FILE>`: git's textconv for the default key passes
            // only the file, which clap puts in the first positional slot.
            Commands::Diff { file: None, .. } => None,
            Commands::Unlock { .. }
            | Commands::Status { .. }
            | Commands::Config { .. }
            | Commands::Completions { .. } => None,
        }
    }
}
