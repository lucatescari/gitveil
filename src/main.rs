mod cli;
mod commands;
mod constants;
mod crypto;
mod error;
mod filter;
mod git;
mod gpg;
mod key;

use std::io;
use std::path::PathBuf;
use std::process;

use clap::Parser;
use colored::Colorize;

use cli::{Cli, Commands};
use constants::DEFAULT_KEY_NAME;
use git::repo::{find_git_dir, key_path};
use key::key_file::KeyFile;

fn main() {
    let cli = Cli::parse();
    let quiet = cli.quiet;

    let result = match cli.command {
        Commands::Init { key_name } => commands::init::init(key_name.as_deref(), quiet),

        Commands::Lock {
            key_name,
            all,
            force,
        } => commands::lock::lock(key_name.as_deref(), all, force, quiet),

        Commands::Unlock { key_files } => commands::unlock::unlock(&key_files, quiet),

        Commands::AddGpgUser {
            key_name,
            no_commit,
            trusted,
            from,
            gpg_user_id,
        } => commands::add_gpg_user::add_gpg_user(
            key_name.as_deref(),
            no_commit,
            trusted,
            gpg_user_id.as_deref(),
            from.as_deref(),
        ),

        Commands::ExportKey {
            key_name,
            output_file,
        } => commands::export_key::export_key(key_name.as_deref(), output_file.as_ref(), quiet),

        Commands::Status {
            encrypted_only,
            unencrypted_only,
            fix,
        } => commands::status::status(encrypted_only, unencrypted_only, fix),

        Commands::Clean { key_name } => run_clean(key_name.as_deref()),

        Commands::Smudge { key_name } => run_smudge(key_name.as_deref()),

        Commands::Diff { key_name, file } => run_diff(key_name.as_deref(), file),
    };

    if let Err(e) = result {
        eprintln!("{} {}", "error:".red().bold(), e);
        process::exit(1);
    }
}

fn load_key_file(key_name: &str) -> Result<KeyFile, error::GitVeilError> {
    let git_dir = find_git_dir()?;
    let kp = key_path(&git_dir, key_name);

    if !kp.exists() {
        return Err(error::GitVeilError::NotInitialized);
    }

    KeyFile::load_from_file(&kp)
}

fn run_clean(key_name: Option<&str>) -> Result<(), error::GitVeilError> {
    let key_name = key_name.unwrap_or(DEFAULT_KEY_NAME);
    let kf = load_key_file(key_name)?;

    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    filter::clean::clean(&mut stdin, &mut stdout, &kf)
}

fn run_smudge(key_name: Option<&str>) -> Result<(), error::GitVeilError> {
    let key_name = key_name.unwrap_or(DEFAULT_KEY_NAME);
    let kf = load_key_file(key_name)?;

    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    filter::smudge::smudge(&mut stdin, &mut stdout, &kf)
}

fn run_diff(key_name: Option<&str>, file: Option<PathBuf>) -> Result<(), error::GitVeilError> {
    let key_name = key_name.unwrap_or(DEFAULT_KEY_NAME);
    let kf = load_key_file(key_name)?;

    let file_path =
        file.ok_or_else(|| error::GitVeilError::Other("diff command requires a file path".into()))?;

    let mut stdout = io::stdout().lock();
    filter::diff::diff(&file_path, &mut stdout, &kf)
}
