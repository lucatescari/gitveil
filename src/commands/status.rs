use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;

use colored::Colorize;

use crate::constants::{ENCRYPTED_FILE_HEADER, ENCRYPTED_FILE_HEADER_LEN};
use crate::error::GitVeilError;
use crate::git::repo::{batch_check_filter_attr, find_git_dir, git_nul_list};
use crate::gpg::display::sanitize_for_display;

/// A file from `git ls-files`, relative to the current directory (like
/// git-crypt's status).
struct FileEntry {
    /// Raw path bytes exactly as git reported them (NUL-delimited output).
    raw: Vec<u8>,
    /// Lossy UTF-8 form of `raw`, for display (after sanitizing).
    path: String,
    /// Index object ids for a tracked file (several while a merge conflict
    /// leaves more than one stage). Empty for an untracked file.
    oids: Vec<String>,
}

impl FileEntry {
    fn tracked(&self) -> bool {
        !self.oids.is_empty()
    }

    /// The path made safe to print: filenames are repository content, and
    /// control characters (ESC, CR, LF, ...) must not reach the terminal.
    fn display(&self) -> String {
        sanitize_for_display(&self.path)
    }

    fn os_path(&self) -> OsString {
        raw_to_os(&self.raw)
    }
}

/// Convert raw path bytes from git to an OS path, losslessly on Unix.
fn raw_to_os(raw: &[u8]) -> OsString {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        OsStr::from_bytes(raw).to_os_string()
    }
    #[cfg(not(unix))]
    {
        // Git for Windows emits UTF-8 paths.
        OsString::from(String::from_utf8_lossy(raw).into_owned())
    }
}

/// Display the encryption status of files in the repository.
///
/// By default the output is focused on files governed by a git-crypt
/// filter — for a large repo this is the actionable subset. A WARNING
/// suffix is appended when a filter-marked tracked file's index blob is
/// plaintext (typically staged before `.gitattributes` was in effect),
/// and a summary points at `-f`. Pass `--all` to also list files without
/// the filter (git-crypt-style verbose output).
///
/// Flags:
///   - `-e`: only files whose blob is encrypted
///   - `-u`: only files marked for encryption whose blob is plaintext
///     (the WARNING set — pair with `-f` to re-stage them)
///   - `-a`/`--all`: include files without the git-crypt filter too
///   - `-f`: re-stage WARNING files so the clean filter encrypts them
///
/// Performance: at most one `git ls-files` per category (tracked/untracked),
/// one batched `git check-attr -z --stdin`, and one batched `git cat-file
/// --batch` regardless of repo size.
pub fn status(
    encrypted_only: bool,
    unencrypted_only: bool,
    all: bool,
    fix: bool,
) -> Result<(), GitVeilError> {
    // Validate up-front that we're inside a git work tree. Without this the
    // failure mode is a confusing "git ls-files failed" message instead of
    // the clean NotAGitRepo error.
    find_git_dir()?;

    let files = list_all_files()?;
    if files.is_empty() {
        return Ok(());
    }

    // Map every file (tracked or not) to its filter value, if any.
    let filter_map = batch_check_filters(&files)?;
    let has_filter = |f: &FileEntry| {
        filter_map
            .get(&f.raw)
            .map(|v| has_git_crypt_filter(v))
            .unwrap_or(false)
    };

    // Blob-check only tracked files that have a git-crypt filter. Untracked
    // files have no blob in the index, and non-filter files don't need the
    // check. Blobs are looked up by object id from `ls-files -s`, never by
    // path: that keeps the newline-delimited cat-file protocol safe for any
    // filename and independent of the current directory.
    let oids: Vec<String> = files
        .iter()
        .filter(|f| has_filter(f))
        .flat_map(|f| f.oids.iter().cloned())
        .collect();

    let blob_encrypted: HashMap<String, bool> = if oids.is_empty() {
        HashMap::new()
    } else {
        let results = batch_check_blobs_encrypted(&oids)?;
        oids.into_iter().zip(results).collect()
    };

    // Display selectors. WARNING files are always collected (used by -f
    // and the summary) even when not printed, so `-e -f` still re-stages
    // them — the suppression applies to *display only*.
    let show_warning_lines = !encrypted_only;
    let show_encrypted_lines = !unencrypted_only;
    let show_non_filter_lines = all && !encrypted_only && !unencrypted_only;

    let mut warning_files: Vec<&FileEntry> = Vec::new();

    for file in &files {
        if has_filter(file) {
            // Untracked files have no blob, so they never produce a
            // WARNING — only the staged/committed blob can be plaintext.
            // Every stage must be encrypted; an unknown result counts as
            // plaintext so a parse problem can never hide a leak.
            let plain_blob = file
                .oids
                .iter()
                .any(|oid| !blob_encrypted.get(oid).copied().unwrap_or(false));

            if plain_blob {
                warning_files.push(file);
                if show_warning_lines {
                    println!(
                        "    {} {} {}",
                        "encrypted:".green(),
                        file.display(),
                        "*** WARNING: staged/committed version is NOT ENCRYPTED! ***"
                            .red()
                            .bold(),
                    );
                }
            } else if show_encrypted_lines {
                if file.tracked() {
                    println!("    {} {}", "encrypted:".green(), file.display());
                } else {
                    // Untracked filter file: there's no blob yet, so the
                    // file on disk is still plaintext. The "(untracked)"
                    // suffix makes it clear that the encrypted state is
                    // prospective — it'll happen on staging.
                    println!(
                        "    {} {} {}",
                        "encrypted:".green(),
                        file.display(),
                        "(untracked)".dimmed(),
                    );
                }
            }
        } else if show_non_filter_lines {
            println!("not encrypted: {}", file.display());
        }
    }

    if !warning_files.is_empty() {
        eprintln!();
        eprintln!(
            "{} one or more files is marked for encryption via .gitattributes",
            "Warning:".yellow().bold(),
        );
        eprintln!("but was staged and/or committed before the .gitattributes file");
        eprintln!("was in effect.");
        if !fix {
            eprintln!(
                "Run '{}' to stage an encrypted version.",
                "gitveil status -f".bold(),
            );
        }

        if fix {
            eprintln!();
            eprintln!(
                "{} {} file(s)...",
                "Fixing".cyan().bold(),
                warning_files.len(),
            );
            let mut fixed = 0usize;
            for file in &warning_files {
                let os_path = file.os_path();
                // A warning file may have been deleted from the working tree
                // (still tracked, plaintext blob, no longer on disk). In that
                // case `git add` would stage the *deletion* — the opposite of
                // re-encrypting. Skip such files with a clear diagnostic.
                if !Path::new(&os_path).exists() {
                    eprintln!(
                        "{} skipping {}: file no longer exists in the working \
                         tree (use `git rm` to remove, or restore the file to \
                         re-encrypt it)",
                        "warning:".yellow().bold(),
                        file.display(),
                    );
                    continue;
                }
                let st = build_restage_command(&os_path).status().map_err(|e| {
                    GitVeilError::Git(format!("failed to stage {}: {}", file.display(), e))
                })?;
                if !st.success() {
                    eprintln!(
                        "{} failed to stage {}",
                        "warning:".yellow().bold(),
                        file.display()
                    );
                    continue;
                }
                fixed += 1;
            }
            eprintln!(
                "{} re-staged {} of {} file(s). Run '{}' to save the \
                 re-encrypted blobs.",
                "Done.".green().bold(),
                fixed,
                warning_files.len(),
                "git commit".bold(),
            );
        }
    }

    Ok(())
}

/// Build the `git add` invocation used by `status -f` to re-stage a file
/// whose committed blob is still plaintext.
///
/// `--renormalize` is required, not cosmetic. A plain `git add` consults the
/// stat cache first: the working file is byte-identical to what was
/// committed — only `.gitattributes` changed, which git cannot see from stat
/// data — so it concludes there is nothing to do, exits 0, and never invokes
/// the clean filter. The plaintext blob stays staged while `-f` reports
/// success, which is a false assurance about the very thing the command
/// exists to fix. It surfaced only intermittently because git re-hashes
/// "racily clean" files (mtime not strictly older than the index) as a
/// safeguard, masking it most of the time.
///
/// `--renormalize` re-applies the clean process to tracked files
/// unconditionally. It does not stage untracked files, so `-f` still refuses
/// to auto-add them.
///
/// `--literal-pathspecs` keeps a name such as `[ab].txt` from being treated
/// as a glob that could stage other files.
fn build_restage_command(file: impl AsRef<OsStr>) -> Command {
    let mut cmd = Command::new("git");
    cmd.args(["--literal-pathspecs", "add", "--renormalize", "--"])
        .arg(file);
    cmd
}

/// True when the file's filter attribute is a gitveil/git-crypt filter.
/// Recognizes both the default `git-crypt` and named-key `git-crypt-<name>`.
fn has_git_crypt_filter(value: &[u8]) -> bool {
    value.starts_with(b"git-crypt")
}

/// List tracked + untracked files (excluding gitignored), ordered to match
/// git-crypt: untracked first, then tracked, each alphabetical.
fn list_all_files() -> Result<Vec<FileEntry>, GitVeilError> {
    let untracked = git_nul_list(None, &["ls-files", "-z", "--others", "--exclude-standard"])?;
    let staged = git_nul_list(None, &["ls-files", "-z", "--stage"])?;

    let mut result: Vec<FileEntry> = untracked
        .into_iter()
        .map(|raw| FileEntry {
            path: String::from_utf8_lossy(&raw).into_owned(),
            raw,
            oids: Vec::new(),
        })
        .collect();

    // `--stage` entries are `<mode> <oid> <stage>\t<path>`, sorted by path,
    // with one entry per stage for unmerged paths.
    for entry in staged {
        let (oid, raw) = parse_stage_entry(&entry).ok_or_else(|| {
            GitVeilError::Git(format!(
                "unexpected git ls-files --stage entry: {}",
                String::from_utf8_lossy(&entry).escape_default()
            ))
        })?;
        match result.last_mut() {
            Some(last) if last.tracked() && last.raw == raw => last.oids.push(oid),
            _ => result.push(FileEntry {
                path: String::from_utf8_lossy(&raw).into_owned(),
                raw,
                oids: vec![oid],
            }),
        }
    }
    Ok(result)
}

/// Parse one NUL-terminated `git ls-files --stage` record into
/// `(object id, path bytes)`.
fn parse_stage_entry(entry: &[u8]) -> Option<(String, Vec<u8>)> {
    let tab = entry.iter().position(|&b| b == b'\t')?;
    let (meta, path) = (&entry[..tab], &entry[tab + 1..]);
    let meta = std::str::from_utf8(meta).ok()?;
    let mut parts = meta.split(' ');
    let _mode = parts.next()?;
    let oid = parts.next()?;
    let _stage = parts.next()?;
    if oid.is_empty() || !oid.bytes().all(|b| b.is_ascii_hexdigit()) || path.is_empty() {
        return None;
    }
    Some((oid.to_string(), path.to_vec()))
}

/// Batch-resolve the `filter` attribute for every file. Returns a map from
/// raw path → filter value when the value is set to something meaningful.
fn batch_check_filters(files: &[FileEntry]) -> Result<HashMap<Vec<u8>, Vec<u8>>, GitVeilError> {
    let paths: Vec<Vec<u8>> = files.iter().map(|f| f.raw.clone()).collect();
    let attrs = batch_check_filter_attr(None, paths)?;
    Ok(attrs
        .into_iter()
        .filter(|(_, v)| {
            v.as_slice() != b"unspecified" && v.as_slice() != b"unset" && !v.is_empty()
        })
        .collect())
}

/// Batch-check whether blobs are encrypted using a single
/// `git cat-file --batch` subprocess instead of spawning one per file.
///
/// The cat-file batch protocol:
///   Input:  `<oid>\n`
///   Output: `<oid> blob <size>\n<content>\n`  — or `<oid> missing\n`
///
/// Queries are object ids, which never contain newlines, so a filename
/// with a newline cannot desynchronize the protocol.
///
/// We only need the first 10 bytes of each blob to check for the
/// `\0GITCRYPT\0` header. Remaining blob bytes are drained to `io::sink()`
/// so large files don't consume memory.
fn batch_check_blobs_encrypted(oids: &[String]) -> Result<Vec<bool>, GitVeilError> {
    let mut child = Command::new("git")
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| GitVeilError::Git(format!("failed to run git cat-file --batch: {}", e)))?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| GitVeilError::Git("failed to open cat-file stdin".into()))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| GitVeilError::Git("failed to open cat-file stdout".into()))?;

    // Writer thread prevents pipe deadlock: with large blobs, reading must
    // proceed concurrently with writing.
    let queries: Vec<String> = oids.to_vec();
    let writer_thread = thread::spawn(move || {
        let mut stdin = stdin;
        for query in &queries {
            if writeln!(stdin, "{}", query).is_err() {
                break;
            }
        }
    });

    let mut reader = BufReader::new(stdout);
    let mut results = Vec::with_capacity(oids.len());

    for _ in oids {
        let mut header_line = String::new();
        reader
            .read_line(&mut header_line)
            .map_err(|e| GitVeilError::Git(format!("failed to read cat-file header: {}", e)))?;

        let header_line = header_line.trim_end_matches('\n');

        if header_line.ends_with(" missing") {
            results.push(false);
            continue;
        }

        let size: usize = header_line
            .rsplit_once(' ')
            .and_then(|(_, s)| s.parse().ok())
            .ok_or_else(|| {
                GitVeilError::Git(format!("unexpected cat-file header: {}", header_line))
            })?;

        if size < ENCRYPTED_FILE_HEADER_LEN {
            drain_bytes(&mut reader, size + 1)?;
            results.push(false);
            continue;
        }

        let mut header_buf = [0u8; ENCRYPTED_FILE_HEADER_LEN];
        reader
            .read_exact(&mut header_buf)
            .map_err(|e| GitVeilError::Git(format!("failed to read blob header: {}", e)))?;

        let is_encrypted = header_buf == ENCRYPTED_FILE_HEADER;

        let remaining = size - ENCRYPTED_FILE_HEADER_LEN + 1;
        drain_bytes(&mut reader, remaining)?;

        results.push(is_encrypted);
    }

    let _ = writer_thread.join();
    let _ = child.wait();

    Ok(results)
}

fn drain_bytes(reader: &mut impl Read, count: usize) -> Result<(), GitVeilError> {
    std::io::copy(&mut reader.take(count as u64), &mut std::io::sink())
        .map_err(|e| GitVeilError::Git(format!("failed to drain cat-file output: {}", e)))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: `-f` must re-apply the clean filter unconditionally.
    /// Without `--renormalize`, git's stat cache makes `git add` a silent
    /// no-op when only `.gitattributes` changed, leaving the plaintext blob
    /// staged while `-f` reports success. Confirmed on Windows CI, where it
    /// reproduced once in 20 runs.
    #[test]
    fn restage_command_uses_renormalize() {
        let cmd = build_restage_command("secret.txt");
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert!(
            args.iter().any(|a| a == "--renormalize"),
            "re-staging must use --renormalize or the clean filter is skipped \
             when only .gitattributes changed. Args: {args:?}",
        );
        assert!(
            args.iter().any(|a| a == "secret.txt"),
            "re-staging must name the file. Args: {args:?}",
        );
        assert!(
            args.iter().any(|a| a == "--literal-pathspecs"),
            "re-staging must not interpret the name as a glob. Args: {args:?}",
        );
    }

    #[test]
    fn has_git_crypt_filter_recognizes_default_and_named() {
        assert!(has_git_crypt_filter(b"git-crypt"));
        assert!(has_git_crypt_filter(b"git-crypt-backend"));
        assert!(has_git_crypt_filter(b"git-crypt-team-xyz"));
        assert!(!has_git_crypt_filter(b"unspecified"));
        assert!(!has_git_crypt_filter(b"lfs"));
        assert!(!has_git_crypt_filter(b""));
    }

    #[test]
    fn parse_stage_entry_handles_special_names() {
        let oid = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391";
        let entry = format!("100644 {} 0\tnew\nline\t.txt", oid);
        let (got_oid, path) = parse_stage_entry(entry.as_bytes()).unwrap();
        assert_eq!(got_oid, oid);
        assert_eq!(path, b"new\nline\t.txt");

        assert!(parse_stage_entry(b"garbage").is_none());
        assert!(parse_stage_entry(b"100644 zz 0\tx").is_none());
    }

    #[test]
    fn display_sanitizes_control_characters() {
        let f = FileEntry {
            raw: b"\x1b[31mevil\n.txt".to_vec(),
            path: "\u{1b}[31mevil\n.txt".to_string(),
            oids: Vec::new(),
        };
        assert!(!f.display().chars().any(|c| c.is_control()));
    }
}
