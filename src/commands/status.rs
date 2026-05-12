use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::thread;

use colored::Colorize;

use crate::constants::{ENCRYPTED_FILE_HEADER, ENCRYPTED_FILE_HEADER_LEN};
use crate::error::GitVeilError;
use crate::git::repo::find_git_dir;

/// A file from `git ls-files` along with whether it is tracked.
struct FileEntry {
    path: String,
    tracked: bool,
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

    // Blob-check only tracked files that have a git-crypt filter. Untracked
    // files have no blob in the index (cat-file would return "missing"), and
    // non-filter files don't need the check.
    let tracked_filter_paths: Vec<String> = files
        .iter()
        .filter(|f| {
            f.tracked
                && filter_map
                    .get(&f.path)
                    .map(|v| has_git_crypt_filter(v))
                    .unwrap_or(false)
        })
        .map(|f| f.path.clone())
        .collect();

    let blob_encrypted = if tracked_filter_paths.is_empty() {
        Vec::new()
    } else {
        batch_check_blobs_encrypted(&tracked_filter_paths)?
    };

    let blob_status: HashMap<&str, bool> = tracked_filter_paths
        .iter()
        .map(|s| s.as_str())
        .zip(blob_encrypted.iter().copied())
        .collect();

    // Display selectors. WARNING files are always collected (used by -f
    // and the summary) even when not printed, so `-e -f` still re-stages
    // them — the suppression applies to *display only*.
    let show_warning_lines = !encrypted_only;
    let show_encrypted_lines = !unencrypted_only;
    let show_non_filter_lines = all && !encrypted_only && !unencrypted_only;

    let mut warning_files: Vec<String> = Vec::new();

    for file in &files {
        let has_filter = filter_map
            .get(&file.path)
            .map(|v| has_git_crypt_filter(v))
            .unwrap_or(false);

        if has_filter {
            // Untracked files have no blob, so they never produce a
            // WARNING — only the staged/committed blob can be plaintext.
            let plain_blob =
                file.tracked && !blob_status.get(file.path.as_str()).copied().unwrap_or(true);

            if plain_blob {
                warning_files.push(file.path.clone());
                if show_warning_lines {
                    println!(
                        "    {} {} {}",
                        "encrypted:".green(),
                        file.path,
                        "*** WARNING: staged/committed version is NOT ENCRYPTED! ***"
                            .red()
                            .bold(),
                    );
                }
            } else if show_encrypted_lines {
                if file.tracked {
                    println!("    {} {}", "encrypted:".green(), file.path);
                } else {
                    // Untracked filter file: there's no blob yet, so the
                    // file on disk is still plaintext. The "(untracked)"
                    // suffix makes it clear that the encrypted state is
                    // prospective — it'll happen on staging.
                    println!(
                        "    {} {} {}",
                        "encrypted:".green(),
                        file.path,
                        "(untracked)".dimmed(),
                    );
                }
            }
        } else if show_non_filter_lines {
            println!("not encrypted: {}", file.path);
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
                // A warning file may have been deleted from the working tree
                // (still tracked, plaintext blob, no longer on disk). In that
                // case `git add` would stage the *deletion* — the opposite of
                // re-encrypting. Skip such files with a clear diagnostic.
                if !std::path::Path::new(file).exists() {
                    eprintln!(
                        "{} skipping {}: file no longer exists in the working \
                         tree (use `git rm` to remove, or restore the file to \
                         re-encrypt it)",
                        "warning:".yellow().bold(),
                        file,
                    );
                    continue;
                }
                let st = Command::new("git")
                    .args(["add", "--"])
                    .arg(file)
                    .status()
                    .map_err(|e| GitVeilError::Git(format!("failed to stage {}: {}", file, e)))?;
                if !st.success() {
                    eprintln!("{} failed to stage {}", "warning:".yellow().bold(), file);
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

/// True when the file's filter attribute is a gitveil/git-crypt filter.
/// Recognizes both the default `git-crypt` and named-key `git-crypt-<name>`.
fn has_git_crypt_filter(value: &str) -> bool {
    value.starts_with("git-crypt")
}

/// List tracked + untracked files (excluding gitignored), ordered to match
/// git-crypt: untracked first, then tracked, each alphabetical.
fn list_all_files() -> Result<Vec<FileEntry>, GitVeilError> {
    let untracked = ls_files_nul(&["ls-files", "-z", "--others", "--exclude-standard"])?;
    let tracked = ls_files_nul(&["ls-files", "-z"])?;

    let mut result: Vec<FileEntry> = untracked
        .into_iter()
        .map(|path| FileEntry {
            path,
            tracked: false,
        })
        .collect();
    result.extend(tracked.into_iter().map(|path| FileEntry {
        path,
        tracked: true,
    }));
    Ok(result)
}

/// Run a `git ls-files` variant with `-z` and parse its NUL-delimited output.
/// Using NUL is essential for filenames containing whitespace or other
/// special characters.
fn ls_files_nul(args: &[&str]) -> Result<Vec<String>, GitVeilError> {
    let out = Command::new("git")
        .args(args)
        .output()
        .map_err(|e| GitVeilError::Git(format!("failed to run git {:?}: {}", args, e)))?;

    if !out.status.success() {
        return Err(GitVeilError::Git(format!("git {:?} failed", args)));
    }

    let mut files = Vec::new();
    for chunk in out.stdout.split(|&b| b == 0) {
        if chunk.is_empty() {
            continue;
        }
        files.push(String::from_utf8_lossy(chunk).into_owned());
    }
    Ok(files)
}

/// Batch-resolve the `filter` attribute for every file. Returns a map from
/// path → filter value when the value is not the literal `unspecified`.
fn batch_check_filters(files: &[FileEntry]) -> Result<HashMap<String, String>, GitVeilError> {
    let mut child = Command::new("git")
        .args(["check-attr", "-z", "filter", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| GitVeilError::Git(format!("failed to run git check-attr: {}", e)))?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| GitVeilError::Git("failed to open check-attr stdin".into()))?;

    // Writer thread prevents pipe deadlock when the number of files exceeds
    // the OS pipe buffer (~64 KB on Linux, smaller on Windows).
    let paths: Vec<String> = files.iter().map(|f| f.path.clone()).collect();
    let writer = thread::spawn(move || {
        let mut stdin = stdin;
        for path in &paths {
            if write!(stdin, "{}\0", path).is_err() {
                break;
            }
        }
    });

    let out = child
        .wait_with_output()
        .map_err(|e| GitVeilError::Git(format!("failed to wait for git check-attr: {}", e)))?;

    let _ = writer.join();

    if !out.status.success() {
        return Err(GitVeilError::Git("git check-attr -z --stdin failed".into()));
    }

    // NUL-delimited triplets: path\0attr\0value\0
    let fields: Vec<&[u8]> = out.stdout.split(|&b| b == 0).collect();
    let mut map = HashMap::new();
    let mut i = 0;
    while i + 2 < fields.len() {
        let path = String::from_utf8_lossy(fields[i]).into_owned();
        let value = String::from_utf8_lossy(fields[i + 2]).into_owned();
        if value != "unspecified" && value != "unset" && !value.is_empty() {
            map.insert(path, value);
        }
        i += 3;
    }
    Ok(map)
}

/// Batch-check whether blobs in the index are encrypted using a single
/// `git cat-file --batch` subprocess instead of spawning one per file.
///
/// The cat-file batch protocol:
///   Input:  `:<path>\n` (index entry for path)
///   Output: `<sha> blob <size>\n<content>\n`  — or `:<path> missing\n`
///
/// We only need the first 10 bytes of each blob to check for the
/// `\0GITCRYPT\0` header. Remaining blob bytes are drained to `io::sink()`
/// so large files don't consume memory.
fn batch_check_blobs_encrypted(files: &[String]) -> Result<Vec<bool>, GitVeilError> {
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
    let queries: Vec<String> = files.iter().map(|f| format!(":{}", f)).collect();
    let writer_thread = thread::spawn(move || {
        let mut stdin = stdin;
        for query in &queries {
            if writeln!(stdin, "{}", query).is_err() {
                break;
            }
        }
    });

    let mut reader = BufReader::new(stdout);
    let mut results = Vec::with_capacity(files.len());

    for _ in files {
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

    #[test]
    fn has_git_crypt_filter_recognizes_default_and_named() {
        assert!(has_git_crypt_filter("git-crypt"));
        assert!(has_git_crypt_filter("git-crypt-backend"));
        assert!(has_git_crypt_filter("git-crypt-team-xyz"));
        assert!(!has_git_crypt_filter("unspecified"));
        assert!(!has_git_crypt_filter("lfs"));
        assert!(!has_git_crypt_filter(""));
    }
}
