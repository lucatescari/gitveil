/// Make an untrusted string safe to print to a terminal.
///
/// GPG user IDs come from key files, which may be attacker-supplied — a
/// shared keyring repository passed to `add-gpg-user --from`, for instance.
/// Printed raw, a UID can emit terminal escape sequences that repaint the
/// screen, hide text, or forge the fingerprint displayed beside it. Control
/// characters (which include ESC, CR and LF) are replaced with `_`;
/// everything else, non-ASCII included, is left alone.
pub fn sanitize_for_display(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { '_' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A GPG user ID comes from a key file, which may be attacker-supplied
    /// (`add-gpg-user --from` a shared keyring repo). Printing it raw lets it
    /// emit terminal escape sequences — repainting the screen, hiding text,
    /// or forging the fingerprint shown next to it in the picker.
    #[test]
    fn strips_terminal_escape_sequences() {
        let sanitized = sanitize_for_display("\u{1b}[31mnot really Alice\u{1b}[0m");
        assert!(
            !sanitized.contains('\u{1b}'),
            "escape character survived: {sanitized:?}"
        );
    }

    #[test]
    fn strips_newlines_and_carriage_returns() {
        let sanitized = sanitize_for_display("Alice\nFingerprint: forged\rmore");
        assert!(!sanitized.contains('\n'), "newline survived: {sanitized:?}");
        assert!(
            !sanitized.contains('\r'),
            "carriage return survived: {sanitized:?}"
        );
    }

    #[test]
    fn leaves_ordinary_user_ids_untouched() {
        let uid = "Alice Mueller (work) <alice@company.example>";
        assert_eq!(sanitize_for_display(uid), uid);
    }

    /// Non-ASCII names are ordinary, not suspicious — only control
    /// characters are replaced.
    #[test]
    fn leaves_non_ascii_names_untouched() {
        let uid = "Zoë Müller <zoe@example.test>";
        assert_eq!(sanitize_for_display(uid), uid);
    }
}
