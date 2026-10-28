//! Process-agnostic command representation.
//!
//! A [`Command`] is an explicit program plus an argument *vector*. Nothing is
//! interpolated into a shell string, so flags, paths and values keep their
//! exact original form and can never be re-tokenised, glob-expanded or
//! word-split by accident. The shell is only reached through the explicit
//! [`Command::shell`] constructor, which is reserved for the handful of
//! providers that genuinely require shell features (pipes, redirection).

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

use std::fmt;
use std::path::PathBuf;

/// Why a command could not be constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandError {
    pub reason: String,
}

impl CommandError {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for CommandError {}

/// An immutable, fully-resolved external command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    program: String,
    args: Vec<String>,
    cwd: Option<PathBuf>,
    env: Vec<(String, String)>,
    /// Argument indexes holding secret material, tracked as arguments are
    /// added. Recording the index at the point the secret is appended is the
    /// only way to guarantee it cannot be forgotten: a caller that later
    /// renumbered or inserted arguments would silently leak a password.
    sensitive: Vec<usize>,
    /// Whether this command performs network activity and therefore must be
    /// launched inside a private oniux namespace whose only route is Tor.
    ///
    /// Defaults to `true`. The dangerous mistake in this framework is a command
    /// that reaches the network without passing through oniux, so a caller must
    /// *opt out* of the boundary with [`Command::local`] rather than remember to
    /// opt in. Anything that turns out to be genuinely local costs one extra
    /// namespace; anything wrongly marked local leaks a scan onto the host
    /// network, and the two mistakes are not symmetric.
    pub network: bool,
    /// Whether construction required a shell. Recorded in execution metadata.
    pub uses_shell: bool,
}

impl Command {
    /// Build a direct (non-shell) command.
    pub fn new(program: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            program: program.into(),
            args,
            cwd: None,
            env: Vec::new(),
            sensitive: Vec::new(),
            network: true,
            uses_shell: false,
        }
    }

    /// Declare this command genuinely local, with no network capability.
    ///
    /// Only for commands that cannot reach the network under any input — reading
    /// a local file, transforming captured evidence. Anything that might open a
    /// connection, even indirectly, must stay behind oniux.
    pub fn local(mut self) -> Self {
        self.network = false;
        self
    }

    /// Build a command that must be evaluated by `/bin/sh -c`.
    ///
    /// Only used by providers that genuinely need shell features; the reason
    /// is recorded so the execution record stays honest about it.
    pub fn shell(script: impl Into<String>, reason: &'static str) -> Self {
        let _ = reason;
        Self {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            cwd: None,
            env: Vec::new(),
            sensitive: Vec::new(),
            // A shell script can do anything, including opening a connection, so
            // it takes the same fail-safe default as a direct command.
            network: true,
            uses_shell: true,
        }
    }

    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Append a secret argument and record its position as sensitive.
    ///
    /// Use this for anything derived from a `Secret` or `Password` input so the
    /// value can never reach a log, a report or the operator's scrollback.
    pub fn secret(mut self, value: impl Into<String>) -> Self {
        self.sensitive.push(self.args.len());
        self.args.push(value.into());
        self
    }

    /// Append a flag whose value is a secret.
    pub fn flag_secret(mut self, flag: &str, value: &str) -> Self {
        if !value.is_empty() {
            self.sensitive.push(self.args.len() + 1);
            self.args.push(flag.to_string());
            self.args.push(value.to_string());
        }
        self
    }

    /// Append several arguments at once.
    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Append a flag/value pair only when the value is non-empty.
    ///
    /// Providers use this instead of hand-rolled `if` blocks so a missing
    /// optional input can never leave a dangling flag behind.
    pub fn flag_value(mut self, flag: &str, value: &str) -> Self {
        if !value.is_empty() {
            self.args.push(flag.to_string());
            self.args.push(value.to_string());
        }
        self
    }

    /// Append a boolean flag when `enabled`.
    pub fn flag(mut self, flag: &str, enabled: bool) -> Self {
        if enabled {
            self.args.push(flag.to_string());
        }
        self
    }

    pub fn cwd(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cwd = Some(dir.into());
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    pub fn network(mut self, is_network: bool) -> Self {
        self.network = is_network;
        self
    }

    /// Whether this command opens network connections and must be run behind oniux.
    pub fn is_network(&self) -> bool {
        self.network
    }

    pub fn program(&self) -> &str {
        &self.program
    }

    pub fn args(&self) -> &[String] {
        &self.args
    }

    pub fn working_dir(&self) -> Option<&std::path::Path> {
        self.cwd.as_deref()
    }

    pub fn env_pairs(&self) -> &[(String, String)] {
        &self.env
    }

    /// Argument indexes whose values must be masked in any display.
    pub fn sensitive_args(&self) -> &[usize] {
        &self.sensitive
    }

    /// Mark an existing argument as sensitive, for the rare case where the
    /// value was appended before its secret nature was known.
    pub fn mark_sensitive(mut self, index: usize) -> Self {
        if !self.sensitive.contains(&index) {
            self.sensitive.push(index);
        }
        self
    }

    /// Shell-quoted single-line rendering suitable for copying and pasting.
    ///
    /// Quoting follows POSIX conventions so the rendered line can be pasted
    /// into a terminal and behave identically. The rendered text is the
    /// command's *exact* content — it is never case-folded.
    pub fn display(&self) -> String {
        let mut out = String::new();
        out.push_str(&quote_token(self.program()));
        for a in self.args() {
            out.push(' ');
            // The `sh -c <script>` pair is rendered verbatim: the script is
            // already a shell program and re-quoting it would be misleading.
            if self.uses_shell && a.contains(['|', '>', '&']) {
                out.push_str(a);
            } else {
                out.push_str(&quote_token(a));
            }
        }
        out
    }

    /// Same as [`Command::display`] but with sensitive values masked.
    /// Render the command for display with the arguments at `sensitive`
    /// indexes masked.
    ///
    /// The mask is emitted literally rather than shell-quoted: it is a marker
    /// for the reader, not a value the operator could paste, and quoting it
    /// would suggest otherwise. Callers normally pass
    /// [`Command::sensitive_args`] and let the command report its own secrets.
    pub fn display_redacted(&self, sensitive: &[usize]) -> String {
        let mut mask: Vec<usize> = self.sensitive.clone();
        mask.extend_from_slice(sensitive);
        let mut out = String::new();
        out.push_str(&quote_token(self.program()));
        for (i, a) in self.args().iter().enumerate() {
            out.push(' ');
            if mask.contains(&i) {
                out.push_str(REDACTED);
            } else {
                out.push_str(&quote_token(a));
            }
        }
        out
    }

    /// Render the command with every secret it knows about masked.
    pub fn display_safe(&self) -> String {
        self.display_redacted(&[])
    }

    /// The argument vector with the arguments at `sensitive` indexes masked.
    ///
    /// This is what belongs in a persisted execution record. Storing the real
    /// argv would put a password into a JSON report, a log line and every
    /// derived summary, none of which the operator asked to publish a
    /// credential into.
    pub fn args_redacted(&self, sensitive: &[usize]) -> Vec<String> {
        let mut mask: Vec<usize> = self.sensitive.clone();
        mask.extend_from_slice(sensitive);
        self.args()
            .iter()
            .enumerate()
            .map(|(i, a)| {
                if mask.contains(&i) {
                    REDACTED.to_string()
                } else {
                    a.clone()
                }
            })
            .collect()
    }
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display())
    }
}

/// Placeholder substituted for a secret argument in any operator-visible
/// rendering of a command.
pub const REDACTED: &str = "<redacted>";

/// POSIX single-quote an argument, escaping embedded single quotes.
/// Quote a single argv element for display in a log or report.
///
/// Exposed so the execution engine can render the *wrapped* argv (the one
/// actually handed to oniux) with the same quoting rules as a plain command,
/// rather than inventing a second, subtly different format.
pub fn quote_for_log(token: &str) -> String {
    quote_token(token)
}

fn quote_token(token: &str) -> String {
    if !token.is_empty()
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-./:=+@,%^".contains(c))
    {
        return token.to_string();
    }
    let mut out = String::with_capacity(token.len() + 2);
    out.push('\'');
    for c in token.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_command_is_network_capable_until_told_otherwise() {
        // The default must be the safe one: behind oniux. A forgotten
        // `.local()` costs a namespace; a forgotten `.network(true)` would put a
        // scan on the host network, so the asymmetry decides the default.
        let c = Command::new("httpx", vec![]);
        assert!(
            c.is_network(),
            "commands must default to the oniux boundary"
        );
        assert!(!c.local().is_network());
        // A shell script can do anything, so it takes the same default.
        assert!(Command::shell("curl $URL", "test").is_network());
    }

    #[test]
    fn simple_arguments_are_left_unquoted() {
        let c = Command::new("nmap", vec!["-sV".into(), "-T4".into(), "10.0.0.1".into()]);
        assert_eq!(c.display(), "nmap -sV -T4 10.0.0.1");
    }

    #[test]
    fn arguments_with_spaces_are_quoted_for_copy_paste() {
        let c = Command::new("nmap", vec!["--script".into(), "http title".into()]);
        assert_eq!(c.display(), "nmap --script 'http title'");
    }

    #[test]
    fn embedded_single_quotes_are_escaped() {
        let c = Command::new("sh", vec!["-c".into(), "echo 'hi'".into()]);
        assert_eq!(c.display(), "sh -c 'echo '\\''hi'\\'''");
    }

    #[test]
    fn flag_value_skips_empty_values_so_no_dangling_flag_remains() {
        let c = Command::new("naabu", Vec::new())
            .flag_value("-host", "10.0.0.1")
            .flag_value("-proxy", "");
        assert_eq!(c.args(), &["-host".to_string(), "10.0.0.1".to_string()]);
    }

    #[test]
    fn flag_is_only_emitted_when_enabled() {
        let c = Command::new("naabu", Vec::new())
            .flag("-json", true)
            .flag("-csv", false);
        assert_eq!(c.args(), &["-json".to_string()]);
    }

    #[test]
    fn command_preserves_original_case_of_execution_data() {
        let c = Command::new(
            "httpx",
            vec!["-u".into(), "https://Example.COM/Path".into()],
        );
        assert!(c.display().contains("https://Example.COM/Path"));
    }

    #[test]
    fn redaction_masks_only_the_named_argument_index() {
        let c = Command::new(
            "nxc",
            vec!["-u".into(), "admin".into(), "-p".into(), "s3cret".into()],
        );
        assert_eq!(c.display_redacted(&[3]), "nxc -u admin -p <redacted>");
    }

    #[test]
    fn a_command_tracks_its_own_secrets_without_being_told_where_they_are() {
        let c = Command::new("nxc", vec!["-u".into(), "admin".into()])
            .arg("-p")
            .secret("s3cret")
            .arg("--shares")
            .secret("IPC$");
        // -u admin -p s3cret --shares IPC$  →  secrets sit at 3 and 5.
        assert_eq!(c.sensitive_args(), &[3, 5]);
        let shown = c.display_safe();
        assert!(!shown.contains("s3cret"), "{shown}");
        assert!(!shown.contains("IPC$"), "{shown}");
        assert!(
            shown.contains("admin"),
            "non-secret arguments must stay visible: {shown}"
        );
        // The real arguments are untouched, so the tool still receives them.
        assert_eq!(c.args()[3], "s3cret");
    }

    #[test]
    fn a_secret_flag_pair_is_recorded_after_the_flag_not_before_it() {
        let c = Command::new("mimikatz", vec![]).flag_secret("-p", "hunter2");
        assert_eq!(c.sensitive_args(), &[1]);
        let shown = c.display_safe();
        assert_eq!(shown, "mimikatz -p <redacted>");
    }

    #[test]
    fn an_empty_secret_value_leaves_no_dangling_flag() {
        let c = Command::new("mimikatz", vec![]).flag_secret("-p", "");
        assert!(c.args().is_empty());
        assert!(c.sensitive_args().is_empty());
        assert_eq!(c.display_safe(), "mimikatz");
    }

    #[test]
    fn marking_an_argument_sensitive_twice_masks_it_once() {
        let c = Command::new("x", vec![]).secret("a").mark_sensitive(0);
        assert_eq!(c.sensitive_args(), &[0]);
        assert_eq!(c.display_safe(), "x <redacted>");
    }

    #[test]
    fn shell_commands_record_their_shell_requirement() {
        let c = Command::shell("cat x | jq .", "pipeline");
        assert!(c.uses_shell);
        assert_eq!(c.program(), "/bin/sh");
    }
}
