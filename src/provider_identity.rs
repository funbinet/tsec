//! Provider identity, and whether it is the tool the catalog means.
//!
//! Resolution is not agreement. `httpx` is the sharpest example: a widely used
//! HTTP probing tool, and also the name of a Python HTTP client whose console
//! entry point lands at `/usr/bin/httpx` on some distributions. Both resolve.
//! Only one understands `-u`, `-silent` and `-nc`, and when the wrong one is
//! found every operation built for the right one exits with `No such option` —
//! a wall of failures that says nothing about why.
//!
//! So a resolved binary is also *identified*: the flags its own help documents
//! are read once, cached, and compared with what the catalog asks of it. A
//! mismatch is reported as a provider fault with the offending flags named,
//! rather than surfacing later as a task that failed for no stated reason.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::catalog::Catalog;

/// How long a provider's `--help` may take. A wedged binary must not make
/// `tsec --status` hang.
const HELP_TIMEOUT: Duration = Duration::from_secs(3);

/// How long a *supplementary* help form may take.
///
/// `--help` is the one every tool answers, so it gets the full budget. The rest
/// are guesses at where a tool hides its options, tried only after the first came
/// back thin — and a tool that does not answer one of them promptly is a tool
/// that is doing something other than printing help.
const EXTRA_HELP_TIMEOUT: Duration = Duration::from_millis(700);

/// How long a drain is given to finish after its child has been killed.
const DRAIN_GRACE: Duration = Duration::from_millis(250);

/// Largest help text read. Flags appear in the first screen or not at all.
const HELP_LIMIT: u64 = 256 * 1024;

/// What a provider binary turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    /// The binary refused to describe itself.
    Silent,
    /// Its help text, trimmed to something displayable.
    Described(String),
    /// It did not run.
    Unrunnable(String),
}

/// Flags a provider's own help documents.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlagSet {
    pub long: BTreeSet<String>,
    pub short: BTreeSet<char>,
    /// Single-dash long options: `-severity`, `-tags`. Cobra's default when
    /// `pflag`'s shorthand mode is off, which is most of these tools.
    pub dash_long: BTreeSet<String>,
}

impl FlagSet {
    /// Whether this help text documents `flag`, as written.
    ///
    /// A single-dash multi-character token is ambiguous, because three
    /// conventions share the syntax and which one a tool uses cannot be told
    /// from the token alone. Each is tried in the order that resolves the
    /// ambiguity safely: an exact single-dash long option, then a cluster of
    /// short options (`-tlnp`), then a short option with its value attached
    /// (`-p8080`, `-v2c`).
    pub fn documents(&self, flag: &str) -> bool {
        match flag.strip_prefix("--") {
            Some(name) => self.long.contains(name),
            None => match flag.strip_prefix('-') {
                None | Some("") => false,
                Some(one) if one.chars().count() == 1 => {
                    let c = one.chars().next().expect("one character");
                    // `-p` is documented either as `-p` or as `-ps`, `-P`, `-Pn`:
                    // a short option that takes an attached value is named with
                    // its value in help.
                    self.short.contains(&c) || self.dash_long.iter().any(|d| d.starts_with(c))
                }
                Some(rest) => {
                    self.dash_long.contains(rest)
                        // A value written attached: `-PS21,22`, `-p8080`.
                        || self.dash_long.iter().any(|d| rest.starts_with(d.as_str()))
                        // A cluster of short options: `-tlnp`, `-sT`.
                        || rest.chars().all(|c| self.short.contains(&c))
                        || rest.chars().next().is_some_and(|c| self.short.contains(&c))
                }
            },
        }
    }
}

/// Every flag an operation's argument vector passes to its binary.
///
/// Tokens are kept whole, because whether `-nc` is one pflag shorthand or two
/// getopt options is the receiving tool's business, not the reader's. A value
/// written with `=` is dropped, since `--severity=high` passes `--severity`.
pub fn flags_used(args: &[String]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for a in args {
        let token = a.split('=').next().unwrap_or(a);
        if token.len() > 1 && token.starts_with('-') {
            out.insert(token.to_string());
        }
    }
    out
}

/// Read a provider's help and extract the flags it documents.
///
/// `--help` is tried before `-h` and before a bare invocation, because several
/// tools print a short usage error when run with no arguments and a naive probe
/// picks that up instead of the real help.
pub fn documented_flags(path: &Path) -> FlagSet {
    static CACHE: OnceLock<Mutex<BTreeMap<PathBuf, FlagSet>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
    if let Ok(map) = cache.lock() {
        if let Some(hit) = map.get(path) {
            return hit.clone();
        }
    }

    let set = parse_flags(&help_text(path));
    if let Ok(mut map) = cache.lock() {
        map.insert(path.to_path_buf(), set.clone());
    }
    set
}

/// A short, displayable description of what a provider binary actually is.
pub fn identity(path: &Path) -> Identity {
    let text = help_text(path);
    if text.trim().is_empty() {
        return Identity::Silent;
    }
    for line in text.lines() {
        let line = line.trim();
        // Skip the ASCII-art frame most Go tools draw around their banner.
        if line.is_empty()
            || line
                .chars()
                .all(|c| c.is_whitespace() || c == '|' || c == '/')
        {
            continue;
        }
        return Identity::Described(line.chars().take(120).collect());
    }
    Identity::Silent
}

/// Help invocations to try, in order.
///
/// `--help` comes before `-h`, because several tools print a short usage error
/// under `-h` while `--help` prints the real menu. The doubled and lettered short
/// forms are here for tools whose summary help omits options: `unzip -h` has no
/// `-P`, `zip -h` documents 15 options where `zip -h2` documents 77, and
/// `mdk4 --fullhelp` describes attack modes that `--help` does not.
///
/// A bare invocation is deliberately absent: with no arguments it either starts
/// the tool's real work, against a target, or waits on input.
const HELP_ARGS: [(&[&str], Duration); 5] = [
    (&["--help"], HELP_TIMEOUT),
    (&["-h"], EXTRA_HELP_TIMEOUT),
    (&["-hh"], EXTRA_HELP_TIMEOUT),
    (&["--fullhelp"], EXTRA_HELP_TIMEOUT),
    (&["-h2"], EXTRA_HELP_TIMEOUT),
];

/// Enough flags to consider a help text informative.
const HELP_FLOOR: usize = 40;

/// Share of the catalog's flags a binary must recognise to count as the intended
/// provider. Below this, it is far more likely to be a different program than a
/// tool with an unfamiliar help layout.
const COVERAGE_FLOOR: usize = 60;

/// Options a binary must document at its own top level before its coverage of
/// the catalog's flags is treated as evidence about its identity.
///
/// Tools that document fewer than this are delegating: an interpreter, a shell
/// wrapper, or a program whose options live behind a subcommand or a second help
/// flag, as `sqlmap --sqlmap-help` and `trivy image --help` do. Their top-level
/// help is not a description of what they accept, so it cannot contradict the
/// catalog, and judging on it produces a fault report nobody can act on.
///
/// A provider that genuinely is the wrong program — `httpx` resolving to a Python
/// client — still clears this easily, because that program describes itself in
/// full.
const SELF_DESCRIBING_FLOOR: usize = 20;

/// The most informative help text a binary will give.
///
/// Of the forms tried, the one documenting the most flags wins, rather than the
/// first that prints anything: a tool's summary help routinely omits options
/// (`unzip -h` has no `-P`, `gitleaks --help` has no `-s`), and settling for the
/// first form would report valid catalog operations as faults.
fn help_text(path: &Path) -> String {
    let mut best = FlagSet::default();
    let mut best_text = String::new();
    for (args, budget) in HELP_ARGS {
        let Some(raw) = run_capped(path, args, budget) else {
            continue;
        };
        let text = strip_escapes(&raw);
        if text.trim().len() <= 40 || is_usage_error(&text) {
            continue;
        }
        // curl prints a category menu rather than its options unless asked twice.
        if text.contains("split into categories") {
            if let Some(raw) = run_capped(path, &["--help", "all"], HELP_TIMEOUT) {
                let all = strip_escapes(&raw);
                let all_flags = parse_flags(&all);
                if all_flags.len() > parse_flags(&text).len() {
                    best_text = all;
                    break;
                }
            }
        }
        let flags = parse_flags(&text);
        if flags.len() > best.len() {
            best = flags;
            best_text = text;
        }
        if best.len() >= HELP_FLOOR {
            break;
        }
    }
    best_text
}

impl FlagSet {
    /// How many distinct flags this help text mentions.
    pub fn len(&self) -> usize {
        self.all().count()
    }

    pub fn is_empty(&self) -> bool {
        self.all().next().is_none()
    }

    /// Every flag this help text mentions, in a stable order.
    fn all(&self) -> impl Iterator<Item = String> + '_ {
        self.short
            .iter()
            .map(|c| format!("-{c}"))
            .chain(self.long.iter().map(|l| format!("--{l}")))
            .chain(self.dash_long.iter().map(|d| format!("-{d}")))
    }
}

/// Whether this output is the tool complaining, not describing itself.
///
/// Some tools answer an unrecognised flag by printing their usage, which reads
/// like help and would be taken as evidence the tool is present and understood.
/// A few reject the doubled short form outright, which is why `waybackurls` and
/// `nxc` looked flagless when their real options are perfectly ordinary.
fn is_usage_error(text: &str) -> bool {
    let head = text
        .lines()
        .take(3)
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    [
        "incorrect usage",
        "flag provided but not defined",
        "unknown flag",
        "unknown option",
        "invalid option",
        "not defined",
        "is not a recognized option",
    ]
    .iter()
    .any(|marker| head.contains(marker))
}

/// Strip terminal control sequences from help text.
///
/// GNU tools in particular wrap each option in an OSC-8 hyperlink, so the
/// literal text is `…#sort-o\`-o, --output=FILE`, and no flag token ever begins
/// with a `-`. Colour and cursor codes have the same effect.
fn strip_escapes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        match chars.peek().copied() {
            // OSC: terminated by BEL or ST (`ESC \`).
            Some(']') => {
                chars.next();
                let mut prev = '\0';
                for c in chars.by_ref() {
                    if c == '\x07' || (prev == '\x1b' && c == '\\') {
                        break;
                    }
                    prev = c;
                }
            }
            // CSI: parameters/intermediates then a final byte in @..~.
            Some('[') => {
                chars.next();
                for c in chars.by_ref() {
                    if ('\x40'..='\x7e').contains(&c) {
                        break;
                    }
                }
            }
            // Two-byte escapes such as ESC ( B.
            Some(_) => {
                chars.next();
            }
            None => {}
        }
    }
    out
}

fn run_capped(path: &Path, args: &[&str], timeout: Duration) -> Option<String> {
    let mut child = Command::new(path)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    // The streams are drained on their own threads. Reading them here would block
    // until end-of-file, and a tool asked for help that prints nothing and waits
    // — or that forks a scanner — never closes them, so the deadline below would
    // never be reached. Killing the child ends the read.
    //
    // Killing the child is not enough to end it: a tool that forks hands its
    // pipes to the grandchild, so the write end stays open in a process that is
    // not the one we signalled, and the read below would never see end-of-file
    // either. The drain therefore accumulates into shared storage that outlives
    // the thread, so the collector below can take what has arrived and walk away
    // from a thread that is still blocked. Joining unconditionally turned a probe
    // with a three-second budget into a hang with no budget at all.
    let stdout = child.stdout.take().map(drain);
    let stderr = child.stderr.take().map(drain);

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    let mut out = String::new();
    out.push_str(&collect(stdout));
    out.push_str(&collect(stderr));
    Some(out)
}

/// Read a pipe to end-of-file, keeping at most [`HELP_LIMIT`] bytes.
fn drain<R: Read + Send + 'static>(pipe: R) -> (Arc<Mutex<String>>, std::thread::JoinHandle<()>) {
    let seen = Arc::new(Mutex::new(String::new()));
    let sink = Arc::clone(&seen);
    let mut pipe = pipe;
    let handle = std::thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        let mut held = 0usize;
        loop {
            let Ok(n) = pipe.read(&mut chunk) else { break };
            if n == 0 {
                break;
            }
            let room = (HELP_LIMIT as usize).saturating_sub(held);
            let take = (n as usize).min(room);
            if take == 0 {
                break;
            }
            if let Ok(mut slot) = sink.lock() {
                slot.push_str(&String::from_utf8_lossy(&chunk[..take]));
            }
            held += take;
            if held >= HELP_LIMIT as usize {
                break;
            }
        }
    });
    (seen, handle)
}

/// Take whatever the drains have collected, giving them a brief grace period.
///
/// A thread still blocked on a pipe held open by a grandchild is detached, not
/// waited for. The bytes already read are kept: a tool that prints its help and
/// then hangs is exactly the case worth reporting on, so what it wrote is
/// retained rather than discarded along with the thread.
fn collect(drained: Option<(Arc<Mutex<String>>, std::thread::JoinHandle<()>)>) -> String {
    let Some((seen, handle)) = drained else {
        return String::new();
    };
    let grace = Instant::now() + DRAIN_GRACE;
    while !handle.is_finished() && Instant::now() < grace {
        std::thread::sleep(Duration::from_millis(10));
    }
    seen.lock().map(|s| s.clone()).unwrap_or_default()
}

fn parse_flags(help: &str) -> FlagSet {
    let mut set = FlagSet::default();
    for token in help.split(|c: char| c.is_whitespace()) {
        let token =
            token.trim_matches(|c: char| matches!(c, ',' | '|' | '[' | ']' | '(' | ')' | '='));
        if let Some(rest) = token.strip_prefix("--") {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '.')
                .collect();
            if !name.is_empty() {
                set.long.insert(name);
            }
        } else if let Some(rest) = token.strip_prefix('-') {
            // The flag is the leading run of flag characters; whatever follows is
            // an attached value or a type annotation. `-i[SUFFIX]` is the short
            // `-i`, `-p8080` is `-p` with `8080`, `-severity` is one long option.
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '-')
                .collect();
            match name.chars().count() {
                0 => {}
                1 => {
                    let c = name.chars().next().expect("one character");
                    if c.is_alphanumeric() || c == '?' {
                        set.short.insert(c);
                    }
                }
                _ => {
                    set.dash_long.insert(name);
                }
            }
        }
    }
    set
}

/// A provider whose own help does not match the flags the catalog passes it.
///
/// The signal is coverage: how much of the catalog's vocabulary the installed
/// binary recognises. A provider that answers for most of it is the tool the
/// catalog was written against, and the few it does not answer for are a probe
/// limitation, not a fault. One that answers for almost none of it is not that
/// tool, whatever its name says — `httpx` is both a widely used prober and the
/// name of a Python HTTP client, and the two share exactly one option.
///
/// This is advisory, because a mismatch has two honest causes and a probe cannot
/// always tell them apart: the wrong program may be installed, or the catalog may
/// name options this version dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlagMismatch {
    pub binary: String,
    pub path: PathBuf,
    /// Every flag the catalog passes this binary.
    pub attempted: Vec<String>,
    /// Flags the catalog passes that this binary does not document.
    pub undocumented: Vec<String>,
    /// Flags this binary does document, to show it is answering at all.
    pub it_has: Vec<String>,
    /// How the binary describes itself, when it says anything.
    pub identity: String,
}

impl FlagMismatch {
    /// How much of the catalog's vocabulary this binary understands.
    pub fn coverage(&self) -> (usize, usize) {
        (
            self.attempted.len() - self.undocumented.len(),
            self.attempted.len(),
        )
    }

    /// One line an operator can act on.
    pub fn reason(&self) -> String {
        let (got, total) = self.coverage();
        let missing: Vec<String> = self
            .undocumented
            .iter()
            .take(4)
            .map(|f| format!("`{f}`"))
            .collect();
        let has = self
            .it_has
            .iter()
            .filter(|f| {
                f.starts_with('-') && !matches!(f.as_str(), "-h" | "-v" | "--help" | "--version")
            })
            .take(4)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "recognises {got} of the {total} flags the catalog passes it, not {}. \
             A different program of the same name is usually why; this build's options \
             may simply have changed. It offers {}.",
            missing.join(", "),
            if has.is_empty() {
                "no options of its own".to_string()
            } else {
                has
            }
        )
    }
}

/// Tools the catalog drives through a subcommand, an interpreter, or a shell.
///
/// Each of these documents its own options under a protocol, a module, or a `-c`
/// script rather than at the top level, so their top-level help is not a
/// description of what they accept and their flag coverage proves nothing.
/// `bash -lc` and `python3 -m http.server --bind` are both entirely valid.
const DELEGATING: &[&str] = &[
    "bash",
    "sh",
    "zsh",
    "python",
    "python2",
    "python3",
    "perl",
    "ruby",
    "nxc",
    "crackmapexec",
    "certipy",
    "coercer",
    "dalfox",
    "gobuster",
    "chisel",
    "scoutsuite",
    "mdk4",
    "kiterunner",
    // These do describe themselves, but only behind a form this probe does not
    // reach: `sqlmap --sqlmap-help`, `gpg --dump-options`. Judging them on the
    // short top-level help invents a fault out of a limitation.
    "sqlmap",
    "gpg",
    "gpgconf",
];

/// Check every installed provider against the flags the catalog passes it.
///
/// Only installed binaries are probed, and each is probed once. A binary whose
/// help is unreadable is left alone: silence is not evidence of a mismatch.
pub fn flag_mismatches(catalog: &Catalog) -> Vec<FlagMismatch> {
    // Probing is a subprocess per provider, so it is bounded rather than run
    // across every core: a host scanning 350 providers should stay responsive,
    // and the result is cached per binary either way.
    let jobs: Vec<(String, PathBuf, Vec<String>)> = {
        let mut needed: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
        for cap in catalog.capabilities() {
            for binding in &cap.providers {
                let entry = needed.entry(binding.binary.as_str()).or_default();
                for op in &binding.operations {
                    entry.extend(flags_used(&op.args));
                }
            }
        }
        needed
            .into_iter()
            .filter(|(_, flags)| !flags.is_empty())
            .filter(|(binary, _)| !DELEGATING.contains(binary))
            .filter_map(|(binary, flags)| {
                crate::provider::find_in_path(binary).map(|path| {
                    (
                        binary.to_string(),
                        path,
                        flags.into_iter().collect::<Vec<_>>(),
                    )
                })
            })
            .collect()
    };

    let found: Vec<Option<FlagMismatch>> = run_bounded(jobs.len(), |i| {
        let (binary, path, flags) = &jobs[i];
        let documented = documented_flags(path);
        if documented.len() < 3 {
            // The binary would not describe itself; that is not a mismatch.
            return None;
        }
        let undocumented: Vec<String> = flags
            .iter()
            .filter(|f| !documented.documents(f))
            .cloned()
            .collect();
        // A provider that answers for most of what the catalog asks of it is the
        // tool the catalog was written against; stragglers are the probe's blind
        // spot, not a fault worth interrupting a run over.
        let coverage = (flags.len() - undocumented.len()) * 100 / flags.len();
        if coverage >= COVERAGE_FLOOR {
            return None;
        }
        // A tool that documents almost nothing at its top level — a wrapper, a
        // shell script, an interpreter — has put its options behind a subcommand
        // the probe cannot reach, so its coverage says nothing about identity.
        // Only a tool with a substantial option list is judged on it.
        if documented.len() < SELF_DESCRIBING_FLOOR {
            return None;
        }
        let it_has = documented.all().take(10).collect::<Vec<_>>();
        let identity = match identity(path) {
            Identity::Described(text) => text,
            _ => path.display().to_string(),
        };
        Some(FlagMismatch {
            binary: binary.clone(),
            path: path.clone(),
            attempted: flags.clone(),
            undocumented,
            it_has,
            identity,
        })
    });

    found.into_iter().flatten().collect()
}

/// Map `f` over `0..n` on at most `n` threads, preserving input order.
///
/// The flag cache is keyed by path and shared, so concurrent probes of the same
/// binary cannot happen: each binary appears once in `jobs`.
fn run_bounded<T: Send + Clone>(n: usize, f: impl Fn(usize) -> T + Sync) -> Vec<T> {
    if n == 0 {
        return Vec::new();
    }
    let threads = std::thread::available_parallelism()
        .map(|p| p.get().min(8))
        .unwrap_or(4)
        .min(n);
    let next = std::sync::atomic::AtomicUsize::new(0);
    let slots: Vec<std::sync::Mutex<Option<T>>> =
        (0..n).map(|_| std::sync::Mutex::new(None)).collect();
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if i >= n {
                    return;
                }
                let value = f(i);
                *slots[i].lock().expect("slot lock") = Some(value);
            });
        }
    });
    slots
        .into_iter()
        .map(|slot| slot.into_inner().expect("slot lock").expect("slot filled"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_and_short_flags_are_extracted_from_a_help_menu() {
        // Shape copied from `curl --help`.
        let set = parse_flags(
            " -s, --silent        Silent mode\n -o, --output <file>  Write to file\n -H, --header <h>   Pass a header\n",
        );
        assert!(set.documents("-s"));
        assert!(set.documents("-o"));
        assert!(set.documents("--silent"));
        assert!(set.documents("--output"));
        assert!(!set.documents("-z"));
        assert!(!set.documents("--not-a-flag"));
    }

    #[test]
    fn single_dash_long_flags_are_understood() {
        // Shape copied from `nuclei -h`.
        let set = parse_flags(
            "   -tags string[]       templates to run\n   -severity string[]   severity to run\n   -nc, -no-color       disable output coloring\n   -lfa                  allow local file access\n",
        );
        assert!(set.documents("-tags"));
        assert!(set.documents("-severity"));
        assert!(set.documents("-nc"));
        assert!(set.documents("-no-color"));
        assert!(set.documents("-lfa"));
        assert!(!set.documents("-rate-limit"));
        // `-tags` is a long option, not a short flag `t`.
        assert!(!set.short.contains(&'t'));
    }

    #[test]
    fn a_hyphenated_word_is_not_mistaken_for_a_flag() {
        // Prose in a help footer must not manufacture flags; without the token
        // split, `some-file-name` reads as `-file` and `-name`.
        let set = parse_flags("scans some-file-name from disk\n  --only-resolve  resolve hosts\n");
        assert!(set.documents("--only-resolve"));
        assert!(!set.documents("-file"));
        assert!(!set.documents("-name"));
        assert!(!set.documents("--ile-name"));
        assert!(set.short.is_empty());
    }

    #[test]
    fn only_flag_shaped_arguments_are_collected() {
        let args: Vec<String> = [
            "-u",
            "https://example.com",
            "--tags",
            "tech",
            "-severity=high",
            "-silent",
            "--nc",
            "{wl:web/common.txt}",
            "-",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let used = flags_used(&args);
        assert!(used.contains("-u"));
        assert!(used.contains("--tags"));
        assert!(used.contains("-severity"));
        assert!(used.contains("-silent"));
        assert!(used.contains("--nc"));
        // A bare `-` is a conventional stdin marker, not a flag.
        assert!(!used.contains("-"));
        // A positional target is not a flag.
        assert!(!used.contains("https://example.com"));
    }

    #[test]
    fn a_mismatch_names_the_binary_the_flags_and_how_to_fix_it() {
        let m = FlagMismatch {
            binary: "httpx".into(),
            path: PathBuf::from("/usr/bin/httpx"),
            attempted: vec![
                "-u".into(),
                "-silent".into(),
                "-nc".into(),
                "-json".into(),
                "-title".into(),
            ],
            undocumented: vec!["-u".into(), "-silent".into(), "-nc".into()],
            it_has: vec!["--method".into(), "--params".into(), "--data".into()],
            identity: "python-httpx console script".into(),
        };
        // Two of five recognised: the prober's vocabulary and the client's.
        assert_eq!(m.coverage(), (2, 5));
        let reason = m.reason();
        assert!(reason.contains("recognises 2 of the 5 flags"));
        assert!(reason.contains("-u"));
        assert!(reason.contains("-silent"));
        assert!(reason.contains("--method"));
    }

    #[test]
    fn a_probe_gives_up_on_a_binary_that_never_exits() {
        // `sleep` accepts no options and prints nothing. It stands in for any
        // tool asked for help that does not answer: reading its output must not
        // block waiting for an end-of-file that never comes.
        let started = Instant::now();
        let out = run_capped(Path::new("/bin/sleep"), &["30"], Duration::from_millis(300))
            .expect("the probe returns whatever it managed to read");
        assert!(out.is_empty(), "sleep says nothing: {out:?}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the deadline must be honoured, took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_binary_that_cannot_describe_itself_is_not_a_mismatch() {
        // `/bin/true` accepts no flags and prints nothing; that is not evidence
        // that it rejects what the catalog passes it.
        let documented = documented_flags(Path::new("/bin/true"));
        assert!(documented.long.is_empty() || documented.short.is_empty());
    }
}
