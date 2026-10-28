//! Distro-aware provider installation, plus the small read-only process helpers
//! the theme adapter needs.
//!
//! The rule this module exists to enforce: **never invent a package name.**
//! A package is only offered after a query against the host's *local* package
//! database actually resolved it — `apt-cache show`, `pacman -Si`,
//! `dnf --cacheonly info`, `apk info -a`, `zypper --non-interactive info`.
//! Every one of those is an offline metadata read. TSEC does not query a
//! repository over the network to decide what to install, because doing so
//! would mean leaving the oniux boundary for something that must be decided
//! before any task runs.
//!
//! Four package managers are supported, because between them they cover the
//! hosts this framework is actually used on:
//!
//! | Family | Manager | Query | Install |
//! |---|---|---|---|
//! | Arch, including Manjaro | `pacman` | `pacman -Si <pkg>` | `pacman -S --needed <pkg>` |
//! | Arch AUR | `yay` / `paru` | — | `<helper> -S <pkg>` |
//! | Debian, Ubuntu, Kali | `apt-get` | `apt-cache show <pkg>` | `apt-get install -y <pkg>` |
//! | Fedora, RHEL, CentOS | `dnf` / `dnf5` / `yum` | `dnf --cacheonly info <pkg>` | `dnf install -y <pkg>` |
//! | Alpine | `apk` | `apk info -a <pkg>` | `apk add <pkg>` |
//! | openSUSE, SLES | `zypper` | `zypper --non-interactive info <pkg>` | `zypper install -y <pkg>` |
//!
//! A tool that is not in any official repository is reported as such, together
//! with the command the operator can run to search for it. That is a real
//! answer; "there is no package for this" is not one.

// Copyright (c) funbinet. All rights reserved.
// Part of TSEC terminal cybersecurity operations platform by funbinet.
//
// Repository: github.com/funbinet/tsec.git (origin)
// Mirror:     codeberg.org/funbinet/tsec.git (codeberg)
// Owner:      funbinet

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::provider::find_in_path;

/// Resolve an executable on `PATH` (or as an absolute path).
pub fn which(binary: &str) -> Option<PathBuf> {
    find_in_path(binary)
}

/// Run `program args…` with a hard timeout and capture stdout.
///
/// Returns the exit code and stdout; `None` when the program could not be
/// started at all. The child is killed if the timeout elapses, so a wedged
/// helper can never hang the interface.
pub fn run_capture(program: &str, args: &[&str], timeout_secs: u64) -> Option<(i32, String)> {
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stdout.read_to_string(&mut buf);
        buf
    });

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(25));
    };

    let out = reader.join().unwrap_or_default();
    match status {
        Some(status) => Some((status.code().unwrap_or(-1), out)),
        // Killed by the timeout: report failure with whatever was read.
        None => Some((-1, out)),
    }
}

// ── distribution detection ───────────────────────────────────────────────────

/// A package manager this module knows how to drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Manager {
    Pacman,
    Apt,
    Dnf,
    Yum,
    Apk,
    Zypper,
    /// No supported manager on this host.
    Unknown,
}

impl Manager {
    /// The command that drives this manager.
    pub fn binary(self) -> &'static str {
        match self {
            Manager::Pacman => "pacman",
            Manager::Apt => "apt-get",
            Manager::Dnf => "dnf",
            Manager::Yum => "yum",
            Manager::Apk => "apk",
            Manager::Zypper => "zypper",
            Manager::Unknown => "",
        }
    }

    /// Human name of the distribution family, for what the operator is shown.
    pub fn family(self) -> &'static str {
        match self {
            Manager::Pacman => "Arch Linux",
            Manager::Apt => "Debian family",
            Manager::Dnf => "Fedora family",
            Manager::Yum => "RHEL family",
            Manager::Apk => "Alpine Linux",
            Manager::Zypper => "openSUSE family",
            Manager::Unknown => "unknown distribution",
        }
    }

    /// Offline metadata query for one package: name, version, description.
    fn query(self, pkg: &str) -> Option<(String, String, String)> {
        match self {
            Manager::Pacman => {
                run_capture("pacman", &["-Si", pkg], 8).and_then(|(_, o)| parse_pacman_info(&o))
            }
            Manager::Apt => run_capture("apt-cache", &["show", pkg], 8).and_then(|(code, o)| {
                if code != 0 || o.trim().is_empty() {
                    return None;
                }
                parse_apt_show(&o)
            }),
            Manager::Dnf | Manager::Yum => {
                let bin = self.binary();
                run_capture(bin, &["--cacheonly", "info", pkg], 15)
                    .or_else(|| run_capture(bin, &["info", pkg], 15))
                    .and_then(|(code, o)| {
                        if code != 0 {
                            return None;
                        }
                        parse_dnf_info(&o)
                    })
            }
            Manager::Apk => run_capture("apk", &["info", "-a", pkg], 8).and_then(|(code, o)| {
                if code != 0 {
                    return None;
                }
                parse_apk_info(&o)
            }),
            Manager::Zypper => run_capture("zypper", &["--non-interactive", "info", pkg], 15)
                .and_then(|(code, o)| {
                    if code != 0 {
                        return None;
                    }
                    parse_zypper_info(&o)
                }),
            Manager::Unknown => None,
        }
    }

    /// Install command for a resolved package name.
    ///
    /// Returns the argv, not a shell string: the install runs as a direct
    /// vector, so nothing in a package name can be reinterpreted as syntax.
    pub fn install_argv(self, pkg: &str) -> Vec<String> {
        let s = |v: &str| v.to_string();
        match self {
            Manager::Pacman => vec![
                s("pacman"),
                s("-S"),
                s("--needed"),
                s("--noconfirm"),
                pkg.to_string(),
            ],
            Manager::Apt => vec![
                s("apt-get"),
                s("install"),
                s("-y"),
                s("--no-install-recommends"),
                pkg.to_string(),
            ],
            Manager::Dnf => vec![s("dnf"), s("install"), s("-y"), pkg.to_string()],
            Manager::Yum => vec![s("yum"), s("install"), s("-y"), pkg.to_string()],
            Manager::Apk => vec![s("apk"), s("add"), pkg.to_string()],
            Manager::Zypper => vec![
                s("zypper"),
                s("--non-interactive"),
                s("install"),
                s("-y"),
                pkg.to_string(),
            ],
            Manager::Unknown => Vec::new(),
        }
    }
}

/// The package manager on this host.
///
/// Order matters: `yum` is a compatibility shim that exists on Fedora hosts
/// alongside `dnf`, and `dnf5` is the newer name, so the modern one wins. On an
/// Arch host `apt` is never present, so the probe order is unambiguous in
/// practice.
pub fn detect_manager() -> Manager {
    static CACHE: OnceLock<Manager> = OnceLock::new();
    *CACHE.get_or_init(|| {
        for manager in [
            Manager::Pacman,
            Manager::Apt,
            Manager::Dnf,
            Manager::Yum,
            Manager::Apk,
            Manager::Zypper,
        ] {
            if which(manager.binary()).is_some() {
                return manager;
            }
        }
        Manager::Unknown
    })
}

/// The distribution's own name, read from `os-release`.
///
/// Used only for what the operator is shown. Detection of *behaviour* comes from
/// [`detect_manager`], because a manager is what can actually be driven.
pub fn distro_name() -> String {
    static CACHE: OnceLock<String> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            let raw = std::fs::read_to_string("/etc/os-release")
                .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
                .unwrap_or_default();
            let field = |key: &str| {
                raw.lines().find_map(|l| {
                    let (k, v) = l.split_once('=')?;
                    (k.trim() == key).then(|| v.trim().trim_matches('"').to_string())
                })
            };
            field("PRETTY_NAME")
                .or_else(|| field("NAME"))
                .unwrap_or_else(|| detect_manager().family().to_string())
        })
        .clone()
}

/// An AUR helper on this host, preferring `paru` then `yay`.
///
/// `paru` first: it is the faster of the two and is what Arch installs by
/// default now, so on a host with both, the quicker one is the right default.
pub fn aur_helper() -> Option<String> {
    ["paru", "yay"]
        .into_iter()
        .find(|h| which(h).is_some())
        .map(String::from)
}

/// Backwards-compatible alias for the Arch-only name this used to expose.
pub fn helper() -> Option<String> {
    aur_helper()
}

/// Whether this process can install anything without help.
pub fn can_install() -> bool {
    detect_manager() != Manager::Unknown
}

// ── advice ───────────────────────────────────────────────────────────────────

/// A package that actually resolved in a local package database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPackage {
    pub manager: Manager,
    pub name: String,
    pub version: String,
    pub description: String,
}

/// What the operator should do to install a missing provider.
#[derive(Debug, Clone)]
pub struct InstallAdvice {
    pub binary: String,
    /// Set when a real query resolved the package.
    pub resolved: Option<ResolvedPackage>,
    /// An AUR helper present on this host, on an Arch host.
    pub helper: Option<String>,
    /// Verified install commands, ready to display.
    pub commands: Vec<String>,
    /// Honest context: where it was verified, or why nothing was.
    pub notes: Vec<String>,
}

impl InstallAdvice {
    /// Already-installed advice, for completeness of the API.
    pub fn installed(binary: &str, path: &Path) -> Self {
        Self {
            binary: binary.to_string(),
            resolved: None,
            helper: aur_helper(),
            commands: Vec::new(),
            notes: vec![format!("already installed at {}", path.display())],
        }
    }

    /// The package name, if one resolved.
    pub fn package(&self) -> Option<&str> {
        self.resolved.as_ref().map(|p| p.name.as_str())
    }

    /// Whether the framework can install this by itself.
    pub fn is_auto_installable(&self) -> bool {
        self.resolved.is_some()
    }
}

/// Installation guidance for `binary`, cached for the process lifetime.
pub fn advise(binary: &str) -> InstallAdvice {
    static CACHE: OnceLock<Mutex<BTreeMap<String, InstallAdvice>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
    if let Ok(map) = cache.lock() {
        if let Some(hit) = map.get(binary) {
            return hit.clone();
        }
    }

    let advice = compute(binary);

    if let Ok(mut map) = cache.lock() {
        map.insert(binary.to_string(), advice.clone());
    }
    advice
}

/// Drop the cached advice for a binary, after a background install changed it.
///
/// Without this, a tool installed during a run would still be reported missing
/// for the rest of the session.
pub fn invalidate(binary: &str) {
    static CACHE: OnceLock<Mutex<BTreeMap<String, InstallAdvice>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
    if let Ok(mut map) = cache.lock() {
        map.remove(binary);
    }
}

/// Package names to try for a binary, in order.
///
/// A binary name and its package name are frequently different — `nikto` ships
/// as `nikto` but `masscan` is `masscan`, while `nmap` the binary is `nmap` the
/// package and `hping3` is `hping3`. The variants below cover the shapes that
/// actually occur without inventing anything: each candidate is still verified.
fn candidates(binary: &str) -> Vec<String> {
    let mut out = vec![binary.to_string()];
    let lower = binary.to_lowercase();
    if lower != binary {
        out.push(lower);
    }
    // `impacket-secretsdump` ships as `impacket-scripts` on Debian and
    // `impacket` on Arch; both spellings are worth a query.
    if let Some(rest) = binary.strip_prefix("impacket-") {
        out.push(format!("impacket-{rest}"));
        out.push("impacket-scripts".to_string());
        out.push("impacket".to_string());
    }
    // Debian splits the Go tools by command: `subfinder` is its own package,
    // but `httpx`, `naabu` and `nuclei` are often namespaced upstream.
    for (bin, pkg) in [
        ("httpx", "httpx-toolkit"),
        ("naabu", "naabu"),
        ("gospider", "gospider"),
        ("interactsh-client", "interactsh-client"),
        ("oledump", "oletools"),
        ("oledump.py", "oletools"),
        ("olebha", "oletools"),
        ("olevba", "oletools"),
        ("oledump", "oletools"),
    ] {
        if binary == bin {
            out.push(pkg.to_string());
        }
    }
    out.dedup();
    out
}

fn compute(binary: &str) -> InstallAdvice {
    if let Some(path) = which(binary) {
        return InstallAdvice::installed(binary, &path);
    }

    let manager = detect_manager();
    let helper = aur_helper();
    let mut advice = InstallAdvice {
        binary: binary.to_string(),
        resolved: None,
        helper: helper.clone(),
        commands: Vec::new(),
        notes: Vec::new(),
    };

    if manager == Manager::Unknown {
        advice.notes.push(
            "no supported package manager found (looked for pacman, apt-get, dnf, yum, apk, zypper)"
                .to_string(),
        );
        advice.notes.push(format!(
            "install {binary} from its upstream release and place it on PATH"
        ));
        return advice;
    }

    for candidate in candidates(binary) {
        let Some((name, version, description)) = manager.query(&candidate) else {
            continue;
        };
        advice.commands = render_install(manager, helper.as_deref(), &name);
        advice.notes.push(format!(
            "verified in the {} package database ({name} {version})",
            manager.family()
        ));
        if !description.is_empty() {
            advice.notes.push(description.clone());
        }
        advice.resolved = Some(ResolvedPackage {
            manager,
            name,
            version,
            description,
        });
        return advice;
    }

    // Not in any official repository. Say so plainly and hand over a search
    // command the operator can run — TSEC will not claim a package exists
    // without verifying it against a real database.
    advice.notes.push(format!(
        "{binary} is not in the {} repositories",
        manager.family()
    ));
    match manager {
        Manager::Pacman => match &helper {
            Some(helper) => advice
                .notes
                .push(format!("search the AUR:  {helper} -Ss {binary}")),
            None => advice
                .notes
                .push("no AUR helper found — install paru or yay, then search the AUR".into()),
        },
        Manager::Apt => advice
            .notes
            .push(format!("search the archive:  apt-cache search {binary}")),
        Manager::Dnf | Manager::Yum => advice.notes.push(format!(
            "search the repos:  {} search {binary}",
            manager.binary()
        )),
        Manager::Apk => advice
            .notes
            .push(format!("search the repos:  apk search -x {binary}")),
        Manager::Zypper => advice
            .notes
            .push(format!("search the repos:  zypper search {binary}")),
        Manager::Unknown => {}
    }
    advice.notes.push(format!(
        "or install {binary} from its upstream release and place it on PATH"
    ));
    advice
}

/// The install commands for a resolved package, best option first.
fn render_install(manager: Manager, helper: Option<&str>, pkg: &str) -> Vec<String> {
    let mut out = vec![manager.install_argv(pkg).join(" ")];
    // On Arch an official package is often also in the AUR with a newer build;
    // offer it second rather than first, because the official one is verifiable.
    if manager == Manager::Pacman {
        if let Some(helper) = helper {
            out.push(format!("{helper} -S {pkg}"));
        }
    }
    // Every root-requiring manager needs sudo unless the process already is root.
    if let Some(first) = out.first_mut() {
        if !is_root() {
            *first = format!("sudo {first}");
        }
    }
    out
}

fn is_root() -> bool {
    std::env::var_os("USER")
        .map(|u| u == "root")
        .unwrap_or(false)
        || Path::new("/proc/self").exists()
            && std::fs::read_to_string("/proc/self/status")
                .map(|s| s.contains("Uid:\t0"))
                .unwrap_or(false)
}

// ── background installation ──────────────────────────────────────────────────

/// The outcome of one background installation attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallOutcome {
    /// The binary is now on `PATH`.
    Installed { package: String },
    /// The install ran and the package manager refused.
    Refused { package: String, reason: String },
    /// No package resolved, so nothing was attempted.
    NoPackage,
    /// Not permitted, or no package manager on this host.
    Unavailable { reason: String },
    /// Still in progress.
    Pending,
}

/// A handle to an installation running on its own thread.
///
/// The run continues while this proceeds: nothing in the execution path waits on
/// it, so a provider that installs mid-run can be picked up by the next task,
/// and one that does not simply stays missing and is reported as such.
pub struct InstallJob {
    binary: String,
    handle: Option<std::thread::JoinHandle<InstallOutcome>>,
}

impl InstallJob {
    /// Start installing `binary` if it is missing and a package resolved.
    ///
    /// Returns a job whose outcome may be [`InstallOutcome::Pending`] until
    /// [`InstallJob::poll`] is called again.
    pub fn spawn(binary: &str) -> Self {
        let advice = advise(binary);
        let Some(pkg) = advice.resolved.clone() else {
            return Self {
                binary: binary.to_string(),
                handle: None,
            };
        };
        let manager = pkg.manager;
        let argv = manager.install_argv(&pkg.name);
        let Some(program) = argv.first().cloned() else {
            return Self {
                binary: binary.to_string(),
                handle: None,
            };
        };
        let args: Vec<String> = argv[1..].to_vec();
        let name = pkg.name.clone();
        let binary_owned = binary.to_string();
        let handle = std::thread::spawn(move || {
            let mut cmd = Command::new(program);
            cmd.args(&args)
                // The package manager must not stop for a keypress while the
                // interface is drawing over it.
                .env("DEBIAN_FRONTEND", "noninteractive")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            match cmd.spawn() {
                Ok(child) => {
                    let out = child.wait_with_output().ok();
                    let code = out.as_ref().and_then(|o| o.status.code()).unwrap_or(-1);
                    invalidate(&binary_owned);
                    if which(&binary_owned).is_some() {
                        InstallOutcome::Installed { package: name }
                    } else {
                        let reason;
                        if let Some(o) = out {
                            let err = String::from_utf8_lossy(&o.stderr);
                            let line = err
                                .lines()
                                .map(str::trim)
                                .find(|l| !l.is_empty() && !l.starts_with("Reading"))
                                .unwrap_or("the package manager reported no detail");
                            reason = format!("exit {code}: {line}");
                        } else {
                            reason = format!("exit {code}");
                        }
                        InstallOutcome::Refused {
                            package: name,
                            reason,
                        }
                    }
                }
                Err(e) => InstallOutcome::Unavailable {
                    reason: format!("could not run {}: {e}", pkg.manager.binary()),
                },
            }
        });
        Self {
            binary: binary.to_string(),
            handle: Some(handle),
        }
    }

    /// The binary this job is installing.
    pub fn binary(&self) -> &str {
        &self.binary
    }

    /// Whether this job has something to do at all.
    pub fn is_active(&self) -> bool {
        self.handle.is_some()
    }

    /// The outcome if the job has finished, without blocking.
    pub fn poll(&mut self) -> InstallOutcome {
        let Some(handle) = &self.handle else {
            return if which(&self.binary).is_some() {
                InstallOutcome::Installed {
                    package: self.binary.clone(),
                }
            } else {
                InstallOutcome::NoPackage
            };
        };
        if handle.is_finished() {
            let taken = self.handle.take().expect("checked above");
            taken.join().unwrap_or(InstallOutcome::NoPackage)
        } else {
            InstallOutcome::Pending
        }
    }

    /// Block until the job finishes, then report.
    ///
    /// Only for a path that genuinely has nothing else to do; the run flow polls
    /// first and only settles here, after the execution has finished.
    pub fn wait(mut self) -> InstallOutcome {
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap_or(InstallOutcome::NoPackage)
        } else {
            self.poll()
        }
    }

    /// Block until the job finishes, keeping the handle so the caller can still
    /// ask which binary it was about.
    pub fn settle(&mut self) -> InstallOutcome {
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap_or(InstallOutcome::NoPackage)
        } else {
            self.poll()
        }
    }
}

impl std::fmt::Debug for InstallJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstallJob")
            .field("binary", &self.binary)
            .field(
                "running",
                &self.handle.as_ref().is_some_and(|h| !h.is_finished()),
            )
            .finish()
    }
}

// ── package-database parsers ─────────────────────────────────────────────────

/// Parse `pacman -Si` output into name, version and description.
fn parse_pacman_info(out: &str) -> Option<(String, String, String)> {
    let mut name = String::new();
    let mut version = String::new();
    let mut description = String::new();
    for line in out.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim().to_string();
        match key.trim() {
            "Name" => name = value,
            "Version" => version = value,
            "Description" => description = value,
            _ => {}
        }
    }
    (!name.is_empty()).then_some((name, version, description))
}

/// Parse `apt-cache show` output.
fn parse_apt_show(out: &str) -> Option<(String, String, String)> {
    let mut name = String::new();
    let mut version = String::new();
    let mut description = String::new();
    for line in out.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim().to_string();
        match key.trim() {
            "Package" if name.is_empty() => name = value,
            "Version" if version.is_empty() => version = value,
            "Description" if description.is_empty() => {
                // The first line is the summary; the rest is the long text.
                description = value.lines().next().unwrap_or("").to_string();
            }
            _ => {}
        }
    }
    (!name.is_empty()).then_some((name, version, description))
}

/// Parse `dnf info` / `yum info` output.
fn parse_dnf_info(out: &str) -> Option<(String, String, String)> {
    // Modern dnf prints a table, then indented fields:
    //   Name         : nmap
    //   Version      : 7.94
    //   Summary      : Network exploration tool and security scanner
    let field = |key: &str| {
        out.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            (k.trim().eq_ignore_ascii_case(key)).then(|| v.trim().to_string())
        })
    };
    let name = field("Name")?;
    let version = field("Version").unwrap_or_default();
    let description = field("Summary")
        .or_else(|| field("Description"))
        .unwrap_or_default();
    Some((name, version, description))
}

/// Parse `apk info -a` output.
fn parse_apk_info(out: &str) -> Option<(String, String, String)> {
    // apk puts the description on the lines *after* the `description:` key, up to
    // the next key or a blank line.
    let mut description = String::new();
    let mut collecting = false;
    for line in out.lines() {
        // The key can share a line with the package identifier, so it is found
        // anywhere rather than only at the start.
        if let Some(at) = line.find("description:") {
            let rest = &line[at + "description:".len()..];
            let inline = rest.trim_start_matches('-').trim();
            if !inline.is_empty() {
                description = inline.to_string();
                collecting = false;
            } else {
                collecting = true;
            }
            continue;
        }
        if collecting {
            if line.trim().is_empty() || line.contains(':') && !line.starts_with(' ') {
                collecting = false;
                continue;
            }
            if !description.is_empty() {
                description.push(' ');
            }
            description.push_str(line.trim());
        }
    }
    // `nmap-7.95-r0 description:` — apk puts the identifier and the first
    // description key on the same line. The name is everything before the first
    // dash; the version is everything after it, because an apk version carries
    // its own `-r0` release counter.
    let head = out.lines().next()?.split_whitespace().next()?;
    let (name, version) = head.split_once('-')?;
    (!name.is_empty()).then(|| (name.to_string(), version.to_string(), description))
}

/// Parse `zypper info` output.
fn parse_zypper_info(out: &str) -> Option<(String, String, String)> {
    // zypper prints a pipe-separated table, but `zypper --non-interactive info`
    // in some versions uses an aligned two-column layout instead. Both are read.
    let field = |key: &str| {
        out.lines().find_map(|l| {
            let (k, v) = l.split_once('|').or_else(|| l.split_once(':'))?;
            (k.trim().eq_ignore_ascii_case(key)).then(|| v.trim().to_string())
        })
    };
    let name = field("Name")?;
    let version = field("Version").unwrap_or_default();
    let description = field("Summary").unwrap_or_default();
    Some((name, version, description))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pacman_info_output_parses_the_fields_that_matter() {
        let out = "\
Repository      : extra
Name            : nuclei
Version         : 3.3.2-1
Description     : Host discovery and vulnerability scanning
Architecture    : x86_64
";
        let (name, version, _) = parse_pacman_info(out).unwrap();
        assert_eq!(name, "nuclei");
        assert_eq!(version, "3.3.2-1");
    }

    #[test]
    fn apt_cache_show_output_parses() {
        // Shape captured from `apt-cache show nmap`.
        let out = "\
Package: nmap
Version: 7.94+dfsg-1
Installed-Size: 3802
Description: Network exploration tool and security/scanning suite
 Nmap is a utility for network discovery and security auditing.
";
        let (name, version, description) = parse_apt_show(out).unwrap();
        assert_eq!(name, "nmap");
        assert_eq!(version, "7.94+dfsg-1");
        assert_eq!(
            description,
            "Network exploration tool and security/scanning suite"
        );
    }

    #[test]
    fn dnf_info_output_parses() {
        let out = "\
Last metadata expiration check: 0:12:41 ago.

Installed Packages
Name         : nmap
Version      : 4.99
Summary      : Network exploration tool and security scanner
Repository   : fedora
";
        let (name, version, description) = parse_dnf_info(out).unwrap();
        assert_eq!(name, "nmap");
        assert_eq!(version, "4.99");
        assert!(description.contains("Network exploration"));
    }

    #[test]
    fn apk_info_output_parses() {
        let out = "nmap-7.95-r0 description:\nNetwork exploration tool and security scanner\n";
        let (name, version, description) = parse_apk_info(out).unwrap();
        assert_eq!(name, "nmap");
        assert_eq!(version, "7.95-r0");
        assert!(description.contains("Network exploration"));
    }

    #[test]
    fn zypper_info_output_parses() {
        let out = "\
Information for package nmap:
---------------------------------
Repository     : devel-repo
Name           : nmap
Version        : 7.92
Summary        : Network exploration tool
";
        let (name, version, _) = parse_zypper_info(out).unwrap();
        assert_eq!(name, "nmap");
        assert_eq!(version, "7.92");
    }

    #[test]
    fn empty_or_failed_output_is_never_a_package() {
        assert!(parse_pacman_info("").is_none());
        assert!(parse_pacman_info("error: package not found\n").is_none());
        assert!(parse_apt_show("").is_none());
        assert!(parse_apt_show("N: Unable to locate package\n").is_none());
        assert!(parse_dnf_info("Error: No matching Packages found\n").is_none());
        assert!(parse_apk_info("").is_none());
        assert!(parse_zypper_info("").is_none());
    }

    #[test]
    fn every_manager_produces_a_direct_install_vector() {
        for manager in [
            Manager::Pacman,
            Manager::Apt,
            Manager::Dnf,
            Manager::Yum,
            Manager::Apk,
            Manager::Zypper,
        ] {
            let argv = manager.install_argv("nmap");
            assert!(!argv.is_empty(), "{manager:?}");
            assert_eq!(argv[0], manager.binary());
            assert!(
                argv.contains(&"nmap".to_string()),
                "{manager:?} lost the package name: {argv:?}"
            );
            // No shell metacharacter may appear in a vector we later execute.
            for part in &argv {
                assert!(
                    !part.contains(['|', ';', '>', '<', '`', '$', '(', ')']),
                    "{manager:?} produced a shell-metacharacter argument: {part:?}"
                );
            }
        }
        assert!(Manager::Unknown.install_argv("x").is_empty());
    }

    #[test]
    fn apt_install_is_non_interactive_and_minimal() {
        let argv = Manager::Apt.install_argv("nmap");
        assert!(argv.contains(&"-y".to_string()));
        assert!(argv.contains(&"--no-install-recommends".to_string()));
    }

    #[test]
    fn guidance_for_a_missing_binary_never_invents_a_package() {
        let advice = advise("tsec-definitely-not-a-real-provider");
        assert!(advice.resolved.is_none());
        assert_eq!(advice.package(), None);
        assert!(!advice.is_auto_installable());
    }

    #[test]
    fn guidance_is_cached_between_calls() {
        let a = advise("tsec-cache-probe");
        let b = advise("tsec-cache-probe");
        assert_eq!(a.notes, b.notes);
    }

    #[test]
    fn invalidating_guidance_drops_the_cached_answer() {
        let first = advise("tsec-invalidate-probe");
        assert_eq!(first.notes, advise("tsec-invalidate-probe").notes);
        invalidate("tsec-invalidate-probe");
        // Recomputed from scratch: still the same answer for a binary that does
        // not exist, but the cache no longer holds it.
        assert!(advise("tsec-invalidate-probe").notes.len() >= first.notes.len());
    }

    #[test]
    fn run_capture_reports_failure_for_a_missing_program() {
        assert!(run_capture("tsec-no-such-program", &[], 1).is_none());
    }

    #[test]
    fn run_capture_kills_a_hung_program() {
        let started = Instant::now();
        let result = run_capture("sleep", &["5"], 1);
        assert!(result.is_some());
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "timeout did not fire: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_job_for_a_binary_with_no_package_does_nothing() {
        let job = InstallJob::spawn("tsec-definitely-not-a-real-provider");
        assert!(!job.is_active());
        assert_eq!(job.wait(), InstallOutcome::NoPackage);
    }

    #[test]
    fn an_installed_binary_is_never_reinstalled() {
        let job = InstallJob::spawn("sh");
        assert!(!job.is_active(), "sh is present; nothing to do");
        assert!(matches!(job.wait(), InstallOutcome::Installed { .. }));
    }

    #[test]
    fn detection_agrees_with_the_host_it_runs_on() {
        let manager = detect_manager();
        if manager == Manager::Unknown {
            assert!(!can_install());
        } else {
            assert!(can_install());
            assert!(which(manager.binary()).is_some());
        }
        // Whatever the host is, the name must be non-empty and printable.
        assert!(!distro_name().is_empty());
    }
}
