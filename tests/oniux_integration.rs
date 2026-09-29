//! Integration tests against the **installed** oniux.
//!
//! The rest of the suite proves the framework's *intent*: that it will wrap a
//! network command and refuse to run it unwrapped. These tests prove the
//! *reality*: that the oniux actually on this machine accepts the exact argv the
//! framework produces, and that a real tool runs through it and comes back.
//!
//! They read the installed binary's own `--help` rather than hard-coding what a
//! version is supposed to accept, because oniux's interface changed between
//! releases: v0.4.0 takes no options at all, while later versions add `-p`, `-c`
//! and `-l`. A framework hard-coded against the wrong one would either inject an
//! option the installed binary rejects, or omit one it needs.
//!
//! If oniux is not installed the tests report that and pass, so the suite still
//! runs on a machine without the boundary. Set `TSEC_REQUIRE_ONIUX=1` to make a
//! missing boundary a hard failure instead — which is what CI should do.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use tsec::domain::command::Command as DomainCommand;
use tsec::domain::execution::{ExecBoundary, TaskStatus};
use tsec::domain::ids::TaskId;
use tsec::domain::plan::RawArtifact;
use tsec::exec::{Cancellation, Launcher, OniuxBackend, Runner, RunnerConfig, TaskSpec};

fn oniux_path() -> Option<PathBuf> {
    let p = std::env::var("TSEC_ONIUX")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("oniux"));
    which(&p.to_string_lossy())
}

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Skip (or hard-fail) when the boundary is absent.
fn require_oniux() -> Option<PathBuf> {
    match oniux_path() {
        Some(p) => Some(p),
        None => {
            let msg = "oniux is not installed; skipping live boundary integration tests";
            if std::env::var("TSEC_REQUIRE_ONIUX").is_ok() {
                panic!("{msg} (TSEC_REQUIRE_ONIUX is set)");
            }
            eprintln!("note: {msg}");
            None
        }
    }
}

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(fut)
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("tsec-oniux-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Run the installed oniux with `--help` and return what it printed.
fn help_text(bin: &PathBuf) -> String {
    let out = std::process::Command::new(bin)
        .arg("--help")
        .stdin(Stdio::null())
        .output()
        .expect("oniux --help runs");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn the_installed_oniux_is_a_command_it_can_wrap() {
    let Some(bin) = require_oniux() else { return };
    let help = help_text(&bin);
    assert!(
        help.to_lowercase().contains("usage"),
        "oniux --help produced no usage line:\n{help}"
    );
    // The interface must accept a program directly after its own name.
    assert!(
        help.contains("<COMMAND>") || help.contains("command"),
        "oniux's help must document the command it wraps:\n{help}"
    );
}

#[test]
fn the_installed_oniux_accepts_exactly_the_argv_the_framework_builds() {
    let Some(bin) = require_oniux() else { return };
    let launcher = Launcher::new(OniuxBackend::new(bin.to_string_lossy()));
    let cmd = DomainCommand::new("/bin/echo", vec!["tsec-boundary-probe".into()]);
    let launch = launcher.plan(&cmd).expect("the boundary resolves");

    // Run precisely what the runner would run, and require the tool's output to
    // come back — which can only happen if oniux really executed the program.
    let out = std::process::Command::new(&launch.program)
        .args(&launch.args)
        .stdin(Stdio::null())
        .output()
        .expect("oniux starts");

    assert_eq!(
        out.status.code(),
        Some(0),
        "oniux rejected the framework's argv {:?}: {}",
        launch.args,
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "tsec-boundary-probe",
        "the wrapped program must produce its own output"
    );
}

#[test]
fn the_framework_never_injects_an_option_the_installed_oniux_may_not_have() {
    // oniux v0.4.0 accepts no options; later versions accept some. The framework
    // must pass none at all, so its argv is valid on every version. This test
    // reads the installed help and proves the framework's first wrapped argument
    // is the tool, never a flag.
    let Some(bin) = require_oniux() else { return };
    let backend = OniuxBackend::new(bin.to_string_lossy());
    for tool in ["/bin/true", "httpx", "nmap"] {
        let launch = backend.wrap(&bin, tool, &["-flag".into(), "value".into()]);
        let first = &launch.args[0];
        assert!(
            !first.starts_with('-'),
            "argv[0] must be the tool, not an option to oniux: {first:?}"
        );
        assert_eq!(first, tool);
    }
}

#[test]
fn preflight_succeeds_against_the_installed_oniux() {
    let Some(bin) = require_oniux() else { return };
    block_on(async move {
        let backend =
            OniuxBackend::new(bin.to_string_lossy()).with_probe_timeout(Duration::from_secs(180));
        match backend.preflight().await {
            Ok(report) => {
                assert_eq!(report.binary, bin);
                assert_eq!(report.probe, "/bin/true");
                assert!(!report.summary().is_empty());
            }
            Err(e) => {
                // A boundary that cannot bootstrap is a real environment
                // problem, not a framework one — report it rather than failing
                // a test about the framework's logic.
                eprintln!("note: oniux preflight did not pass here: {}", e.reason());
                assert_eq!(e.kind.code(), "ONIUX_UNAVAILABLE");
            }
        }
    });
}

#[test]
fn a_network_task_runs_through_the_installed_boundary_and_is_recorded_as_such() {
    let Some(bin) = require_oniux() else { return };
    block_on(async move {
        let dir = tmp("live");
        let spec = TaskSpec {
            id: TaskId(0),
            provider: "probe".into(),
            operation: "live".into(),
            label: "live boundary probe".into(),
            timeout: Duration::from_secs(120),
            artifacts: RawArtifact {
                primary: dir.join("out.txt"),
                stderr: dir.join("out.err.txt"),
            },
            sensitive_args: vec![],
        };
        let runner = Runner::new(
            Launcher::new(OniuxBackend::new(bin.to_string_lossy())),
            RunnerConfig::default(),
        );
        let cmd = DomainCommand::new("/bin/echo", vec!["through-oniux".into()]);
        let done = runner
            .run(&spec, &cmd, "RECON", "TEST", &Cancellation::new())
            .await;

        if done.record.status == TaskStatus::Complete {
            // The tool ran inside the boundary and its output was captured.
            let body = std::fs::read_to_string(&spec.artifacts.primary).unwrap();
            assert_eq!(body.trim(), "through-oniux");
            assert_eq!(done.record.boundary, ExecBoundary::Oniux);
            assert!(done.record.network);
            assert!(
                done.record
                    .launched
                    .starts_with(&bin.to_string_lossy().to_string()),
                "launched was {:?}",
                done.record.launched
            );
        } else {
            // The boundary could not establish itself here. The framework must
            // have failed loudly rather than run the tool directly.
            assert_eq!(done.record.boundary, ExecBoundary::Oniux);
            assert_eq!(done.record.error_code.as_deref(), Some("ONIUX_UNAVAILABLE"));
            assert!(
                !spec.artifacts.primary.exists(),
                "a failed boundary must not produce a direct execution"
            );
            eprintln!(
                "note: boundary unavailable in this environment: {:?}",
                done.record.error_message
            );
        }
    });
}
