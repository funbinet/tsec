//! Command executor — builds, validates, and runs external commands.

use anyhow::{bail, Result};
use std::collections::HashMap;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Result of a command execution.
#[derive(Debug)]
pub struct ExecResult {
    pub stdout:    String,
    pub stderr:    String,
    pub exit_code: i32,
    pub duration:  Duration,
}

/// Replace all `{placeholder}` tokens in a command template.
///
/// `inputs`  — map from placeholder name to user-supplied value.
/// `out`     — value to substitute for `{output_file}`.
/// `ts`      — value to substitute for `{timestamp}`.
pub fn build_command(
    template:  &str,
    inputs:    &HashMap<String, String>,
    out:       &str,
    ts:        &str,
) -> String {
    let mut cmd = template.to_string();
    for (key, val) in inputs {
        cmd = cmd.replace(&format!("{{{key}}}"), val);
    }
    cmd = cmd.replace("{output_file}", out);
    cmd = cmd.replace("{timestamp}", ts);
    cmd
}

/// Check whether `binary` is on PATH using `which`.
pub fn check_binary(binary: &str) -> bool {
    std::process::Command::new("which")
        .arg(binary)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run `cmd` through `sh -c`, enforcing `timeout_secs`.
/// Delegates to `run_command_with_env` with no extra env vars.
pub fn run_command(cmd: &str, timeout_secs: u64) -> Result<ExecResult> {
    run_command_with_env(cmd, timeout_secs, &HashMap::new())
}

/// Run `cmd` through `sh -c`, enforcing `timeout_secs`, with additional
/// environment variables injected into the child process.
///
/// The command is executed on a worker thread. If the timeout fires the
/// thread is abandoned (the child process continues briefly) and an error
/// is returned — acceptable for a v1 sequential tool.
pub fn run_command_with_env(
    cmd: &str,
    timeout_secs: u64,
    env_vars: &HashMap<String, String>,
) -> Result<ExecResult> {
    let start = Instant::now();
    let cmd_owned = cmd.to_string();
    let env_owned = env_vars.clone();
    let (tx, rx) = mpsc::channel::<Result<ExecResult>>();

    thread::spawn(move || {
        let mut command = std::process::Command::new("sh");
        command.arg("-c").arg(&cmd_owned);

        // Inject anonymity environment variables
        for (key, val) in &env_owned {
            command.env(key, val);
        }

        let result = command.output();

        let res = match result {
            Ok(out) => Ok(ExecResult {
                stdout:    String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr:    String::from_utf8_lossy(&out.stderr).into_owned(),
                exit_code: out.status.code().unwrap_or(-1),
                duration:  start.elapsed(),
            }),
            Err(e) => Err(anyhow::anyhow!("Failed to spawn command: {e}")),
        };
        let _ = tx.send(res);
    });

    if timeout_secs == 0 {
        match rx.recv() {
            Ok(res) => res,
            Err(_) => bail!("Command thread disconnected unexpectedly")
        }
    } else {
        match rx.recv_timeout(Duration::from_secs(timeout_secs)) {
            Ok(res) => res,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                bail!("Command timed out after {timeout_secs}s")
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                bail!("Command thread disconnected unexpectedly")
            }
        }
    }
}

/// Install hint for a missing binary (best-effort).
pub fn install_hint(binary: &str) -> String {
    // Common package name overrides.
    let pkg = match binary {
        "rustscan"       => "rustscan",
        "eyewitness"     => "eyewitness",
        "theHarvester"   => "theharvester",
        "reconftw.sh"    => "reconftw",
        "sniper"         => "sn1per",
        "paramspider"    => "paramspider",
        "knockpy"        => "knockpy",
        other            => other,
    };
    // For Arch Linux, suggest pacman, yay, or go install
    let arch_pkg = match binary {
        "httpx-pd" => "httpx-bin (yay) or go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "subfinder" => "subfinder (pacman) or go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "amass" => "amass (pacman)",
        "dnsx" => "dnsx-bin (yay) or go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "naabu" => "naabu (yay) or go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "tlsx" => "tlsx-bin (yay) or go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
        "katana" => "katana-bin (yay) or go install github.com/projectdiscovery/katana/cmd/katana@latest",
        "nuclei" => "nuclei (pacman) or go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "rustscan" => "rustscan (yay)",
        "theHarvester" => "theharvester (pacman)",
        "ffuf" => "ffuf (pacman)",
        "gobuster" => "gobuster (pacman)",
        _ => pkg,
    };
    format!("sudo pacman -S {pkg}   OR   yay -S {arch_pkg}")
}

