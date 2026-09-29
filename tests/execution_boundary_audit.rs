//! A mechanical audit of the network-execution boundary.
//!
//! "Oniux is an architectural invariant" is a claim, and claims rot. These
//! tests read the repository's own source and fail if the claim stops being
//! true — if a second spawn site appears, if a network command can be built
//! without a boundary, or if the legacy proxy configuration creeps back.
//!
//! They are deliberately source-level rather than behavioural: a behavioural test
//! can only prove the paths it thought to exercise.

use std::path::{Path, PathBuf};

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rust_sources() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![crate_root().join("src")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()))
}

/// Production lines of `p`: everything before the file's `#[cfg(test)]` module.
///
/// A test that spawns `/bin/echo` to prove the runner captures output is not a
/// bypass of anything. Production code that spawns without the boundary is.
fn production_lines(p: &Path) -> Vec<String> {
    let text = read(p);
    let cut = text
        .find("#[cfg(test)]")
        .map(|byte| text[..byte].lines().count())
        .unwrap_or_else(|| text.lines().count());
    text.lines()
        .take(cut)
        .map(str::trim)
        .filter(|l| !l.starts_with("//") && !l.starts_with('*'))
        .map(str::to_string)
        .collect()
}

#[test]
fn there_is_exactly_one_tool_spawn_site_in_the_engine() {
    // Any process spawn must go through Runner::run, which consults the launcher.
    let mut spawns = Vec::new();
    for src in rust_sources() {
        for line in production_lines(&src) {
            if line.contains(".spawn()") {
                spawns.push(format!("{}: {}", src.display(), line));
            }
        }
    }
    assert_eq!(
        spawns.len(),
        2,
        "expected exactly two spawns — the tool spawn in exec/mod.rs and the oniux \
         preflight probe in exec/oniux.rs — but found:\n{}",
        spawns.join("\n")
    );

    let (tool, probe): (Vec<_>, Vec<_>) = spawns.iter().partition(|s| s.contains("exec/mod.rs"));
    assert_eq!(tool.len(), 1, "one tool spawn expected: {tool:?}");
    assert_eq!(probe.len(), 1, "one oniux probe spawn expected: {probe:?}");
}

#[test]
fn the_tool_spawn_is_only_reachable_through_a_launch() {
    let mod_rs = read(&crate_root().join("src/exec/mod.rs"));
    let spawn_at = mod_rs.find(".spawn()").expect("the tool spawn site");

    // The `Command` builder call sits immediately before the spawn it feeds.
    // The process builder must name the launch, never the domain command.
    // `DomainCommand::new` also contains the substring "Command::new(", so the
    // assertion is on the full, unambiguous expression.
    let build_at = mod_rs
        .find("Command::new(&launch.program)")
        .expect("the process Command must be built from the launch");
    let region = &mod_rs[build_at..spawn_at];
    assert!(
        region.contains(".args(&launch.args)"),
        "the spawned args must come from the launch"
    );
    assert!(
        !region.contains("cmd.program()") && !region.contains("cmd.args()"),
        "the spawn must not read the domain command directly, only the launch"
    );

    // And the plan call must precede it, so wrapping happens before any process
    // object exists.
    let plan_at = mod_rs
        .find("self.launcher.plan(cmd)")
        .expect("the launcher must plan the command");
    assert!(
        plan_at < build_at,
        "the command must be routed before a process is built for it"
    );
}

#[test]
fn the_launcher_has_no_path_that_returns_an_unwrapped_network_command() {
    let src = read(&crate_root().join("src/exec/launch.rs"));
    let plan = src
        .split("pub fn plan")
        .nth(1)
        .expect("Launcher::plan exists")
        .split("\n    }")
        .next()
        .expect("plan body");

    // The local branch is guarded on the command not being network-capable.
    assert!(
        plan.contains("if !cmd.is_network()"),
        "the direct-execution branch must be guarded by !is_network()"
    );
    // The network branch resolves oniux before wrapping.
    assert!(
        plan.contains("self.backend.resolve()?"),
        "the network branch must resolve the boundary"
    );
    // And the wrapped result is what gets returned for a network command.
    assert!(
        plan.contains("boundary: Boundary::Oniux"),
        "a network command must be planned behind the oniux boundary"
    );
}

#[test]
fn commands_default_to_the_network_boundary() {
    let src = read(&crate_root().join("src/domain/command.rs"));
    // Scope to `impl Command` so `CommandError::new` is not mistaken for it.
    let impl_block = src
        .split("impl Command {")
        .nth(1)
        .expect("impl Command exists");
    let new_body = impl_block
        .split("pub fn new(")
        .nth(1)
        .expect("Command::new exists")
        .split("\n    }")
        .next()
        .expect("new body");
    assert!(
        new_body.contains("network: true"),
        "a new command must default to the oniux boundary, not to running directly"
    );
}

#[test]
fn no_production_source_refers_to_the_retired_proxy_configuration() {
    // `torsocks` / `tor_socks` may appear only in the config migration that
    // deliberately drops those keys, and in prose explaining that history.
    for src in rust_sources() {
        if src.file_name().is_some_and(|n| n == "model.rs") {
            continue; // the legacy-key migration, asserted on below
        }
        for line in production_lines(&src) {
            assert!(
                !(line.contains("torsocks") || line.contains("tor_socks")),
                "{} still references the retired proxy configuration: {}",
                src.display(),
                line
            );
        }
    }
}

#[test]
fn the_config_migration_still_drops_the_retired_proxy_keys() {
    // The one place allowed to name them, and only to remove them.
    let src = read(&crate_root().join("src/config/model.rs"));
    let body: String = production_lines(&crate_root().join("src/config/model.rs")).join("\n");
    for key in ["torsocks_binary", "tor_socks_proxy"] {
        assert!(
            body.contains(&format!("exec.remove(\"{key}\")")),
            "the migration must still drop {key}"
        );
    }
    assert!(
        body.contains("root.remove(\"anonymity\")"),
        "the migration must still drop the [anonymity] section"
    );
    let _ = src;
}

#[test]
fn there_is_no_anonymity_toggle_in_production_code() {
    // Anonymity is not a feature this framework offers. A config key, a command
    // flag or a struct field that turns it on or off must not exist. Legacy key
    // names may survive only inside the migration that deletes them.
    for src in rust_sources() {
        for line in production_lines(&src) {
            for banned in [
                "anonymity_enabled",
                "anonymity:",
                "tor_enabled",
                "kill_switch",
                "proxy_overrides",
            ] {
                assert!(
                    !line.contains(banned),
                    "{} reintroduces an anonymity/proxy control: {}",
                    src.display(),
                    line
                );
            }
        }
    }
}

#[test]
fn every_network_catalog_operation_is_marked_as_network_capable() {
    // A catalog operation that talks to a host or a URL must not be declared
    // local. Only the genuinely local tools may be.
    let toml = read(&crate_root().join("catalog/capabilities.toml"));
    let allowed_local = ["john", "hashcat", "find", "grep", "sqlite3", "airmon-ng"];

    let mut current_binary = String::new();
    let mut checked = 0usize;
    for line in toml.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("binary = \"") {
            current_binary = rest.trim_end_matches('"').to_string();
        }
        if t == "network = false" {
            checked += 1;
            assert!(
                allowed_local.contains(&current_binary.as_str()),
                "operation for {current_binary} is marked network = false, but only \
                 genuinely local tools may be: {allowed_local:?}"
            );
        }
    }
    assert!(checked > 0, "expected some local operations to be declared");
}

#[test]
fn the_error_taxonomy_names_the_boundary_rather_than_a_proxy() {
    let src = read(&crate_root().join("src/error.rs"));
    assert!(
        src.contains("ONIUX_UNAVAILABLE"),
        "the boundary needs its own code"
    );
    assert!(
        !src.contains("PROXY_UNAVAILABLE"),
        "the retired proxy error code must not come back"
    );
}
