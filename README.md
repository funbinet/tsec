# TSEC

**Tactical Security Enumeration & Compromise Framework**

A target-driven security framework organised around ten fixed phases. You pick a
*capability* — "PORT DISCOVERY", "TEMPLATE SCAN", "DNS RESOLUTION" — not a tool.
The framework resolves which providers implement it, verifies their command
syntax against the installed binaries, executes them behind an isolated network
boundary, and consolidates their output into one provenance-rich harvest.

---

## Table of contents

- [What makes this different](#what-makes-this-different)
- [The network boundary: oniux](#the-network-boundary-oniux)
- [Requirements](#requirements)
- [Installation](#installation)
- [The ten phases](#the-ten-phases)
- [Using the framework](#using-the-framework)
- [What a run produces](#what-a-run-produces)
- [Configuration](#configuration)
- [Command syntax is verified, not assumed](#command-syntax-is-verified-not-assumed)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

---

## What makes this different

**Capabilities, not tools.** A phase contains capabilities; a capability names
the providers that implement it and the exact argv for each. Nothing about a
tool's flags is written in Rust, so a tool's interface can change without
touching framework code.

**Only verified syntax is offered.** A provider is offered only when its
executable resolves *and* the flags the catalog uses appear in that installed
binary's own `--help` output. `scripts/verify_catalog.py` checks this
independently, and `catalog/verification.json` records the result. A capability
whose tools are missing reports itself unavailable with a reason — it is never
silently offered, and never substituted.

**No shell, ever.** Every command is an argument vector. A template containing
`|`, `>` or `&&` is rejected when the catalog loads rather than quietly
mis-executed. Shell *metacharacters inside a single argument* are passed to the
tool literally, not interpreted.

**Nothing is invented.** The parser turns raw output into findings only from
facts a tool actually reported. Each finding keeps the tool's own wording and
carries the provider, command, timestamp and artifact file it came from. Output
the framework cannot interpret is kept as evidence, never dropped.

**Secrets stay out of the evidence.** Arguments declared sensitive are masked in
every rendering, record and report, so a credential never reaches a log file or
a JSON report.

---

## The network boundary: oniux

**Every network-capable command runs through
[oniux](https://gitlab.torproject.org/tpo/core/oniux).** This is an architectural
invariant, not a setting.

```
oniux <tool> <args…>
```

oniux drops the tool into its own network, mount, PID and user namespace, creates
a `onion0` TUN device wired to an embedded Tor (Arti) client, and replaces
`/etc/resolv.conf` with a Tor-aware resolver. The tool therefore has **no route
to the host network at all** — unlike a SOCKS proxy, a tool that ignores its
proxy environment variable still cannot reach the internet.

What this means in practice:

| Situation | What TSEC does |
|---|---|
| oniux missing | Every network task **fails**. It never runs directly. |
| oniux present but broken (no `tun`, no user namespaces) | Preflight **fails loudly** before any tool runs. |
| oniux fails mid-run | The task fails with oniux's own error. Still no fallback. |
| Command is genuinely local (reads a local file) | Runs directly, still as an argv, in its own process group. |

There is **no anonymity toggle, no anonymity mode, and no ON/OFF switch**, by
design. Anonymity is not a feature this framework offers; the framework simply
assumes its network-capable execution boundary is oniux and enforces that.
Tor itself is configured and supervised entirely outside the framework.

Commands **default to network-capable** and must be explicitly marked
`.local()` to run without oniux. The two possible mistakes are not symmetric: a
command wrongly sent through oniux costs a little performance, while a network
command wrongly marked local puts a scan on the host network.

### Setting up oniux

```sh
# Arch / AUR
paru -S oniux

# or from source (v0.4.0 is the version TSEC is written against)
cargo install --git https://gitlab.torproject.org/tpo/core/oniux --tag v0.4.0 oniux
```

oniux needs the `tun` module and unprivileged user namespaces:

```sh
sudo modprobe tun
# on distributions that restrict them:
#   kernel.unprivileged_userns_clone = 1
#   kernel.apparmor_restrict_unprivileged_userns = 0
```

Verify the boundary yourself:

```sh
oniux /bin/true && echo "boundary works"
```

TSEC runs that exact probe automatically before the first network task, and
reports the result on its `BOUNDARY` line.

> **Note on versions.** oniux v0.4.0 accepts *no options at all* — its entire
> interface is `oniux [command] [args...]`. Newer versions (main) add `-p`, `-c`
> and `-l`. TSEC deliberately injects none of them, so its argv is valid across
> versions.

---

## Requirements

- **Linux** (oniux is Linux-only; the framework is written against it)
- **Rust** 1.82 or newer
- **oniux** — the network boundary. Required for any network capability.
- Optional provider tools — see [`REQUIREMENTS.TXT`](REQUIREMENTS.TXT)

A missing provider tool degrades gracefully: the capabilities that need it
report themselves unavailable, with the reason. A missing oniux does not — it
stops every network task, by design.

---

## Installation

```sh
sudo ./install.sh
```

The installer builds the release binary, installs it to `/usr/bin/tsec`, creates
the workspace at `/opt/tsec`, and then installs or verifies **oniux**, loading
the `tun` module and warning if unprivileged user namespaces are disabled.

Manual build:

```sh
cargo build --release --offline
sudo cp target/release/tsec /usr/bin/tsec
```

---

## The ten phases

| # | Phase | What it establishes |
|---|---|---|
| 1 | `RECON` | Hosts and subdomains, from registries, search and certificates |
| 2 | `SURFACE` | Open ports, services, HTTP endpoints, technology fingerprints |
| 3 | `VULNERABILITY` | Which of those findings are actually exploitable |
| 4 | `PAYLOAD` | Building and delivering proof-of-concept payloads |
| 5 | `ESCALATION` | Turning limited access into more of it |
| 6 | `CREDENTIALS` | Finding, correlating and validating credentials |
| 7 | `LATERAL` | Moving between hosts and trusts |
| 8 | `PERSISTENCE` | Surviving a reboot or a rebuild |
| 9 | `OBJECTIVES` | The specific goal: data, secrets, the flag |
| 10 | `WIRELESS` | 802.11 networks, clients and handshakes |

Phases run in that order and each consumes what the previous ones established.

The current authored catalog populates recon, surface, vulnerability,
credentials, lateral, objectives and wireless. Payload, escalation and
persistence are present as phases with no capabilities yet — they are
deliberately empty rather than filled with unverified commands.

---

## Using the framework

```sh
tsec
```

On startup TSEC reports which capabilities are available and whether the oniux
boundary is present:

```
tsec 3.0.0 · no colour (not a tty)
15/15 available · subfinder not installed
  RECON          2/2 available
  SURFACE        3/3 available
  BOUNDARY       /usr/bin/oniux
```

Pick a phase, pick a capability, answer the inputs it declares, and confirm.
TSEC then:

1. resolves the providers and checks their installed versions
2. builds each provider's argv from the catalog, substituting your inputs
3. rejects any template that would need a shell
4. probes the oniux boundary
5. runs the tools concurrently, each in its own process group and its own oniux
   namespace, capturing stdout and stderr to separate files
6. parses the output into findings, deduplicates them, and records every source
7. writes the manifest, the raw evidence and the consolidated harvest

`Ctrl+C` cancels safely: running tools are terminated as process groups, and
everything gathered so far is preserved.

---

## What a run produces

```
/opt/tsec/output/<run-id>/
  manifest.json     every execution record: command, boundary, status, timings
  harvest.txt       consolidated, deduplicated, human-readable findings
  harvest.json      the same findings, structured, with full provenance
  run.json          phase/capability/run summary
  raw/T01.out       each tool's stdout, byte-for-byte
  raw/T01.err       each tool's stderr
```

Every write is atomic — a temporary file in the same directory, then a rename —
so an interrupted run leaves either the old file or the new one, never a
truncated harvest. Raw output is never rewritten by the parser, so any finding
can be checked against the bytes that produced it.

A finding records which tools reported it:

```
80/tcp  open — on 80/tcp [naabu, nmap]
Python  version 3.14.7 [nmap]
```

---

## Configuration

`/opt/tsec/config/config.toml`:

```toml
[general]
output_dir    = "/opt/tsec/output"
log_dir       = "/opt/tsec/logs"
preview_lines = 500
color         = "auto"
keep_raw      = true

[execution]
max_concurrency  = 6
timeout_secs     = 300
oniux_binary     = "oniux"     # the network boundary
kill_grace_ms    = 2000
```

`oniux_binary` is the only network-related setting, and it names *where* the
boundary is — not whether it applies. There is no way to turn the boundary off.

A v2 configuration still loads: the old `[anonymity]` section, `torsocks_binary`
and `tor_socks_proxy` keys describe a SOCKS proxy, which oniux is not, so they
are dropped rather than translated. Everything else is preserved.

---

## Command syntax is verified, not assumed

Every flag in the catalog was checked against a real binary's help output.

```sh
# re-verify the authored catalog against the installed tools
python3 scripts/verify_catalog.py

# re-verify every legacy provider inventory entry
python3 scripts/verify_providers.py
```

The verifier reports unknown flags, missing subcommands and uninstalled
providers. A capability is only offered if its operations verify.

---

## Troubleshooting

**"Oniux network boundary required … is unavailable"** — oniux is missing or
cannot start. Check:

```sh
command -v oniux && oniux /bin/true
sudo modprobe tun
sysctl kernel.unprivileged_userns_clone      # must be 1
```

A non-zero exit from `oniux /bin/true` with a message about the TUN device means
the `tun` module is not loaded; a message about namespaces means unprivileged
user namespaces are disabled. TSEC reports oniux's own error text verbatim — it
is the authoritative description of what failed.

**Capability reported unavailable** — its provider is not installed, or the
installed version does not document the flags the catalog uses. The reason is
printed with the capability.

**A task fails with `ONIUX_UNAVAILABLE`** — the boundary could not be proven
usable, so the engine refused to start the tool. The task did **not** run on the
host network; it did not run at all. The engine runs this check itself before
every network task and it cannot be turned off, so this error means the boundary
was already unusable when the task was reached. Fix oniux and start a new run.
The check happens once per run however many tasks follow, so a burst of
concurrent tasks costs one probe, not twenty.

**Nothing is happening during a run** — each network tool boots its own Tor
client inside its own namespace. That is the isolation model, and the first boot
after a machine starts is the slowest. See `docs/TROUBLESHOOTING.md`.

---

## Development

```sh
cargo fmt -- --check
cargo clippy --offline --all-targets -- -D warnings
cargo test --offline
cargo build --offline --release
python3 scripts/verify_catalog.py
```

`tests/execution_boundary_audit.rs` reads the framework's own source and fails
the build if a second spawn site ever appears, if a network command can be
planned unwrapped, or if an anonymity toggle is reintroduced. `tests/oniux_integration.rs`
runs against the *installed* oniux and skips when it is absent; set
`TSEC_REQUIRE_ONIUX=1` to make its absence a failure instead, which is what CI
should do.

- `docs/ARCHITECTURE.md` — how the layers fit together and why
- `docs/TROUBLESHOOTING.md` — failure modes and what they mean
- `catalog/inventory.json` — the full legacy tool inventory
- `catalog/verification.json` — the provider verification snapshot

---

## Licence

MIT.
