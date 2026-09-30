# TSEC 3.0

**Tactical Security Enumeration & Compromise Framework** — a terminal platform
for authorised red-team and security-assessment work.

TSEC 3.0 is capability-first. An operator chooses *what to accomplish* — `PORT
DISCOVERY`, `HARVEST HASHES`, `HANDSHAKE CAPTURE` — and the framework knows which
tools implement it and exactly how to invoke each one. Nothing about a tool's
flags is written in Rust; all of it lives in one reviewed file,
[`catalog/capabilities.toml`](catalog/capabilities.toml).

The framework is organised as **ten phases, sixteen capabilities each**. Every
phase is mandatory: a catalog that leaves one empty is rejected at startup
rather than shipped half-finished.

| # | Phase | | # | Phase |
|---|---|---|---|---|
| 01 | `RECON` | | 06 | `CREDENTIALS` |
| 02 | `SURFACE` | | 07 | `LATERAL` |
| 03 | `VULNERABILITY` | | 08 | `PERSISTENCE` |
| 04 | `PAYLOAD` | | 09 | `OBJECTIVES` |
| 05 | `ESCALATION` | | 10 | `WIRELESS` |

---

## Requirements

- Linux with a TTY (the interface is interactive; `--status` works anywhere).
- Rust 1.82 or newer to build.
- **oniux** — the network-execution boundary. Every network-capable command is
  launched as `oniux <tool> <args…>`. Without it, no network capability can run
  at all. See [`REQUIREMENTS.TXT`](REQUIREMENTS.TXT).
- The provider tools themselves, which are optional: a capability whose tools are
  missing says so, by name, and stays out of the way.

```sh
cargo build --release
sudo ./install.sh          # installs /usr/bin/tsec and /opt/tsec/{catalog,config,…}
```

Running from a checkout works with no install at all:

```sh
TSEC_HOME="$PWD" cargo run --release
```

## Launching

```sh
tsec                 # the interface
tsec --status        # availability per phase, and the network boundary
tsec --version
tsec --help
```

## Driving the interface

Every screen is one centred box: a one-word title, the choices that belong to
it, and `-[ENTER]` underneath when Enter makes a selection. There is no
numbering, no breadcrumb and no status badge anywhere.

| Key | Action |
|---|---|
| `I` / `↑` | move up |
| `K` / `↓` | move down |
| `J` / `←` | back — closes the current box |
| `L` / `→` / `Enter` / `Space` | select |
| `Esc` | exit / close |
| `Ctrl+C` | leave immediately; a running task's process group is terminated |

The top level lists the ten phases plus two screens:

- **`STATUS`** — version, theme, catalog size, live availability per phase, and
  whether the oniux boundary resolves.
- **`OUTPUTS`** — previous runs. Selecting one reads its consolidated harvest
  back; nothing is re-executed.

A capability whose providers are missing is still listed, drawn dimmed, and
cannot be selected — move onto it and the box says which binary is absent.

## Running a capability

1. The capability's box appears, with its summary.
2. Each declared input is prompted for, validated against its declared type
   (`domain`, `target`, `url`, `ports`, `path`, `secret`, `mac`, …). Sensitive
   inputs are masked everywhere they could otherwise be displayed or recorded.
3. Every provider operation runs concurrently, bounded by
   `execution.max_concurrency`. Each runs behind oniux.
4. `OUTPUTS` reports how the tasks ended — complete, failed, interrupted and the
   error codes — then the deduplicated findings, then where the evidence went.

A task that fails is never silently dropped. A tool that exits non-zero, times
out, or is refused by the boundary still produces a record, its raw stderr, and
a line in the harvest.

## The catalog

One file describes the whole operational surface. A capability declares the
inputs it needs and, for each provider, the argument vectors that implement it:

```toml
[[capability]]
id = "recon.subdomain-discovery"
phase = "recon"
label = "SUBDOMAIN DISCOVERY"
summary = "Passive and permutation subdomain enumeration across public sources"
inputs = [
  { key = "domain", type = "domain", required = true, help = "Root domain to enumerate, e.g. example.com" },
]
[[capability.provider]]
binary = "subfinder"
[[capability.provider.operation]]
name = "Passive Enumeration"
args = ["-d", "{domain}", "-silent"]
output = "lines"
network = true
```

The loader enforces, at startup:

- **`phase`** is one of the ten phases, and every phase holds capabilities.
- **`label`** is exactly two uppercase words — it is what the box shows.
- Every **`{placeholder}`** names a declared input, so a renamed input fails
  loudly instead of reaching a tool as a literal `{target}`.
- Arguments may not contain **shell syntax** (`|`, `&`, `;`, `<`, `>`, `` ` ``,
  `$`, `(`, `)`); a template containing any of it is a catalog error, because
  arguments are executed as a vector and never through a shell.
- `{{` and `}}` are literal braces, `%{…}` is printf-style literal text
  (curl's `%{http_code}`), and `network = false` marks the few operations that
  must not leave the host.

## The network boundary

oniux is not a feature that can be turned off; it is the only way a network
command can be started. There is no SOCKS setting, no proxy flag, no per-tool
override, and no anonymity mode — `execution.oniux_binary` names the binary and
nothing else.

Before the first network task of a run, the engine probes
`oniux /bin/true`. If the probe fails, every network task fails with
`ONIUX_UNAVAILABLE` and the tool is not started at all: not on the host network,
not anywhere. The probe is remembered for the run, so a burst of concurrent
tasks pays for one preflight rather than one each. Local operations
(`network = false`) run directly.

## Evidence

Each run writes one directory:

```
<output_dir>/<run_id>/
├── manifest.json     every task: the exact command, boundary, status, timings
├── harvest.txt       consolidated findings, one per line
├── harvest.json      the same findings with their sources
└── raw/
    └── 20260930_034525_objectives_objective_discovery_rg_keyword_search.out
```

Artifact names are `YYYYMMDD_HHMMSS_PHASE_CAPABILITY_PROVIDER_OPERATION` with a
`.out` or `.err` suffix, so a file found in isolation still says what produced
it. The manifest is written after every task, so an interrupted run is still a
complete record of what ran. Nothing is written to `harvest.txt` that is not
also in a raw file.

## Configuration

`$TSEC_HOME/config/config.toml`, created with defaults on first launch:

```toml
version = 3

[general]
output_dir = "/opt/tsec/output"
log_dir = "/opt/tsec/logs"
preview_lines = 500     # harvest lines the OUTPUTS panel may show
color = "auto"          # auto | always | never, and NO_COLOR is honoured
keep_raw = true

[execution]
max_concurrency = 6     # simultaneous tool processes
timeout_secs = 300      # per task, then SIGTERM, then SIGKILL
oniux_binary = "oniux"
kill_grace_ms = 2000
group_kill_grace_ms = 500

[tools]
search_paths = []       # searched before PATH when resolving providers
```

Paths are discovered rather than hard-coded: `TSEC_HOME`, then `/opt/tsec`, then
`$XDG_DATA_HOME/tsec`, then `~/.local/share/tsec`. Configuration from an older
release is migrated rather than rejected — keys describing a SOCKS proxy are
dropped, because oniux has no endpoint to point at.

## Design rules

1. **Capability first.** The operator picks an objective, never a tool.
2. **Nothing is guessed.** Every argument vector is declared; a flag the catalog
   does not name is never passed.
3. **No shell, ever.** Argument vectors only, with shell metacharacters rejected
   at load time.
4. **No fallback path.** A network task that cannot get its boundary fails.
5. **Honest unavailability.** A missing tool is named, never substituted.
6. **No fake completion.** Failed, timed-out and interrupted tasks are recorded
   as such, with their partial evidence kept.
7. **Secrets stay out of the evidence.** Sensitive arguments are masked in every
   rendering, record and report.

## Layout

```
catalog/capabilities.toml   the operational surface: phases, capabilities, providers
src/catalog.rs              catalog loading and validation
src/provider.rs             which providers resolve on this host
src/domain/                 commands, inputs, plans, findings, ids, reports
src/exec/                   the single spawn site, oniux preflight, isolation
src/parser.rs               nmap XML, JSON, line and raw parsing into findings
src/store.rs                run directory, manifest, harvest, atomic writes
src/ui/                     panels, menus, run flow, spinner, adaptive theme
docs/ARCHITECTURE.md        how the pieces fit and why
docs/TROUBLESHOOTING.md     error codes and what to do about them
REQUIREMENTS.TXT            the boundary and the provider toolset
```

## Verifying a build

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test              # includes loading and validating the shipped catalog
cargo build --release
```

`cargo test` fails if `catalog/capabilities.toml` has a phase without sixteen
capabilities, a label that is not two uppercase words, a placeholder with no
matching input, or an argument containing shell syntax.

---

TSEC 3.0 — terminal cybersecurity operations platform, built by funbinet.
© funbinet. All rights reserved.
