# TSEC 3.0 architecture

How the pieces fit, and the invariants the code is written to keep.

---

## 1. The shape of the system

```
            catalog/capabilities.toml
                     │  (loaded and validated at startup)
                     ▼
  src/catalog.rs ─────────────► src/provider.rs
   capabilities, operations       which binaries resolve here
                     │
   src/domain/       ▼
   inputs, commands, plans ─► src/exec/ ─► oniux ─► the tool
                                  │            (or the host, if local)
                                  ▼
                             src/store.rs ─► raw evidence + manifest
                                  │
                             src/parser.rs ─► findings
                                  │
                             src/ui/  ─► panels, menus, harvest
```

The operator never names a tool. A **capability** is chosen, the catalog says
which providers implement it and exactly how each is invoked, and the engine
runs those argument vectors behind the network boundary.

## 2. The catalog is the source of truth

`catalog/capabilities.toml` describes ten phases and sixteen capabilities per
phase. `Catalog::from_toml` refuses to load a file that breaks any of these:

| Rule | Why |
|---|---|
| `phase` is one of the ten phases | The phase model is structural, not extensible |
| every phase holds at least one capability | A half-populated catalog is incomplete, not extensible |
| `label` is exactly two uppercase words | Labels are the interface, and the interface is fixed |
| every `{placeholder}` names a declared input | A renamed input must fail at startup, not reach a tool as `{target}` |
| no argument contains shell syntax | Arguments are executed as a vector; a template that implies a shell is a bug |
| a capability has providers, each with operations, each with arguments | An empty operation would run a bare binary |
| ids are unique and namespaced under their phase | Reports and manifests key on the id |

Validation happens at load time, not at run time, so a malformed catalog is a
startup failure naming the file, the capability and the reason.

### Placeholders and escapes

Substitution is per argument token, never textual across the whole vector:

- A token that is *exactly* `{key}` becomes one argv entry, however much
  whitespace the value contains — a target can never split into two arguments.
- A placeholder inside a larger token (`--rate={rate}`) is interpolated in place.
- `{{` and `}}` are literal braces, so a tool that needs to receive `{ ... }` can
  be described exactly.
- `%{…}` is printf-style literal text and is copied through untouched, which is
  what makes curl's `%{http_code}` expressible.

Inputs are validated against their declared `type` (`domain`, `target`, `url`,
`port`, `ports`, `path`, `file`, `interface`, `mac`, `hash`, `list`, …). Values
of a sensitive type (`secret`, `password`) are registered on the command as
sensitive, and every rendering — terminal, manifest, report — masks them.

## 3. Execution

There is **exactly one `Command::spawn` in the engine**, in
`exec::Runner::run`. Everything that decides *what* runs feeds that one site, so
the boundary is a property of the code path rather than a rule someone has to
remember.

1. **Evidence first.** Both capture files are created before anything can fail,
   so a task that is refused still leaves two (empty) files and a manifest entry
   that points at something real.
2. **Preflight.** A network command cannot proceed until `oniux /bin/true` has
   succeeded. The probe is memoized on the launcher (`OnceCell`), so concurrent
   tasks pay for exactly one; a failure is remembered for the run.
3. **Routing.** `Launcher::plan` returns the argument vector to execute. For a
   network command argv[0] is the resource path of the oniux binary and argv[1]
   is the tool; for a local command argv[0] is the tool. There is no third case
   and no unwrapped network vector.
4. **Isolation of the process group.** Each child gets its own process group, so
   a timeout or an interrupt reaches grandchildren too: `SIGTERM` to the group,
   then `SIGKILL` after `kill_grace_ms`.
5. **Concurrency.** A capability's operations are dispatched together and bounded
   by a semaphore sized from `execution.max_concurrency`, so a slow tool never
   holds back a fast one. Each task writes its own artifacts, so there is nothing
   to serialise. Records are sorted back into catalog order before the manifest
   is written, which keeps runs diffable.
6. **Cancellation.** `Ctrl+C` sets a `Cancellation` flag from a watcher thread;
   running tasks observe it within one poll interval and are terminated as a
   group. Their records come back marked `INTERRUPTED` with their partial output
   intact.

### Why oniux and not a proxy

A SOCKS proxy is a per-tool option: it only works for tools that honour it, it
can be forgotten for one invocation, and it does not isolate the process. oniux
is a namespace whose only route is an embedded Tor client, so isolation is a
property of the process rather than of the tool's flags. That is also why there
is no anonymity toggle: a switch that silently changes the security property of
every command is the thing this design removes.

## 4. Evidence

```
<output_dir>/<run_id>/
├── manifest.json     one record per task, written after each task completes
├── harvest.txt       consolidated findings
├── harvest.json      findings with their sources
└── raw/<stem>.out|.err
```

- **Artifact stems** are `YYYYMMDD_HHMMSS_PHASE_CAPABILITY_PROVIDER_OPERATION`,
  sanitised to `[a-z0-9_]`, so a file found in isolation still identifies itself.
- **Every write is atomic**: a same-directory temporary file, `fsync`, then
  `rename`. A machine that dies mid-run cannot leave a truncated manifest.
- **The manifest is appended per task**, which is what makes a partial run
  useful: everything that finished is already recorded.
- **The record holds the redacted command** that was run, the boundary it ran
  under, exit status, byte counts, and the error code when it failed.

## 5. Parsing and harvest

`parse_artifact` reads a raw capture according to the format the catalog declared
for that operation (`nmap`, `json`, `lines`, `raw`) and produces findings with
provenance. Choosing the format per *operation* rather than per tool matters:
one provider can emit different formats per operation, and reading nmap's XML as
a line list would silently lose the structured ports.

Findings from every task are merged, deduplicated by (category, value), and
correlated by counting their sources. Unparsed or empty output is recorded as a
finding of its own rather than dropped, so "the tool reported nothing" and "the
parser could not read this" stay distinguishable. Input larger than 32 MiB is
truncated with a note and a finding; the raw file keeps everything.

## 6. Presentation

`ui/panel.rs` owns geometry and drawing: a centred box, a one-word title, rows,
and `-[ENTER]` underneath. `ui/menu.rs` builds screens out of panels; `ui/output.rs`
builds the harvest panel; `ui/theme.rs` resolves palettes and colour depth;
`ui/spinner.rs` animates one line while tasks run.

Keys are fixed: `I`/`↑` up, `K`/`↓` down, `J`/`←` back, `L`/`→`/Enter select,
`Esc` close, `Ctrl+C` leave. Rows that cannot be chosen are skipped by the cursor
and explain themselves when the cursor lands on them.

The theme adapts: palettes (`midnight`, `graphite`, `solarized-dark`,
`solarized-light`, `daylight`, `ashen`), depth detection (truecolor → 256 → 16 →
none), `NO_COLOR` honoured, and `color = "always"` for pipes. Styling never
changes the text, only its colour, so a screenshot and a log agree.

## 7. Configuration

`Config::load_or_create` writes defaults when no file exists, validates ranges
on load, and reports the file and the key when something is wrong. Paths are
discovered (`TSEC_HOME`, `/opt/tsec`, XDG, `~/.local/share/tsec`) so the same
binary works from a checkout and from a system install. Configuration describing
a removed feature — a SOCKS proxy, a per-tool override — is dropped on load with
a note rather than rejected.

## 8. Error model

Every failure carries a **stage** (`PLAN`, `EXECUTE`, `CAPTURE`, `PARSE`, …), a
stable **code** (`ONIUX_UNAVAILABLE`, `TIMEOUT`, `EXIT_STATUS`,
`CATALOG_ERROR`, …) and, where useful, a hint. Codes are what
`docs/TROUBLESHOOTING.md` documents and what the manifest records, so a record
can be read months later without guessing which layer failed.

A task never fails the run. It fails *itself*, with a record, and the run
continues — which is why the harvest panel leads with a task tally and the error
codes before it shows any findings.

## 9. Deliberate non-features

| Not present | Because |
|---|---|
| A shell, or shell syntax in the catalog | An argument vector is the only thing that can be verified |
| An anonymity toggle, `--no-proxy`, per-tool overrides | The boundary is not optional, so it is not a setting |
| A fallback to the host network | A silent downgrade is worse than a failure |
| Guessed flags or tool invocation templates | A flag the catalog does not name is never passed |
| Silent substitution of a missing tool | An operator must know what did *not* run |
| Telemetry, phone-home, crash uploads | Evidence leaves the machine only when the operator moves it |
| A `main.rs` that knows how the framework works | `main.rs` parses arguments, loads config and hands over |

## 10. Verification

The test suite pins the parts that are expensive to get wrong:

- the shipped catalog loads, every phase holds sixteen capabilities, and every
  label is two uppercase words;
- shell syntax in an argument, an undeclared placeholder, a label that is not
  two uppercase words, and an empty phase are all rejected;
- placeholder substitution keeps a whitespace-bearing value as one argument,
  `{{ … }}` survives as literal braces, and `%{http_code}` is not treated as a
  placeholder;
- a sensitive input is masked in the rendered command and in serialised output;
- availability reports missing binaries by name;
- provider search paths are honoured ahead of `PATH`.

`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test` and `cargo build --release` are the gate for every change.

---

TSEC 3.0 — terminal cybersecurity operations platform, built by funbinet.
© funbinet. All rights reserved.
