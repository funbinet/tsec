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

`catalog/capabilities.toml` describes ten phases and 226 capabilities. Phase
membership is structural; per-phase counts are not, because a phase with more
distinct jobs carries more capabilities.

`Catalog::from_toml` refuses to load a file that breaks any of these:

| Rule | Why |
|---|---|
| `phase` is one of the ten phases | The phase model is structural, not extensible |
| every phase holds at least one capability | A half-populated catalog is incomplete, not extensible |
| `label` is one to three uppercase words | Labels are headings in a fixed-width menu; three words is a vocabulary choice, not a layout one |
| every `{placeholder}` names a declared input | A renamed input must fail at startup, not reach a tool as `{target}` |
| every `{wl:path}` resolves inside the corpus | A capability must not depend on a path that exists only on the machine it was authored on |
| a capability has providers, each with operations | A provider block with nothing in it is a hole in the surface |
| ids are unique and namespaced under their phase | Reports and manifests key on the id |

Validation happens at load time, not at run time, so a malformed catalog is a
startup failure naming the file, the capability and the reason.

Two things are deliberately *not* fatal, because refusing to start would not help
anyone:

- **Shell syntax embedded in a payload.** A URL query string, an LDAP filter, an
  XML entity and a SQL statement all carry `&`, `(`, `;` and `<`. They reach the
  tool verbatim and do exactly what the author meant.
- **A wordlist that is not on disk yet.** The operator can fetch it. The
  capability needing it is reported unavailable, by name, rather than being
  pointed at a different corpus.

What *is* reported is an argument that **is** a shell operator — `|`, `&&`,
`2>/dev/null` — as a whole argv entry. No tool takes one, so its presence means a
command line was pasted in without being split, and the tool will run as if it
were not there. `tsec --status` lists these.

### The intelligence pass

The format parsers answer "what shape did this tool print?". That is necessary
and not sufficient: most tools do not print findings one per line, they print
progress banners and then a line carrying several independent artefacts.

```text
10.0.0.4 - - "POST /login HTTP/1.1" 302 0 "Mozilla/5.0" "admin:Sup3rS3cr3t"
```

Whole-line classification files that under one heading and separates nothing.
`src/intel.rs` scans every line of every artifact, whatever its declared format,
for artefact shapes — secrets, tokens, cookies, hashes, CVEs, exposed files,
comments, credentials, and the network inventory — and emits one finding per
match. It runs before and independently of the format parsers, which own the
shapes a regex cannot decide: hostnames, `host:port`, httpx bracket fields.

Two properties keep this safe over arbitrary tool output:

* **Nothing is invented.** A finding exists only because a pattern matched bytes
  the tool printed. The matched text and the line it came from both travel with
  the finding, so the interpretation is checkable against the raw evidence.
* **Noise is separated, not deleted.** Progress bars, timings and banners become
  `Category::Noise`: counted, retrievable, and out of the document. Folding them
  in with real evidence is what made previous harvests read as empty.

`intel::recommend` closes the loop by mapping what was harvested to the
capabilities that follow from it, ranked by signal strength. It is a routing
table, not advice: every step names a phase and a capability that exist.

### The wordlist corpus

`wordlists/` is part of the product, not an optional extra. The catalog names a
list relative to it and the loader resolves that to an absolute path, so the
operator is never asked for a corpus and no capability assumes a distribution
package is installed.

| | |
|---|---|
| Reference | `{wl:ssh/passwords.txt}` — a path inside `wordlists/` |
| Resolution | `$TSEC_WORDLIST_ROOT`, else `<install root>/wordlists` |
| Traversal | refused; a reference may not escape the corpus |
| Missing | reported by name; the capability is unavailable, never substituted |
| Large lists | four exceed 100 MB, so `fetch-wordlists.sh` retrieves them with a pinned SHA-256 |

Corpora are per attack class. `{wl:passwords/rockyou.txt}` and
`{wl:ssh/passwords.txt}` are different files on purpose: substituting one for
the other produces a run that looks successful and finds nothing, which is worse
than a failure.

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
├── output.txt        the operator-facing document
├── output.json       findings with their sources
├── artifacts/        anything the run generated
└── raw/<stem>.out|.err
```

A generated payload belongs to the run that made it. `msfvenom -o rev.elf`
given a bare filename writes to the working directory the tool happened to be
launched from, which is the operator's shell: the file is still there several runs
later, nobody knows which run produced it, and the document has no path to give.
`{artifacts}` resolves to the current run's own directory, so
`-o {artifacts}/rev.elf` writes there, the run leaves nothing in the working
directory, and `output.txt` lists what was made and how large it is.

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

Only tasks that completed are harvested. A task that failed printed its usage
because the flag was wrong, its banner because it exited early, or its error
because a file was missing; reading any of that as findings produced a page of
`--help` lines reported as comments and a version banner reported as evidence.
The failure itself is not lost — the document's WHY section states what each
operation said on the way out, and the bytes stay in the raw evidence.

Every line is stripped of terminal control sequences before it is matched or
shown. Most of this catalog colours its output, and an escape left in place
corrupts the value of the finding it belongs to while the fragment it was part
of becomes a finding of its own.

A line the extractor does not recognise is recorded as `Evidence` and kept in
`output.json`, but `Evidence` is not actionable and never reaches `output.txt`.
A line not yet known to be nothing is certainly not known to be intelligence,
and an operator reading a document needs every line in it to be a claim about
the target.

Findings from every task are merged, deduplicated by (category, value), and
correlated by counting their sources. Unparsed or empty output is recorded as a
finding of its own rather than dropped, so "the tool reported nothing" and "the
parser could not read this" stay distinguishable. Input larger than 32 MiB is
truncated with a note and a finding; the raw file keeps everything.

## 6. Presentation

`ui/panel.rs` owns geometry and drawing: full-terminal-width adaptive boxes (`inner = cols - 2`)
that resize dynamically with the terminal. Menus format and center choices cleanly, while
document viewers, output inspection, and execution monitors use left-alignment for dense,
structured output.

Keys are fixed and consistent:
- `I` / `↑` up (linear navigation across all capabilities without skipping any item)
- `K` / `↓` down (linear navigation across all capabilities without skipping any item)
- `J` / `←` back / close current panel
- `L` / `→` / `Enter` / `Space` select or activate item
- `Esc` close / back
- `Ctrl+C` context-sensitive: cancels input prompts, confirms before stopping operations (`Stop ongoing operations? [y/N]`, default `N`)

Provider readiness is explicitly reported (`[READY]`, `[PARTIAL]`, `[PROVIDER MISSING]`).
Selecting an unavailable capability does not fail silently; instead, it opens Arch Linux
installation guidance (`install::advise`), querying `pacman -Si` and AUR helpers to guide the operator.

The execution engine (`ui/execution.rs`) monitors multi-operation concurrent jobs with:
- Live ~12 fps smooth spinner per active job.
- Per-operation status (`PENDING`, `RUNNING`, `SUCCEEDED`, `FAILED`, `INTERRUPTED`).
- Live command line display with masked credentials (`[REDACTED]`).
- 6-stage pipeline: `Parsing` → `Normalizing` → `Deduplicating` → `Correlating` → `Harvesting` → `Writing`.
- Truthful outcome reporting (never masking missing boundaries or errors as "NO FINDINGS").
- Output preview up to 500 lines, prompt `Open full output? [Y/n]`, and full document viewer (`ui/output::view_document`).

The theme adapts: system theme discovery (`omarchy`, `pywal`, `base16`), built-in palettes (`midnight`,
`graphite`, `solarized-dark`, `solarized-light`, `daylight`, `ashen`), depth detection (truecolor → 256 → 16 → none),
`NO_COLOR` honoured, and `color = "always"` for pipes. Styling never changes the text, only its colour,
so a screenshot and a log agree.

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

## 9a. Provider installation

A missing provider is a fact about the host, not an error in the capability.
`src/install.rs` handles it in three steps, each of which is deliberately local:

1. **Detect** the distribution and its package manager: `pacman`, `apt-get`,
   `dnf`, `yum`, `apk`, `zypper`, plus an AUR helper on Arch.
2. **Resolve** the binary to a package by querying the host's local package
   database — `pacman -Si`, `apt-cache show`, `dnf --cacheonly info`,
   `apk info -a`, `zypper --non-interactive info`. All of these are offline
   metadata reads, which matters: deciding what to install happens before any
   task runs, and it must not require the boundary.
3. **Install** on a background thread while the capability runs with whatever
   else it can.

No package name is ever guessed. A binary that resolves in no repository is
reported as such, with the search command the operator can run. That is a real
answer; "there is no package for this" is not one.

The install outcome is recorded distinctly from execution failure:

| Situation | Recorded as |
|---|---|
| Binary present | a normal task |
| Installed during the run | a normal task, labelled *(installed mid-run)* |
| Still missing afterwards | `TOOL_NOT_FOUND`, status `Skipped` |

The last row is the important one. Nothing ran, so nothing failed: reporting it
as a failed task would invent a failure that never happened, and would make a
capability whose every provider was missing read as `EXECUTION FAILED`.

## 10. Verification

The test suite pins the parts that are expensive to get wrong:

- the shipped catalog loads, every phase is populated, and every label is one to
  three uppercase words;
- an unknown phase, an empty phase, a duplicate id, an undeclared placeholder, a
  provider with no operations, and a wordlist reference escaping the corpus are
  all rejected;
- payload braces are not mistaken for input placeholders — `{10,}` and
  `{"role":"admin"}` are payload, `{target}` and `{sudo-password}` are inputs;
- shell syntax inside a payload is left alone, while an argument that is a shell
  operator is reported without stopping the load;
- every `{wl:...}` reference in the shipped catalog resolves to a non-empty file
  inside `wordlists/`, and the shipped catalog names no missing list;
- placeholder substitution keeps a whitespace-bearing value as one argument,
  `{{ … }}` survives as literal braces, and `%{http_code}` is not treated as a
  placeholder;
- an operation may declare no arguments at all, because `id`, `env` and
  `printenv` are run for what they print;
- a sensitive input is masked in the rendered command and in serialised output;
- availability reports missing binaries and missing wordlists by name;
- provider search paths are honoured ahead of `PATH`;
- the intelligence pass recovers a credential, a token and a cookie from
  realistic multi-tool output, counts progress lines separately, and keeps both
  out of the document;
- a URL is never reported as a credential pair, and a `Set-Cookie` header yields
  one finding rather than two;
- every `arch|debian` mapping in `tools.sh` is well formed, and every binary the
  catalog names has one, so the two cannot drift apart;
- every package manager produces a direct argv with no shell metacharacter, and
  apt is asked for non-interactive minimal installs;
- guidance for a binary that exists in no repository invents nothing.

`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test` and `cargo build --release` are the gate for every change.

---

TSEC 3.0 — terminal cybersecurity operations platform, built by funbinet.
© funbinet. All rights reserved.
