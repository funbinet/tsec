# TSEC 3.0

**Tactical Security Enumeration & Compromise Framework** — a terminal platform
for authorised red-team and security-assessment work.

TSEC 3.0 is capability-first. An operator chooses *what to accomplish* — `PORT
DISCOVERY`, `HARVEST HASHES`, `HANDSHAKE CAPTURE` — and the framework knows which
tools implement it and exactly how to invoke each one. Nothing about a tool's
flags is written in Rust; all of it lives in one reviewed file,
[`catalog/capabilities.toml`](catalog/capabilities.toml).

Reference docs:
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md)
- [`docs/CAPABILITY_OPERATIONS.md`](docs/CAPABILITY_OPERATIONS.md)

The framework is organised as **ten phases, 200 capabilities**. Every phase is
mandatory: a catalog that leaves one empty is rejected at startup rather than
shipped half-finished.

| # | Phase | Caps | | # | Phase | Caps |
|---|---|---|---|---|---|---|
| 01 | `RECON` | 22 | | 06 | `CREDENTIALS` | 22 |
| 02 | `SURFACE` | 22 | | 07 | `LATERAL` | 24 |
| 03 | `VULNERABILITY` | 22 | | 08 | `PERSISTENCE` | 19 |
| 04 | `PAYLOAD` | 20 | | 09 | `EXPLOITATION` | 27 |
| 05 | `ESCALATION` | 24 | | 10 | `WIRELESS` | 16 |

A phase holds what it needs to hold. The counts differ because a phase with more
distinct things to do carries more capabilities, not because some are padded.

### Wordlists ship with the framework

Every corpus a capability can reach is in [`wordlists/`](wordlists/), and the
catalog names them relative to that directory. The operator supplies a target
and whatever the specific attack needs; they are **never** asked for a path to a
wordlist, and no capability depends on `/usr/share/seclists` or
`/usr/share/wordlists` existing on the host.

Each service has its own corpus, because `rockyou.txt` is the right answer for
offline hash cracking and the wrong one for an SSH spray or a WPA handshake:

```
wordlists/passwords/   offline hash cracking: rockyou, top-1m, JWT secrets
wordlists/ssh/         account names and passwords for SSH attacks
wordlists/smb/  ftp/  mail/  db/  ad/     per-service authentication corpora
wordlists/wifi/        PSK defaults, passphrases, SSID names
wordlists/web/  dns/  fuzz/              content, subdomain and payload corpora
wordlists/network/  osint/  rules/      ports, cloud naming, hashcat rules
```

Four lists are too large for a git repository (GitHub and Codeberg both refuse
blobs over 100 MB). One command gets them, with a pinned SHA-256 each:

```sh
./wordlists/fetch-wordlists.sh
```

See [`wordlists/README.md`](wordlists/README.md) for the full table, provenance
and the override for a relocated corpus.

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
sudo ./install.sh          # installs /usr/bin/tsec and /opt/tsec/{catalog,wordlists,config,…}
```

The installer deploys the catalog **and** the wordlist corpus to
`/opt/tsec`, then fetches the four large lists. A missing large list is reported,
not fatal: the capability that needs it is marked unavailable by name.

Running from a checkout works with no install at all:

```sh
TSEC_HOME="$PWD" cargo run --release
```

## Launching

```sh
tsec                 # the interface
tsec --status        # availability per phase, the boundary, and wordlist health
tsec --version
tsec --help
```

## Driving the interface

Every screen is one full-terminal-width box that adapts to the terminal size,
rendered in place: moving a pointer, typing an input or watching a task run
**overwrites the same box** — nothing is appended, nothing scrolls, nothing is
duplicated, and nothing on your terminal before TSEC is ever cleared (the UI
runs on the alternate screen and restores your history on exit). Menu entries
are block-centred: they share one left column, and the block as a whole sits in
the centre of the box.

| Key | Action |
|---|---|
| `I` / `↑` | move up (linear, never skips an entry) |
| `K` / `↓` | move down (linear, never skips an entry) |
| `L` / `→` / `Enter` | select / accept |
| `J` / `←` | back one level (from a run's submenu, close the document) |
| `Esc` | **context-sensitive** — see below |
| `Ctrl+C` | same as `Esc` where a cancel makes sense |

`Esc` never means "go back a menu". Its meaning is fixed per screen:

| Screen | `Esc` does |
|---|---|
| Input box | cancels the capability, back to the capability menu |
| Capability menu | **exits the system** |
| Main menu | **exits the system** |
| During execution | opens `Stop ongoing operations? [y/N]` — `Y` stops, `N` continues |
| Output / viewer / guidance | closes the screen |

Leaving the system shows the exit screen: the `TSEC` title, three lines of
metadata (`OUTPUTS`, `RUNTIME`, `VERSION`), and a goodbye.

The top level lists the ten phases plus two management screens:

- **`STATUS`** — version, theme diagnostics, catalog size, live availability
  per phase, and whether the oniux boundary resolves.
- **`OUTPUTS`** — every previous run, with its normalized output, raw evidence
  and manifest browsable in the scrollable viewer.

### Capability menus

Capability menus list capabilities **by name only** — no READY/PARTIAL/MISSING
decorations. Every capability stays selectable. Choosing one whose provider is
missing opens a guidance box with verified install commands (queried from
`pacman` sync databases, with AUR fallbacks) instead of a dead end.

## Running a capability

1. **The capability box.** One closed box titled with the capability's own
   name (centred), then one input box per declared parameter: a two-row closed
   box — the input's title on the first row, your typing on the second, both
   centred — with the `-[ENTER] ACCEPT   -[ESC] CANCEL` hint centred below.
   Values are validated against their declared type (`domain`, `target`,
   `url`, `ports`, `secret`, …) and sensitive inputs are masked everywhere.
2. **The `EXECUTION` box.** One box, one title, updated in place. Each task
   shows a live spinner beside its status (`QUEUED`, `RUNNING`, `COMPLETE`,
   `FAILED`, `TIMED OUT`, `CANCELLED`), the redacted command line beneath it,
   and a live tally (`n/m FINISHED · RUNNING · QUEUED · ELAPSED`). `Esc` or
   `Ctrl+C` asks before stopping anything; only `Y` cancels, and evidence
   already collected is kept.
3. **The `PROCESSING` box.** One box, seven real stages — parsing, normalizing,
   deduplicating, correlating, harvesting, recommending, writing — each ticked
   (`✓`) only when the corresponding work has actually finished. No timer-driven
   animation, no duplication.
4. **The `OUTPUT` screen.** The run's document, previewed up to 500 lines
   (the saved file and the viewer are never truncated), an `OUTPUT FILE` box
   naming the saved path, and exactly three operations in the hint:
   `-[I/K] SCROLL   -[L] OPEN FULL   -[J/ESC] CLOSE`. `L` opens the full
   scrollable viewer directly — there is no `Open full output? [Y/n]` prompt.

## What a run actually gives you

Raw tool output is not the deliverable. The deliverable is what can be used
against the target next, so the harvest is built in two passes.

**The format pass** reads the shape the catalog declared — nmap's XML, nuclei's
JSON lines, one-finding-per-line output — and understands it as that tool means
it.

**The intelligence pass** (`src/intel.rs`) then scans every line of every
artifact, whatever its declared format, for artefact shapes that matter:

| Recovered | Examples |
|---|---|
| `SECRETS` | AWS keys, private keys, `password=` assignments, DSNs with inline credentials |
| `TOKENS` | GitHub, Slack, Google, Stripe, GitLab, npm, OpenAI, Anthropic keys; JWTs; bearer and `Authorization` headers |
| `COOKIES` | `Set-Cookie` headers, `PHPSESSID`, `JSESSIONID`, `ASP.NET` session ids, CSRF and refresh tokens |
| `CREDENTIAL PAIRS` | `user:pass` as hydra, nikto and access logs emit it |
| `HASHES` | crypt, NTLM, NetNTLMv1/v2, Kerberos, DYNECT, SSHA |
| `VULNERABILITIES` | CVE, CWE, GHSA, OWASP identifiers |
| `FILES` | `.git/`, `.env`, `.aws/credentials`, `wp-config.php`, keys, certs, dumps, archives, source files |
| `COMMENTS` | HTML, block and inline comments; `TODO` / `FIXME` / `HACK` markers |
| `EMAILS`, `URLS`, `IP ADDRESSES`, `MACs`, `HOSTS`, `PORTS` | the inventory |

One line yields as many findings as it really carries, which is the point: an
access-log line holds the client IP, the URL, the status *and* a credential, and
before this pass all four were filed as one unremarkable line of evidence.

Every artefact keeps the line it came from as its `detail`, so a three-character
finding is still interpretable weeks later without re-reading the artifact.
Nothing is invented: a finding exists only because a pattern matched bytes a tool
actually printed.

### Noise is separated, not discarded

Progress banners, progress bars, timings and run summaries are the largest
single source of unreadable output in a multi-tool run. They are classified as
`Noise`: counted, kept in `output.json`, and excluded from the document, with
the excluded count stated at the foot of the findings. A run that found nothing
and a run that printed two thousand progress lines now look different.

### Next actions

The harvest ends with `NEXT ACTIONS`: the capabilities the observations imply,
strongest signal first, each naming the phase, the capability, why it follows
from what was found, and what the operator has to supply.

```
NEXT ACTIONS
  [HIGH] credentials / CREDENTIAL DUMP LINUX / SERVICE LOGIN BRUTE — a password,
         private key or connection string was recovered in the clear
        needs: the host it belongs to
  [HIGH] exploitation / PUBLIC CVE SWEEP — a CVE identifier was reported
        needs: the affected host and its version
```

A step is only offered when a specific observed artefact implies it. Suggesting
an attack because a port was open is noise.

## Missing tools are installed while the run proceeds

A capability whose provider is not installed does not stop. The framework
detects the distribution and its package manager, resolves the package against
the host's **local** package database, and installs it on a background thread
while the rest of the capability runs:

| Family | Manager | Verified by |
|---|---|---|
| Arch, Manjaro, Omarchy | `pacman` (+ `paru`/`yay` for the AUR) | `pacman -Si` |
| Debian, Ubuntu, Kali, Mint, Pop | `apt-get` | `apt-cache show` |
| Fedora, RHEL, CentOS, Rocky, Alma | `dnf`, `yum` | `dnf --cacheonly info` |
| Alpine | `apk` | `apk info -a` |
| openSUSE, SLES | `zypper` | `zypper --non-interactive info` |

Every query is an offline metadata read. A package name is never invented, and a
tool that is in no repository is reported as such with a search command to run.

If the install lands before the capability finishes, its operations are dispatched
in the same run. If it does not, the provider is recorded as **`TOOL_NOT_FOUND`** —
skipped, not failed, because nothing ran and nothing failed — and named in the
document with the reason.

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
- **`label`** is one to three uppercase words — it is what the box shows.
- Every **`{placeholder}`** names a declared input, so a renamed input fails
  loudly instead of reaching a tool as a literal `{target}`. A placeholder is an
  identifier: regex quantifiers (`{10,}`) and JSON bodies (`{"role":"admin"}`)
  carry braces too, and are not mistaken for inputs.
- Every **`{wl:path}`** names a bundled wordlist. A reference to a list that is
  not on disk is reported by name, and the capability needing it is marked
  unavailable rather than silently pointed at some other corpus.
- An argument that *is* a shell operator (`|`, `&&`, `2>/dev/null`, …) is
  reported. Arguments are executed as a vector and never through a shell, so such
  a byte reaches the tool verbatim and the run looks clean while finding nothing.
  A shell metacharacter inside a larger token — a URL query string, an LDAP
  filter, an XML payload, a SQL statement — is legitimate and left alone.
- `{{` and `}}` are literal braces, `%{…}` is printf-style literal text
  (curl's `%{http_code}`), and `network = false` marks operations that must
  not leave the host.

`tsec --status` prints any of these that were noted but not fatal, so a catalog
that loads cleanly is not the same as one that behaves correctly.

## Editing capabilities, providers and commands

Everything about *what* a capability runs lives in
[`catalog/capabilities.toml`](catalog/capabilities.toml) — you never need to
touch Rust to tune a command, swap a flag, or add a provider. The file is
re-read on every launch, so an edit takes effect the next time `tsec` starts.

### Structure at a glance

```
[[capability]]                          one capability
  id                                    'phase.short-name', unique
  phase                                 one of the ten phase slugs
  label                                 ONE TO THREE UPPERCASE WORDS — shown in the menu
  summary                               one sentence, shown in guidance
  inputs = [ { key, type, required, default, help, rule }, … ]
[[capability.provider]]                 one provider binary per block
  binary                                the executable name resolved on PATH
[[capability.provider.operation]]       one command per block
  name                                  shown in the execution monitor
  args                                  the argv template — see below
  output                                lines | json | raw | nmap
  network                               true (via oniux) | false (local only)
```

### Wordlist references

Inside `args`, `{wl:<path>}` resolves to that file inside `wordlists/`:

```toml
args = ['-t', 'ssh', '-l', '{wl:ssh/users.txt}', '-P', '{wl:ssh/passwords.txt}', '{rhost}']
```

The reference may be a whole argument or embedded in one (`-l{wl:web/common.txt}`).
It resolves against `$TSEC_WORDLIST_ROOT` if that is set, otherwise against
`<install root>/wordlists`, where the install root is the directory holding
`catalog/`. A reference that tries to escape that directory is refused.
`{wlroot}` is the directory itself, for the capabilities that report on the
corpus rather than consume an entry.

This is why no capability declares a `wordlist` input. The corpus is a property
of the framework, not of the engagement.

### Changing flags or options of an existing command

Find the capability by its `label` (e.g. `EMAIL HARVESTING`), then the
`[[capability.provider.operation]]` block under the provider you want to tune,
and edit the `args` array. Each element is **one argv entry** — exactly what
would appear as one shell word:

```toml
[[capability.provider.operation]]
name = 'Search Engines'
args = ['-d', '{domain}', '-b', 'bing', '-l', '{limit}']
output = 'lines'
network = true
```

- To change a flag value, edit or add elements: `'-l', '{limit}'` →
  `'-l', '500'` fixes the limit; `'-b', 'bing'` → `'-b', 'crtsh'` changes the
  source.
- To keep a flag but force a value while still accepting operator input for
  the rest, just leave the `{placeholder}` elements you want untouched.
- **Never remove or rewrite the `{input}` placeholders** — every placeholder
  must name an input declared in the capability's `inputs` list, and the
  loader rejects the catalog at startup otherwise.
- One argv entry per array element: write `["--rate", "100"]`, never
  `["--rate 100"]` (a space inside an element would be passed to the tool as
  part of a single argument, not split).

### Placeholders and literal braces

| Template | Becomes |
|---|---|
| `{domain}` | the operator's `domain` input, as one argv entry when it fills a whole element |
| `--rate={rate}` | `--rate=100` (embedded substitution) |
| `{{` / `}}` | literal `{` / `}` |
| `%{http_code}` | literal `%{http_code}` (printf-style, for curl's `-w`) |

### Adding or removing an operation

Copy an existing `[[capability.provider.operation]]` block under the same
provider, change `name` (unique within the provider) and `args`. Delete a block
to remove that operation. Setting `network = false` marks an operation as
strictly local: it runs directly on the host and never through oniux.

### Adding a provider to a capability

Append a `[[capability.provider]]` block with its `binary` and one or more
operation blocks:

```toml
[[capability.provider]]
binary = 'theharvester'
[[capability.provider.operation]]
name = 'All Sources'
args = ['-d', '{domain}', '-b', 'all', '-l', '{limit}']
output = 'lines'
network = true
```

The binary must resolve on the host (via `PATH` or `tools.search_paths` in the
config); a capability runs with whichever of its providers are installed, and
the execution monitor names the missing ones.

### Validating your edits

```sh
cargo run -- --status     # the catalog is loaded and validated on every launch
cargo test                # includes catalog-wide validation tests
./tools.sh -<phase> -c    # check that every provider of a phase is installed
```

A malformed edit fails loudly at startup with the capability, operation and
reason — nothing half-valid ever reaches a tool.

## Installing the tools of a phase

[`tools.sh`](tools.sh) reads its tool list **directly from the catalog**, so it
always matches what the framework actually executes:

```sh
./tools.sh -recon          # verify & install every provider of the RECON phase
./tools.sh -wireless       # same for WIRELESS
./tools.sh -all            # every phase
./tools.sh -recon -c       # check only: list missing tools + install commands
```

For each missing tool it attempts an automated install (pacman, then an AUR
helper on Arch; apt on Kali), and for anything it cannot install it prints the
exact **Arch Linux and Kali Linux** commands to run by hand.

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
├── output.txt        the operator document (centred header, then FINDINGS)
├── output.json       the same findings with sources and correlations
└── raw/
    └── T01_subfinder_passive_enumeration.out
```

The document's header is centred — the version line, the
`RUN … | PHASE … | CAPABILITY …` line, `STATE … | PIPELINE …` and the task
tally — followed by a full-width rule and the `FINDINGS` section,
left-aligned. It is saved exactly as shown. The manifest is written after
every task, so an interrupted run is still a complete record of what ran.

## Configuration

`$TSEC_HOME/config/config.toml`, created with defaults on first launch:

```toml
version = 3

[general]
output_dir = "/opt/tsec/output"
log_dir = "/opt/tsec/logs"
preview_lines = 500     # harvest lines the OUTPUT preview may show
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
the build tree. Configuration from an older release is migrated rather than
rejected — keys describing a SOCKS proxy are dropped, because oniux has no
endpoint to point at.

## Design rules

1. **Capability first.** The operator picks a capability, never a tool.
2. **Nothing is guessed.** Every argument vector is declared; a flag the catalog
   does not name is never passed.
3. **No shell, ever.** Argument vectors only. An argument that is a shell
   operator is reported at load time, because it means a command line was pasted
   in without being split; a metacharacter inside a payload is left alone.
4. **No fallback path.** A network task that cannot get its boundary fails.
5. **Honest unavailability.** A missing tool is named, never substituted. A
   missing wordlist is named too, and never quietly swapped for a different one.
6. **No fake completion.** Failed, timed-out and interrupted tasks are recorded
   as such, with their partial evidence kept.
7. **Secrets stay out of the evidence.** Sensitive arguments are masked in every
   rendering, record and report.
8. **One frame per screen.** Nothing is ever cleared or duplicated; the screen
   is overwritten in place, and the operator's own terminal history is sacred.

## Layout

```
catalog/capabilities.toml   the operational surface: phases, capabilities, providers
wordlists/                  the bundled corpus, one directory per attack class
  MANIFEST.tsv              path, tier, digest, upstream URL, purpose
  fetch-wordlists.sh        the four lists too large to commit, digest-checked
  verify-wordlists.sh       presence and checksum report for the whole corpus
tools.sh                    phase tool installer (Arch + Kali commands)
src/catalog.rs              catalog loading and validation
src/provider.rs             which providers resolve on this host
src/domain/                 commands, inputs, plans, findings, ids, reports
src/exec/                   the single spawn site, oniux preflight, isolation
src/parser.rs               nmap XML, JSON, line and raw parsing into findings
src/store.rs                run directory, manifest, document, atomic writes
src/ui/                     panels, menus, run flow, spinner, adaptive theme
docs/ARCHITECTURE.md        how the pieces fit and why
docs/CAPABILITY_OPERATIONS.md  the catalog format, field by field
docs/COMMANDS.md            every operator-facing command
docs/TROUBLESHOOTING.md     error codes and what to do about them
wordlists/README.md         the corpus, its provenance and its override
REQUIREMENTS.TXT            the boundary and the provider toolset
install.sh                  binary, catalog and corpus to /opt/tsec
```

## Verifying a build

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test              # includes loading and validating the shipped catalog
cargo build --release
./wordlists/verify-wordlists.sh   # presence and checksums for the whole corpus
./tools.sh -all -c                # which provider binaries are missing
```

`cargo test` fails if `catalog/capabilities.toml` has an empty phase, an unknown
phase, a duplicate id, a label that is not one to three uppercase words, a
placeholder with no matching input, a provider with no operations, or a wordlist
reference that escapes the corpus or names nothing.

It also fails if any `{wl:...}` reference in the shipped catalog does not resolve
to a non-empty file, so a capability cannot quietly ship pointing at a list that
is not there.

---

TSEC 3.0 — terminal cybersecurity operations platform, built by funbinet.
© funbinet. All rights reserved.
