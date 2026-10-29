# Capability operations and command mapping

This document explains where TSEC capability operations are defined, how command
templates are executed, and where to edit or add provider operations safely.

## Primary files

- `catalog/capabilities.toml`
  - Source of truth for capabilities, providers, operations, argument templates,
    output formats, and network/local execution flags.
- `wordlists/`
  - The bundled wordlist corpus. The catalog references it with `{wl:path}`.
- `src/catalog.rs`
  - Loads and validates the catalog, validates placeholders and wordlist
    references, builds concrete command vectors from templates and operator input.
- `src/ui/menu.rs`
  - Converts selected capability + collected inputs into executable jobs.
- `src/exec/mod.rs`
  - Executes commands, enforces network-boundary routing, captures stdout/stderr.
- `src/intel.rs`
  - Scans every line of every artifact for exploitable artefact shapes, and maps
    the result to the capabilities that follow from it.
- `src/parser.rs`
  - Parses raw evidence based on per-operation `output` format.
- `src/install.rs`
  - Detects the distribution, resolves a missing provider against the host's
    local package database, and installs it in the background during a run.
- `src/store.rs`
  - Harvests, normalizes, deduplicates, correlates, and writes `output.txt/json`.

## Where command definitions live

Every executable operation is defined in `capabilities.toml` under:

- `[[capability]]`
- `[[capability.provider]]`
- `[[capability.provider.operation]]`

Important operation keys:

- `name` — operation label shown in execution UI. Required and unique per provider.
- `args` — command argument template (one argv token per array element). May be
  empty for a tool run for what it prints, such as `id` or `env`.
- `output` — parser mode (`lines`, `json`, `raw`, `nmap`).
- `network` — `true` for boundary-wrapped network execution, `false` for local.
- `stage` — optional, 1-3 (default 1): 1 baseline, 2 analysis, 3 consequential.
  Stages dispatch in order, and a stage whose predecessor completed nothing is
  withdrawn rather than run.
- `confirm` — optional, default `false`. Gates the operation behind an explicit
  operator go-ahead before it dispatches. Only valid on stages 2 and 3; setting
  it on a baseline operation is a load failure.
- `timeout` — optional, 1-86400 seconds. The operation's own time budget; a run
  that exceeds it is stopped and its raw output is still harvested. When absent,
  the per-binary configuration override applies, then the configured default.
  Every CTF operation declares one, and the operator's SPEED choice at the start
  of a CTF run scales it (fast = a third, never under 10 s; deep = double).
- `probe` — optional, default `false`. Marks an operation whose non-zero exit is
  an *answer*, not a failure: a decoder handed non-base64, an extractor handed a
  non-archive, a grep that found nothing. Such a run completes as
  `PROBE_NEGATIVE` with its raw output preserved as evidence. Only a
  process-level failure to launch still counts as a failure. Every CTF
  operation is a probe — in a hunt, a negative answer is a result.

## How templates become commands

`src/catalog.rs` (`Operation::command`) resolves `args` with validated inputs:

- Full-token placeholders: `{domain}` → one argv token, however much
  whitespace the value contains.
- Embedded placeholders: `--rate={rate}`.
- Literal brace escapes: `{{` and `}}`.
- Literal printf-style tokens like `%{http_code}` are preserved.
- Wordlist references: `{wl:ssh/passwords.txt}` → the absolute path of that file
  inside `wordlists/`.

Commands are built as argument vectors, not shell strings.

## Placeholders versus payload braces

A placeholder is an identifier: it starts with a letter or underscore and
contains only letters, digits, underscores and hyphens. That is what lets a
capability receive `{target}` and `{sudo-password}` while the payloads below pass
through untouched:

| Token | Read as |
|---|---|
| `{domain}` | an input reference |
| `{db-pass}`, `{sudo-password}` | an input reference |
| `{10,}`, `{35}`, `{0,20}` | a regex quantifier |
| `{"role":"admin"}` | a JSON body |
| `{wl:web/common.txt}` | a bundled wordlist |
| `{wlroot}` | the wordlist directory itself |

If an input reference is not declared, the catalog does not load. If a wordlist
reference does not resolve, the load succeeds with a note and the capability
becomes unavailable — the operator can fix it by running the fetcher.

## Wordlist references

```toml
[[capability.provider.operation]]
name = 'SSH Brute'
args = ['-t', 'ssh', '-l', '{wl:ssh/users.txt}', '-P', '{wl:ssh/passwords.txt}', '{rhost}']
```

- `{wl:<path>}` is a path relative to `wordlists/`.
- Resolution order: `$TSEC_WORDLIST_ROOT`, then `<install root>/wordlists`, where
  the install root is the directory containing `catalog/`.
- A reference may be a whole argument or embedded (`-l{wl:web/common.txt}`).
- A reference containing `..` that would escape the corpus is refused.
- `{wlroot}` resolves to the corpus directory, for capabilities that report on
  it rather than consume an entry.

**Never add a capability that asks the operator for a wordlist path.** The corpus
is a property of the framework. A capability that needs a list names it, and the
list is either present or reported missing by name.

Pick the corpus that matches the attack. `passwords/rockyou.txt` is for offline
hash cracking; an SSH password spray wants `ssh/passwords.txt`, a WPA handshake
wants `wifi/passphrases.txt`, and an SMB spray wants `smb/passwords.txt`. See
[`../wordlists/README.md`](../wordlists/README.md) for the full table.

## How to edit an existing operation

1. Open `catalog/capabilities.toml`.
2. Find the capability and provider operation block.
3. Update `args`, `output`, and/or `network`.
4. Keep placeholders aligned with declared `inputs`, and wordlist references
   inside the corpus.
5. Validate:
   ```sh
   cargo fmt --check
   cargo clippy --all-targets -- -D warnings
   cargo test
   ./target/debug/tsec --status
   ```

## How to add an operation

1. Add a new `[[capability.provider.operation]]` block under an existing provider.
2. Set unique `name` within that provider block.
3. Set `args` with valid placeholders.
4. Set correct `output` parser type.
5. Set `network = true/false` based on whether the command reaches the network.
6. Set `stage` (1-3) and, for gated work, `confirm = true` on stages 2-3 only.
7. Run the validation commands above.

## How to add a provider to a capability

1. Add a new `[[capability.provider]]` block with `binary = "<tool>"`.
2. Add one or more `[[capability.provider.operation]]` blocks beneath it.
3. A provider block with no operations is a load failure — if you have nothing
   new to say for that binary, do not add the block.
4. Validate with the status/test pipeline.

## Argument vectors, not shell command lines

Arguments are passed as a vector and never through a shell, so shell syntax in an
argument is inert. That cuts two ways, and both matter when writing `args`:

**Never split a pipeline across array elements.** `['--list', 'formats', '|',
'grep', 'vba']` passes the three characters `|`, `grep` and `vba` to the tool as
flags and filenames. It runs, finds nothing, and reports a clean result. The
loader reports this as a catalog note, because no tool takes a shell operator as
an argument.

**Shell metacharacters inside a larger token are fine and often required.** A
URL query string (`?q={domain}&output=json`), an LDAP filter (`(objectClass=*)`),
an XML entity, a SQL statement and a log4j payload (`${jndi:ldap://…}`) all
carry them, and they reach the tool exactly as written.

The one case where a shell *is* correct is a remote command: `ssh user@host 'mkdir
-p ~/.ssh && cat >> ~/.ssh/authorized_keys'` is a single argument, because the
remote end interprets it. Chain operators belong inside that one argument, not
split across the vector.

## What the operation's output becomes

`output` decides how the *shape* is understood. It does not decide what is looked
for: `src/intel.rs` scans every line of every artifact regardless, so a leaked
key in an access log, a credential in a `raw` report and a session cookie in an
`http-post-form` dump are all recovered.

```toml
[[capability.provider.operation]]
name = 'Access Log Sweep'
args = ['-f', '/var/log/nginx/access.log']
output = 'raw'          # the format is not understood...
```

…and the `Set-Cookie:` header and the `admin:hunter2` pair in the same file are
still reported under `COOKIES` and `CREDENTIAL PAIRS`.

Two things are deliberately not findings:

- **Progress and chatter.** Classified `Noise`, counted, excluded from the
  document, and stated as an excluded count. A line that both looks like progress
  and contains an artefact keeps the artefact.
- **Shape the regex cannot decide.** Hostnames, `host:port` and httpx bracket
  fields belong to the format parsers, which understand them properly.

## CTF runs: flag formats and the sidecar

The `ctf` phase adds one input type and one output artefact that the other phases
do not have.

## CTF runs: flag formats, speed and the sidecar

The `ctf` phase adds one input type, a speed choice, and one output artefact
that the other phases do not have.

**The `ctf_flag_format` input.** Inputs of this type compile through
`src/ctf.rs` before the run starts; a pattern that will not compile, or one with
no discriminating power, stops the run before any tool executes. The usual
spelling is a **bare word**: type the flag's prefix alone and the framework adds
the braces. The bare word `safctf` compiles three tiers of search:

- **Braced value** — the escaped prefix plus a bounded body,
  `safctf\{[^{}]{1,256}\}`, matched case-insensitively. This is the tier that
  finds the real flag value, e.g. `safctf{09x2kc249c235cg3v45554}`, and it is
  the only tier subject to the indiscriminate-pattern check.
- **Terms** — the prefix itself and derived words (including its `ctf` tail, so
  `safctf` also hunts `ctf`), word-bounded and case-insensitive. A bare
  `safctf` string without braces is a *flag lead*: the flag's vocabulary
  surfaced, so the value is probably close.
- **Flag shape** — any generic `word{body}` string, so a flag using a prefix
  you did not declare is still reported.

Two further spellings are accepted, decided by shape rather than a mode flag:

- **Shorthand** — `safctf{...}` or `flag{...}`: a literal, case-sensitive prefix
  ending in `{...}`. It expands to the escaped prefix plus a bounded identifier
  body (`safctf{...}` → `safctf\{[A-Za-z0-9_]{1,64}\}`), so it can never match
  everything.
- **Full regex** — anything carrying regex operators, compiled as written.
  Append `/i` for case-insensitive matching (`FLAG[0-9]+/i`); the suffix is
  stripped before compilation and never matches literally.

A pattern that matches the empty string, or matches ordinary text everywhere,
is refused: a pattern that matches everything turns every artifact into
thousands of false candidates. Reports and documents always show the real
matched value — the flag itself, never the pattern.

**The SPEED choice.** Every CTF run opens by asking `SPEED [fast / normal /
deep]`. The answer scales every operation's time budget for that run: `fast`
cuts each budget to a third (never below 10 seconds, so every tool still gets a
real attempt), `normal` keeps the declared budgets, `deep` doubles them for a
patient target. `Esc` at the prompt withdraws the capability, like every other
prompt.

**Extraction and classification.** Every raw artifact is scanned line by line
against the compiled pattern; each match is recorded with up to 250 characters
of surrounding context, so a candidate can be judged without re-running the
tool. Candidates are classified as verified (inside a value-shaped finding),
candidate (a bare match), or reviewed-out — the classification travels with the
match in the report. A CTF run harvests its failed tasks too: a tool that died
mid-dump may already have printed the flag, and a run interrupted by the
operator still shows everything the finished tools found.

**The hits engine.** Beyond the operator's flag pattern, `src/hits.rs` scans
every CTF run's raw evidence — completed and failed tasks, stdout, stderr and
every file in the artifacts directory — for everything else a hunt cares about:
hashes (md5/sha lengths, crypt and `$NT$` formats), `user=`/`password=`
credential pairs, private keys, API tokens, shell material (`/bin/sh`,
`pty.spawn`, meterpreter), suspicious endpoints, CVE identifiers, interesting
file names, and long base64 blobs. Each hit is deduplicated by class and value
and lands as an ordinary finding under its own heading (`HASHES`,
`CREDENTIAL PAIRS`, `SHELL MATERIAL`, …), so the document, `output.json` and
the next-steps brain all see it.

**Next steps.** The recommendation engine reads a CTF harvest with hunting
eyes: every hit class maps to the exact CTF category to run next with the
inputs to supply — a hash sends you to CRYPTO CHALLENGES with the hash or its
challenge file, a credential to ACTIVE DIRECTORY with the target, a flag lead
to FLAG SCANNING over this run. The steps appear in the document's NEXT STEPS
section and in `ctf.json` under `next_steps`.

**The `ctf.json` sidecar.** Every CTF run writes `ctf.json` beside
`manifest.json` and `output.json` — including runs where nothing matched, since
an empty candidate list is a result. It records the challenge context as the
operator declared it (flag format, `challenge_desc` objective,
`authorized_scope` statement), a command-by-command account of every attempted
operation with its outcome classification, every flag candidate with the
artifact path it came from, and `next_steps`: the exact follow-up
(capability, why, and what to feed it) derived from the run's hits. Every claim
in the CTF report can be checked against the bytes a tool actually produced.

**FLAG SCANNING.** The fifteenth CTF category sweeps *finished* runs rather
than a live target. It replaces the ordinary input form with its own flow:

1. **Flag format** — the bare prefix word; the braces are added for you.
2. **Category** — which CTF category's evidence to sweep (a picker of the
   other fourteen).
3. **Run** — one recorded run of that category, listed by name.

The sweep patterns are composed at input time from the validated word — the
catalog only names `{braced_pattern}` and `{shape_pattern}` as inputs; the
regex brace literals never pass through the placeholder grammar. The run's
grep and ripgrep operations then sweep the recorded raw evidence for
the braced flag value, the bare prefix, and any flag-shaped string, writing the
matched lines to the run document. Flag scanning needs nothing but evidence:
it is how a hunt that stalled is revived from what earlier runs already
captured.

**Stages in a CTF run.** The same 1-3 staging applies: baseline enumeration on
stage 1, decoding and analysis on stage 2, consequential actions (a downloaded
payload being executed, a service being restarted) on stage 3 behind
`confirm = true`. A stage whose predecessor completed nothing is withdrawn
rather than run — the usual CTF shape is that stage 2 has nothing to decode
until stage 1 has dumped something.

## Common failure points

| Symptom | Cause |
|---|---|
| Catalog will not load: `undeclared input {x}` | `{x}` is not in this capability's `inputs` |
| Catalog will not load: `not one of the eleven phases` | `phase` is misspelled, or a phase was renamed |
| Catalog will not load: `has no operations` | A `[[capability.provider]]` block with nothing under it |
| Catalog will not load: `escapes the wordlist directory` | A `{wl:…}` reference uses `..` |
| `RUN ABORTED` naming the flag format | The `ctf_flag_format` input did not compile, or had no discriminating power |
| A CTF task reads `PROBE_NEGATIVE` | A probe operation exited non-zero: the tool ran, its premise was wrong (nothing to decode, nothing to extract). Its raw output is still evidence |
| Stage 2 or 3 shows `STAGE_WITHDRAWN` | The previous stage completed nothing, so the dependent stage was not run |
| `CATALOG NOTES` in `--status` names an operation | Its `args` contains a shell operator as a whole argument |
| Capability shows as unavailable, reason names a wordlist | Run `wordlists/fetch-wordlists.sh`, or set `TSEC_WORDLIST_ROOT` |
| Wrong `output` mode | Parser failures and poor harvesting; match the tool's real format |
| Provider not installed | Installed in the background; if that fails, recorded as `TOOL_NOT_FOUND` and skipped, never as a failed task |
| An artefact looks wrong in the harvest | `output` mode, or the pattern in `src/intel.rs`, is wrong for that tool — check the raw artifact |
