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
6. Run the validation commands above.

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

## Common failure points

| Symptom | Cause |
|---|---|
| Catalog will not load: `undeclared input {x}` | `{x}` is not in this capability's `inputs` |
| Catalog will not load: `not one of the ten phases` | `phase` is misspelled, or a phase was renamed |
| Catalog will not load: `has no operations` | A `[[capability.provider]]` block with nothing under it |
| Catalog will not load: `escapes the wordlist directory` | A `{wl:…}` reference uses `..` |
| `CATALOG NOTES` in `--status` names an operation | Its `args` contains a shell operator as a whole argument |
| Capability shows as unavailable, reason names a wordlist | Run `wordlists/fetch-wordlists.sh`, or set `TSEC_WORDLIST_ROOT` |
| Wrong `output` mode | Parser failures and poor harvesting; match the tool's real format |
| Provider not installed | Installed in the background; if that fails, recorded as `TOOL_NOT_FOUND` and skipped, never as a failed task |
| An artefact looks wrong in the harvest | `output` mode, or the pattern in `src/intel.rs`, is wrong for that tool — check the raw artifact |
