# TSEC 3.0 troubleshooting

Every failure reports the stage it happened in, a stable error code, and — where
the tool said something useful — the tool's own message. The same code is
recorded in `manifest.json`, so a run can be explained long after it happened.

The `OUTPUTS` panel leads with how the tasks ended and the codes they ended
with. Read that first: `10 FAILED` with `ONIUX_UNAVAILABLE x10` means nothing
reached the network, not that the network was empty.

---

## The network boundary

### `ONIUX_UNAVAILABLE`

> Oniux network boundary required for `<tool>` is unavailable: *reason*

The framework will not run a network command outside oniux. The tool was not
started — not on the host network, and not at all.

**Diagnose:**

```sh
command -v oniux
oniux /bin/true; echo "exit=$?"
```

| What you see | Meaning | Fix |
|---|---|---|
| `oniux: command not found` | Not installed | `paru -S oniux`, or `cargo install --git https://gitlab.torproject.org/tpo/core/oniux --tag v0.4.0 oniux` |
| `Failed to open tun interface, is tun kmod loaded?` | `tun` module missing | `sudo modprobe tun` |
| `Operation not permitted` / namespace errors | Unprivileged user namespaces disabled | `sysctl -w kernel.unprivileged_userns_clone=1`, and where present `sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` |
| Hangs, then nothing | Tor cannot bootstrap | Check outbound connectivity and DNS; oniux brings up its own client |
| Works in a shell, but TSEC says unavailable | The binary is not on the search path TSEC sees | Set `execution.oniux_binary` to an absolute path, or add the directory to `tools.search_paths` |

**Where the check happens.** The engine runs the `/bin/true` probe itself,
immediately before the first network task of a run. The result is remembered for
the rest of that run: nothing in the interface can skip it, and fixing the
environment mid-run does not unblock the tasks of the run in progress. On
success nothing is printed — the only thing worth saying is that it failed.

**Which capabilities are affected.** Anything the catalog marks
`network = true`, which is nearly everything. Operations marked `network =
false` are the local ones (`EVIDENCE PRESERVATION`, `TRANSFER INTEGRITY`, parts
of `PERSISTENCE`) and they run regardless.

## Providers

### `TOOL_NOT_INSTALLED`

The capability is listed with `[PROVIDER MISSING]`, and selecting it immediately opens
the Arch Linux installation guidance panel (`install::advise`), querying `pacman -Si`
and AUR helpers (`yay`, `paru`) to display the exact installation command.

```sh
sudo pacman -S <package>       # Official Arch repos
yay -S <package>               # Arch User Repository (AUR)
tsec --status                  # Verify availability across all 10 phases
```

### `TOOL_VERSION_INCOMPATIBLE`

The tool is installed, but it rejected the invocation the catalog describes —
usually a flag renamed by a major release. The tool's own message is in
`raw/<stem>.err` and in the manifest.

```sh
<tool> --help
```

Then fix the operation in `catalog/capabilities.toml` and prove the catalog
still loads:

```sh
cargo test
```

### A capability is dimmed but the tools are installed

Resolution checks the search paths first, then `PATH`, and requires the file to
be executable. A tool installed only for another user, or a `bin` directory not
on the service manager's `PATH`, will not resolve. Point `tools.search_paths` at
its directory.

## Execution

### `SPAWN_FAILED`

The tool could not be started: wrong path, bad interpreter, missing shared
library.

```sh
ldd "$(command -v <tool>)" | grep "not found"
```

### `EXIT_STATUS`

The tool ran and exited non-zero. Its stderr is in `raw/<stem>.err` and its exit
code is in the manifest. A non-zero exit often means the tool accepted a flag the
target rejected — read the stderr before concluding the target was unreachable.

### `TIMEOUT`

The tool exceeded `execution.timeout_secs` and its process group was terminated
(`SIGTERM`, then `SIGKILL` after `kill_grace_ms`). Partial output is kept, and is
usually worth reading before raising the timeout.

### `INTERRUPTED`

`Ctrl+C`. The process group was terminated and everything gathered so far was
kept. The run is still a valid run: the manifest is complete up to that point.

### `IO_FAILURE`

Usually a permissions or space problem writing under `general.output_dir`.

```sh
ls -ld /opt/tsec/output
df -h /opt/tsec
```

### Runs feel slow, or use a lot of memory

Expected. Every network task is its own oniux process with its own Tor client —
that is what per-task isolation costs. Lower `execution.max_concurrency` (default
6) to reduce peak memory; raise it to trade memory for wall clock. The first task
after boot is the slowest; later ones reuse a warm Tor directory.

## Parsing and harvest

### `0 FINDINGS` with tasks marked complete

The tool probably wrote to its own output file rather than stdout. Check the raw
capture and its size:

```sh
wc -c /opt/tsec/output/<run-id>/raw/<stem>.out
```

An empty file with `exit_code = 0` means the flags produced no output — usually a
target that resolved to nothing, or an argument vector that still contains an
unsplit shell operator (see `CATALOG NOTES` above).

### `PARSER_FAILURE`

The declared `output` format does not match what the tool emitted. Look at the
first bytes of the raw file and correct `output` for that operation
(`nmap`, `json`, `lines`, `raw`).

### Output was truncated

An artifact larger than 32 MiB is truncated, and the truncation is recorded as a
note and a finding. The raw file still holds everything; narrow the scan rather
than raising the cap.

### Findings look wrong

They are checkable. Each finding names the providers that reported it, and the
manifest holds the exact redacted command:

```sh
grep -n '<value>' /opt/tsec/output/<run-id>/raw/<stem>.out
```

Nothing is written to `harvest.txt` that is not in a raw file.

## Configuration

### `CONFIG_ERROR`

The message names the key. Common causes: `color` that is not
`auto`/`always`/`never`, `max_concurrency` of zero, an empty
`execution.oniux_binary`, or a path that cannot be created.

### A config from an older release was rewritten

Expected. Keys describing a SOCKS proxy (`[anonymity]`, `torsocks_binary`,
`tor_socks_proxy`) are dropped with a note, because oniux has no endpoint to
configure. `version` is bumped to `3` and everything else is preserved.

### `CATALOG_ERROR`

`catalog/capabilities.toml` is malformed, or the file is not valid TOML at all.
The message names the capability and the reason.

**Structural rejections** — these stop startup:

- a phase that is not one of the ten, or a phase with no capabilities;
- a capability id declared twice, or not namespaced under its own phase;
- a label that is not one to three uppercase words;
- an input declared twice, or required *and* carrying a default;
- a placeholder with no matching input;
- a `{wl:...}` reference that tries to escape the corpus;
- a capability with no providers, or a provider block with no operations.

**Notes, not rejections** — these load and are reported by `tsec --status`:

- a wordlist reference naming a list that is not on disk;
- an argument that *is* a shell operator (`|`, `&&`, `2>/dev/null`, …) as a
  whole argv entry.

A common TOML failure: a shell single-quote escape (`'"'"'`) or a bare `\'`
inside a `'…'` string. TOML literal strings cannot contain a single quote at
all. Use a double-quoted `"…"` string for a value that needs one.

## Wordlists

### `WORDLISTS` in `--status` lists missing files

The catalog references a corpus that is not installed. Every list except four
ships in the repository, so this means a partial install or a relocated corpus.

```sh
./wordlists/fetch-wordlists.sh     # the four that are too large to commit
./wordlists/verify-wordlists.sh    # what is present, and whether it is intact
```

If the corpus lives somewhere else entirely:

```sh
TSEC_WORDLIST_ROOT=/srv/tsec-wordlists tsec --status
```

The rest of the capability still runs; only the operations that need the absent
list are withheld, and the capability is reported unavailable by name rather than
being pointed at a different corpus.

### A capability is unavailable and the reason names a wordlist

Working as intended. Run the fetcher, or set `TSEC_WORDLIST_ROOT`.

### A tool ran and returned nothing

Check whether its `args` still contains a shell operator split across array
elements. `['--list', 'formats', '|', 'grep', 'vba']` hands the tool three
filenames and finds nothing while exiting cleanly. `tsec --status` lists every
operation where this happens under `CATALOG NOTES`.

Shell metacharacters *inside* a larger argument are fine and often required: a
URL query string, an LDAP filter, an XML entity, a SQL statement. The only place
a shell is correct is a remote command — `ssh user@host 'mkdir -p ~/.ssh && cat
>> ~/.ssh/authorized_keys'` is a single argument, because the remote end
interprets it.

## The interface

### `Esc` does nothing

A bare `Esc` is only distinguishable from the start of an escape sequence once
the terminal has stopped sending bytes. Terminals and multiplexers differ here;
`J` and `←` close a box or navigate back in exactly the same way, and always work.

### Accidental cancellation

During execution, `Ctrl+C` triggers an interactive prompt:
`Stop ongoing operations? [y/N]` (default `N`).
Hitting Enter defaults to `N` and resumes execution monitoring without disruption.
To cancel an input prompt before execution, `Ctrl+C` cleanly returns to the menu.

### Colours are wrong, or absent

`general.color` and the environment decide this:

```sh
NO_COLOR=1 tsec         # no colour at all
TSEC_PALETTE=graphite tsec
```

`COLORFGBG` is consulted to pick a light or dark palette when it is set.

### The box is drawn too narrow

Boxes automatically adapt to full terminal width (`inner = cols - 2`) and re-calculate
on resize. If running in a subshell or multiplexer without SIGWINCH forwarding, resize
the window to trigger a redraw.

## Still stuck

Gather this much before asking:

```sh
tsec --status                            # availability and the boundary
oniux /bin/true; echo "exit=$?"          # does the boundary work at all
<tool> --help                            # does the flag the catalog names exist
cat /opt/tsec/output/<run-id>/manifest.json  # what ran, and how it ended
cat /opt/tsec/output/<run-id>/raw/<stem>.err # what the tool said
```

---

TSEC 3.0 — terminal cybersecurity operations platform, built by funbinet.
© funbinet. All rights reserved.
