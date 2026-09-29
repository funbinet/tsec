# TSEC troubleshooting

Every failure TSEC reports names the stage it happened in, a stable error code,
and — where relevant — the underlying tool's own message. This document maps the
codes and messages to what to actually do.

---

## The network boundary

### `ONIUX_UNAVAILABLE`

> Oniux network boundary required for `<tool>` is unavailable: *reason*

The framework refuses to run a network command outside oniux. This error means
the boundary is missing or could not start. It is never bypassed.

**Diagnose:**

```sh
command -v oniux
oniux /bin/true
```

| What you see | Meaning | Fix |
|---|---|---|
| `oniux: command not found` | Not installed | `paru -S oniux`, or `cargo install --git https://gitlab.torproject.org/tpo/core/oniux --tag v0.4.0 oniux` |
| `Failed to open tun interface, is tun kmod loaded?` | `tun` module missing | `sudo modprobe tun` |
| `Operation not permitted` / namespace errors | Unprivileged user namespaces disabled | `sysctl -w kernel.unprivileged_userns_clone=1` and, where present, `sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` |
| Permission denied on `/etc/resolv.conf` | The bind mount needs a mount namespace | Usually the userns problem above; check `dmesg` |
| Hangs, then no output | Tor bootstrap cannot complete | Check general connectivity and DNS; the boundary brings up its own client |

### The probe

TSEC runs the `/bin/true` probe itself, inside the engine, immediately before
the first network-capable task. It is not something a caller may skip and not
something a configuration file may disable: the function that spawns anything is
the function that performs the check. The result is remembered for the rest of
the run, so a burst of concurrent tasks pays for one probe rather than one each.

The error therefore surfaces at the first network task, not scattered across the
capability. On success nothing is reported, because the only thing worth saying
is that the boundary works.

### `ONIUX_UNAVAILABLE`

The boundary could not be proven usable. The tool was not started: not on the
host network, and not at all. Resolve the cause from the table above and start a
new run — a failed probe is remembered for the life of the run, so fixing the
environment mid-run does not unblock tasks that are still to come.

---

## Providers and capabilities

### `TOOL_NOT_INSTALLED`

The capability is reported unavailable with the missing provider named.

```sh
sudo pacman -S <tool>          # Arch
```

Or see [`REQUIREMENTS.TXT`](../REQUIREMENTS.TXT) for the package name and the
version the catalog was verified against.

### `TOOL_VERSION_INCOMPATIBLE`

The tool is installed, but its help output does not document the flags the
catalog uses. Common after a major tool release renamed something.

```sh
<tool> --help
```

Then update the catalog entry and re-verify:

```sh
python3 scripts/verify_catalog.py
```

The framework will not run a flag the installed binary does not document.

### A capability says "unavailable" but every tool is installed

Re-run the verifier. The catalog is only offered when the operation verifies
against the *installed* version:

```sh
python3 scripts/verify_catalog.py
```

Look for `unknown flag` or `missing subcommand` in its output.

---

## Execution

### `SPAWN_FAILED`

The tool could not be started: wrong path, bad interpreter, or a missing shared
library.

```sh
ldd "$(command -v <tool>)" | grep "not found"
```

### `EXIT_STATUS`

The tool ran and exited non-zero. Its stderr is preserved in
`raw/<task>.err` and the exit code is in the manifest. A non-zero exit often
means a flag the tool accepts but the target rejected — read the stderr before
concluding the target was unreachable.

### `TIMEOUT`

The tool exceeded `execution.timeout_secs` and its process group was terminated
(`SIGTERM`, then `SIGKILL` after `kill_grace_ms`). Its partial output is
preserved — check the raw file before raising the timeout.

### `INTERRUPTED`

`Ctrl+C`. The tool was terminated as a process group and everything gathered so
far was kept. The run is still a valid run.

### Runs feel very slow

Expected. Each network task launches its own oniux, which boots its own Tor
client — that is what per-task isolation costs, and it is the property that
prevents one tool from observing another's traffic. The first boot after a
machine starts is the slowest; later ones use a warm Tor directory.

Adjust `execution.max_concurrency` (default 6) to trade memory for wall clock.

---

## Parsing and harvest

### A capability produced no findings

Usually the tool wrote to its own output file rather than stdout, or produced
nothing. Check the raw capture:

```sh
cat /opt/tsec/output/<run-id>/raw/T01.out
wc -c /opt/tsec/output/<run-id>/raw/T01.out
```

The harvest records unparsed and empty output explicitly rather than omitting
it, so "no findings" and "not reported" are distinguishable.

### Findings look wrong

They are checkable. Every finding names the tools that reported it, and the
manifest holds the exact command. Read the raw bytes:

```sh
grep -n '<value>' /opt/tsec/output/<run-id>/raw/T01.out
```

Nothing is written to `harvest.txt` that is not in a raw file.

### Output was truncated

An artifact larger than 32 MiB is truncated by the parser, and the truncation is
recorded as a note and as a finding. The raw file still holds everything; narrow
the scan (fewer ports, a smaller wordlist) rather than raising the cap.

---

## Configuration

### `CONFIG_ERROR` mentioning `oniux_binary`

`execution.oniux_binary` is empty. It must name the boundary executable.

### A v2 config was rewritten

Expected. `[anonymity]`, `torsocks_binary` and `tor_socks_proxy` describe a
SOCKS proxy; oniux is not one, so those keys are dropped on load and not
rewritten. Everything else in the file is preserved.

### `CATALOG_ERROR`

`catalog/capabilities.toml` is malformed — usually an unknown phase, a label
longer than three words, a placeholder with no matching input, or a template
containing a shell metacharacter. The error names the capability and the reason.

---

## Still stuck

Gather these before asking:

```sh
tsec                                    # startup output, including BOUNDARY line
oniux /bin/true; echo "exit=$?"         # does the boundary work at all
<tool> --version                        # is the version what you think it is
python3 scripts/verify_catalog.py       # what does the framework believe
cat /opt/tsec/output/<run-id>/manifest.json   # what actually ran, and how
cat /opt/tsec/output/<run-id>/raw/*.err      # what the tool said
```
