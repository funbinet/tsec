# TSEC architecture

This document explains how the layers fit together and, more importantly, *why*
the boundaries between them are where they are.

---

## Layers

```
                    ┌──────────────────────────────┐
   operator  ──▶    │  catalog/capabilities.toml   │   declarative: what exists
                    └───────────────┬──────────────┘
                                    │ loaded + validated
                    ┌───────────────▼──────────────┐
                    │      src/catalog.rs          │   resolves + expands argv
                    └───────────────┬──────────────┘
                                    │ validated Command (no shell)
                    ┌───────────────▼──────────────┐
                    │    src/exec/launch.rs        │   ◀── THE boundary decision
                    │      src/exec/oniux.rs        │
                    └───────────────┬──────────────┘
                                    │ Launch { program, args, boundary }
                    ┌───────────────▼──────────────┐
                    │      src/exec/mod.rs          │   the ONE spawn site
                    └───────────────┬──────────────┘
                                    │ raw bytes on disk
                    ┌───────────────▼──────────────┐
                    │      src/parser.rs           │   findings + provenance
                    └───────────────┬──────────────┘
                                    │
                    ┌───────────────▼──────────────┐
                    │       src/store.rs            │   atomic, append-only
                    └──────────────────────────────┘
```

---

## The execution boundary

### Why oniux and not a proxy

A SOCKS proxy is advisory. A tool that ignores `ALL_PROXY` — or that opens a
raw socket, or that uses a protocol the proxy does not understand — reaches the
internet anyway. `torsocks` mitigates this with `LD_PRELOAD`, which is bypassable
and does not cover statically linked or unusual binaries.

oniux is not a proxy at all. It creates a **network namespace** containing a
single TUN interface whose default route is an embedded Tor client. A process
inside that namespace has no interface to send traffic through except Tor, so
"ignoring the proxy setting" is not a concept that applies.

This is why the framework treats it as an invariant rather than a feature.

### Why there is exactly one spawn site

`Runner::run` in `src/exec/mod.rs` is the only place in the codebase that calls
`Command::spawn`. It never receives a raw argv — it receives a validated
`Command` and asks the `Launcher` to plan it.

`Launcher::plan` has two branches:

- `cmd.is_network()` is false → return the command as-is (`Boundary::Local`)
- `cmd.is_network()` is true → resolve oniux, wrap, return (`Boundary::Oniux`)

There is deliberately no third branch, and the network branch has no error path
that returns the unwrapped command. A missing boundary is an `Err`, and the
caller records a failure. A capability cannot "forget" to route a command,
because routing is not something a capability does.

### Why the default is network-capable

`Command::new` sets `network: true`. A caller must write `.local()` to opt out.

The default could be the other way round, and both are defensible — but the
failure modes are asymmetric. A command wrongly sent through oniux costs a
namespace and some startup time. A command wrongly marked local puts a scan on
the host network, silently, and that is precisely the failure the whole design
exists to prevent. When in doubt, oniux is the correct answer.

### Preflight is enforced, not requested

Before the first network task, the framework proves the boundary works:

1. `oniux` resolves on `PATH` and is executable
2. `oniux --help` parses (it is really oniux)
3. `oniux /bin/true` runs and exits 0

Step 3 is the only honest test of "can this boundary establish its environment
right now" — it exercises the user namespace, `/proc`, the private `/tmp`, the
TUN device and the Tor bootstrap. Failure is fatal and is reported with oniux's
own stderr. There is no degraded mode.

The enforcement is the part that matters. This check lives inside `Runner::run` —
the single function that can spawn — not in a helper a caller is expected to
remember. There is consequently no path to a network tool that has not passed
it, and no configuration setting that skips it. The result is memoized on the
`Launcher` in a `tokio::sync::OnceCell`, so twenty concurrent tasks wait on one
probe instead of racing twenty of them; a *failure* is memoized too, so every
task in the run reports the same clear cause rather than a scatter of vaguer
ones.

Because the check cannot be bypassed, a task that fails it never reaches the
spawn. Its record still says `network: true` and `boundary: ONIUX`, so the
harvest distinguishes "this did not run because the boundary was down" from
"this did not run because the tool was broken".

### Tor stays outside the framework

oniux runs its own embedded Tor client, so the framework has nothing to
configure: no SOCKS port, no control port, no circuit settings. Tor is the
operating system's concern, exactly as it should be. The framework's only
responsibility is the routing invariant.

---

## Concurrency

Independent tasks in a plan run concurrently, bounded by
`execution.max_concurrency`. Each task gets:

- its own process group, so a timeout or `Ctrl+C` reaches the tool's children
- its own stdout and stderr files, written directly by the child through the
  kernel — never through a shared pipe, which would interleave concurrent output
  and can block a child once the buffer fills
- its own oniux process, and therefore its own namespace

That last point has a real cost: every network task boots a Tor client. The
isolation is per process, which is the property that matters, and the cost is
why `max_concurrency` defaults to a modest 6 rather than the CPU count.

Timeouts escalate `SIGTERM` → grace period → `SIGKILL`, addressed to the
negative pid so the whole process group dies. Cancellation is cooperative,
wakeable through a `Notify` rather than polled, so an interrupt is acted on
within milliseconds instead of at the next tick.

---

## The parser

`src/parser.rs` handles four output shapes, declared per operation in the
catalog:

| Format | Shape | Approach |
|---|---|---|
| `Nmap` | XML report | open-tag scanner, one finding per observation |
| `Json` | NDJSON (nuclei) | per-record field extraction |
| `Lines` | one finding per line | a classifier that recognises the shapes that occur |
| `Raw` | anything else | kept verbatim as evidence |

The `Lines` classifier is worth explaining. Different tools disagree about what
a line looks like — naabu emits `1.2.3.4:443`, httpx emits
`http://h [200] [title] [ip] [Tech:1.0]`, subfinder emits a bare hostname. Rather
than a bespoke parser per tool, the classifier recognises those shapes and keeps
anything it does not recognise **as evidence rather than dropping it**. Silently
losing a tool's output is how a framework becomes quietly untrustworthy.

Deduplication keeps every source: two tools reporting the same host produce one
finding listing both, with occurrence counts — not one finding pretending a
single tool said it. Order is deterministic so two runs over the same evidence
produce byte-identical harvests, which is what makes diffing runs meaningful.

---

## The store

`src/store.rs` writes everything under one directory per run, atomically:
write to a temporary file in the same directory, `fsync`, then `rename`.

`rename` within a directory is atomic on POSIX, so a concurrent reader sees
either the whole old file or the whole new one. A partial run is still a useful
run: the manifest is written after *every* task, not at the end, so an operator
who interrupts a long scan keeps everything that already finished.

Raw evidence is never rewritten by the parser. Anything derived goes in a
separate file, so a disputed finding can always be checked against the original
bytes.

---

## Verification model

Two independent gates stand between the catalog and the operator:

1. **`scripts/verify_catalog.py`** runs each catalog operation against the
   installed binary's help and reports unknown flags, missing subcommands and
   uninstalled providers.
2. **`src/provider.rs`** loads `catalog/verification.json` and offers an
   operation only when its provider resolves *and* its syntax verifies.

An operation whose command contains shell constructs is classified `suspect`,
never `verified`. The catalog loader independently rejects such templates, so a
`suspect` entry can never reach execution.

The reason this is two separate gates is that a framework which both authors and
grades its own data is not really checking anything. The Python script has no
knowledge of the Rust code; the Rust code has no knowledge of the script.

---

## Deliberate non-features

| Not present | Why |
|---|---|
| Anonymity toggle or mode | Anonymity is not a feature; the boundary is the invariant. |
| SOCKS endpoint configuration | oniux is not a proxy and has no endpoint. |
| A shell execution path | Templates needing one are rejected at load. |
| Automatic provider substitution | An unavailable capability says so. |
| Flag inference | Only flags a real binary documents are used. |
| Silent output truncation | A truncated artifact is recorded as truncated. |
