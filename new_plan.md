# TSEC — Target Architecture & Migration Map

> Architecture baseline prepared from the supplied TSEC snapshots on 2026-09-29. This is a design/implementation contract, not a claim that every provider is currently installed or every flag has been verified.

## 1. Executive decision

TSEC should be rebuilt as a **capability-centric, provider-backed, task-graph terminal framework** while preserving the ten-phase operator model and recovering the interactive terminal UI from the earlier implementation.

The old snapshot is the reference for the operator experience. The newer snapshot contains useful execution architecture, but it is incomplete as a product: it currently has only 15 authored capabilities, covers only 7 phases in the catalog, has no interactive menu module, and `main.rs` only prints availability/status information.

The correct target is therefore a **merge-and-recreate**, not a rollback and not a blind continuation of the 3.0 snapshot.

---
## 2. Snapshot findings

### Old snapshot: what must be recovered

The old Rust UI contains a real crossterm state machine: raw terminal mode, cursor hiding, boxed menus, scrolling selection, Enter/right to select, left/Escape/back, Home/Exit handling, numeric shortcuts, timeout override, output browsing, file actions, settings, result rendering and wait-for-key behavior. `src/ui/mod.rs` explicitly registers `menu`, `output`, `output_viewer`, `spinner` and `theme`.

The old `README.md` documents the actual historical key map as **Up/u, Down/j, Back/h/q/<, Select/k/Enter/Right**. The user's desired I/J/K/L layout is therefore treated as the new target key map rather than falsely claiming that the old archive already used it. The redesigned UI should support both arrow keys and the requested Vim-like I/J/K/L navigation, with Enter/Right selecting and Left/Escape backing out.

### New snapshot: what is worth keeping

- Declarative `catalog/capabilities.toml` rather than tool definitions embedded entirely in Rust.
- Provider verification and honest availability reporting.
- Argument-vector execution rather than `sh -c` command execution.
- A single execution spawn boundary.
- Bounded asynchronous concurrency and process-group cancellation.
- Oniux as a mandatory network boundary with no direct-network fallback.
- Structured execution records with provider, operation, status, timing and boundary provenance.
- Raw evidence preservation plus consolidated harvest generation.
- Atomic storage writes and resumable/partial-run manifests.
- Semantic terminal color roles and color-depth degradation.

### New snapshot: what must be corrected/recreated

- The interactive UI must be restored; `src/ui/mod.rs` cannot contain only `theme`.
- The startup path must enter the operator menu instead of printing availability tables and exiting.
- All ten phases must exist in the catalog and UI.
- The catalog must grow from 15 capabilities to at least 150 (15 per phase minimum; this design defines 160).
- Every capability must have at least five provider candidates and at least five execution operations, subject to real-world availability and verification.
- Capabilities must accept structured input schemas and pass those values to task builders.
- The current hardcoded palette families are not the Omarchy adapter; the Bash adapter behavior must be recreated as a Rust theme-source adapter.
- Oniux version assumptions must be verified at runtime/install time rather than freezing the framework to one historical CLI revision.
- The operator-facing result must be a single consolidated artifact per capability execution, even if internal raw evidence is stored separately.

---
## 3. Target architecture

```text
TSEC
 │
 ├── INTERACTIVE TERMINAL UI
 │     ├── PHASE MENU
 │     ├── CAPABILITY MENU
 │     ├── INPUT FORM
 │     ├── EXECUTION MONITOR
 │     ├── RESULT VIEW
 │     └── OUTPUT BROWSER
 │
 ├── CAPABILITY CATALOG
 │     ├── 10 PHASES
 │     ├── 16+ CAPABILITIES / PHASE
 │     ├── INPUT SCHEMAS
 │     ├── PROVIDER CANDIDATES
 │     └── EXECUTION OPERATIONS
 │
 ├── PLANNER
 │     ├── INPUT RESOLUTION
 │     ├── PROVIDER AVAILABILITY
 │     ├── OPERATION VERIFICATION
 │     └── TASK DAG
 │
 ├── EXECUTION ENGINE
 │     ├── BOUNDED CONCURRENCY
 │     ├── DEPENDENCY CONTROL
 │     ├── TIMEOUT / CANCEL
 │     └── ONIUX NETWORK BOUNDARY
 │
 ├── HARVEST ENGINE
 │     ├── PROVIDER PARSERS
 │     ├── NORMALIZATION
 │     ├── DEDUPLICATION
 │     ├── CORRELATION
 │     └── PROVENANCE
 │
 ├── ARTIFACT STORE
 │     ├── PRIMARY CONSOLIDATED TXT
 │     ├── MACHINE JSON
 │     ├── RAW EVIDENCE
 │     └── MANIFEST
 │
 └── ADAPTIVE THEME
       ├── OMARCHY
       ├── CATPPUCCIN
       ├── BASE16/BASE24
       ├── PYWAL
       ├── GENERIC TOML/JSON
       └── FALLBACK
```

### Core rule

The operator chooses **what they want to accomplish**. TSEC chooses **how it is implemented**. A tool/provider is never the primary navigation abstraction.

---
## 4. Domain model

- **Phase** — One of the ten fixed operator phases.
- **Capability** — A concrete operator objective inside a phase.
- **InputSchema** — Typed, validated values required by a capability.
- **Provider** — An installed external implementation capable of performing an operation.
- **Operation** — One verified provider invocation strategy; one provider may expose many operations.
- **ExecutionTask** — A scheduled instance of an operation with resolved inputs and dependencies.
- **Finding** — A normalized observation with provenance.
- **Asset** — A normalized target entity such as domain, IP, host, service, URL, identity or wireless network.
- **Artifact** — A durable output produced by the run.
- **Theme** — A normalized semantic terminal palette independent of its source.
- **Boundary** — The network-execution isolation decision; network tasks are ONIUX, local tasks are LOCAL.

---
## 5. Operator UI contract

Typing `tsec` must open the interactive interface, not a diagnostic/status page.

```text
╔══════════════════════════════════════════════════════════════╗
║                         TSEC                                ║
╠══════════════════════════════════════════════════════════════╣
║  > RECONNAISSANCE                                          ║
║    ATTACK SURFACE MAPPING                                  ║
║    VULNERABILITY ASSESSMENT                                ║
║    PAYLOAD DEVELOPMENT & DELIVERY                          ║
║    PRIVILEGE ESCALATION                                    ║
║    CREDENTIAL ACCESS                                       ║
║    LATERAL MOVEMENT                                        ║
║    PERSISTENCE & DEFENSE EVASION                           ║
║    ACTIONS ON OBJECTIVES                                   ║
║    WIRELESS HACKING                                        ║
╚══════════════════════════════════════════════════════════════╝
```

Navigation target: Arrow keys and **I/J/K/L**. I = up, K = down, J = left/back, L = right/select. Enter selects. Escape/Left backs out. `#` returns home. `x` exits. Numeric shortcuts may select visible items. The UI must also retain safe Ctrl+C cancellation and terminal restoration.

The UI should have no `ANONYMITY: ON/OFF` banner. It may show a neutral execution-boundary status such as `BOUNDARY: ONIUX READY` when relevant; the boundary is infrastructure, not a user-selectable mode.

### UI states

1. Home / phase selection
2. Capability selection
3. Structured input collection
4. Plan preview
5. Task execution monitor
6. Harvest/result view
7. Output browser
8. Settings
9. Help/keymap

---
## 6. Capability execution contract

Every capability follows this lifecycle:

```text
operator input
    ↓
schema validation
    ↓
provider availability + syntax verification
    ↓
execution plan
    ↓
task DAG
    ↓
bounded concurrent execution
    ↓
provider-specific parsing
    ↓
normalized assets/findings
    ↓
deduplicate + correlate + provenance
    ↓
single consolidated operator artifact
```

A capability must not be considered complete merely because a provider exited 0. Completion means the tasks were executed, output was captured, parsing/harvesting was attempted, and the result artifact was written with provenance.

---
## 7. Command model

A capability can contain multiple providers. A provider can contain multiple operations. Therefore:

```text
CAPABILITY
  ├── PROVIDER A
  │     ├── OPERATION 01
  │     ├── OPERATION 02
  │     └── OPERATION 03
  ├── PROVIDER B
  │     ├── OPERATION 04
  │     └── OPERATION 05
  └── ...
```

The design minimum is **5 provider candidates and 5 executable operations per capability**. These are minimums, not a requirement to run exactly five. If ten independent operations are useful, the scheduler may run all ten within the configured concurrency/resource limits.

Exact flags must never be guessed. Catalog entries should contain structured argv templates and be accepted only after the verification layer checks the installed binary's supported syntax. This is superior to embedding fragile shell pipelines in a string.

### Example low-risk command contract

```text
Capability: SUBDOMAIN DISCOVERY
Input: domain=example.com

subfinder  → passive discovery argv(domain)
amass      → passive/active discovery argv(domain)
findomain  → domain discovery argv(domain)
assetfinder→ hostname discovery argv(domain)
theHarvester→ public-source hostname discovery argv(domain)
```

The catalog stores the exact argv arrays after verification; the UI never asks the operator to choose these tools.

For high-impact capabilities, the catalog should prefer assessment/validation operations and explicit authorization gates rather than embedding uncontrolled autonomous attack chains.

---
## 8. Storage contract

The operator-facing result is **one primary file per capability execution**, named deterministically:

```text
YYYYMMDD_HHMMSS_PHASE_CAPABILITY.txt
```

Example:

```text
20260929_160412_RECONNAISSANCE_SUBDOMAIN_DISCOVERY.txt
```

That file is the clean harvested result—not raw provider logs. Internal evidence may still be retained underneath the run store because provenance and dispute resolution require it.

Recommended internal layout:

```text
/opt/tsec/output/
  20260929_160412_RECONNAISSANCE_SUBDOMAIN_DISCOVERY.txt   ← operator artifact
  runs/
    20260929_160412_ab12/
      manifest.json
      harvest.json
      raw/
        T01.out
        T01.err
        T02.out
        T02.err
```

The UI should expose the primary TXT immediately and provide an optional `VIEW EVIDENCE` action for the underlying raw streams.

---
## 9. Parsing, normalization and harvesting

Raw output is evidence. It is not the final product.

The parser layer should support:
- Nmap XML
- JSON / NDJSON
- CSV
- line-oriented discovery output
- HTTP fingerprint output
- TLS output
- PCAP/CAP metadata
- provider-specific structured formats
- raw/unparsed evidence

Every parser emits normalized observations such as:

```text
Domain
IP
Host
Port
Service
URL
Technology
Certificate
Identity
CredentialMetadata
CloudAsset
WirelessNetwork
WirelessClient
Finding
Evidence
```

Deduplication must retain all sources. If five providers report the same host, the harvest contains one normalized host with five provenance records—not five visually duplicated lines and not one line pretending there was one source.

Correlation should link objects across capabilities. For example:

```text
SUBDOMAIN DISCOVERY
  api.example.com
       ↓
DNS INTELLIGENCE
  203.0.113.10
       ↓
PORT DISCOVERY
  443/tcp
       ↓
HTTP SERVICE DISCOVERY
  https://api.example.com
       ↓
TECHNOLOGY MAPPING
  observed technology
       ↓
VULNERABILITY ASSESSMENT
  finding + evidence
```

---
## 10. Adaptive theme architecture

The Bash Universal Theme Adapter is the **behavioral reference**, not Rust source to translate line-by-line.

The Rust design must be:

```text
ThemeSourceDetector
      ↓
ThemeAdapter
      ↓
NormalizedPalette
      ↓
Semantic TSEC Theme
      ↓
UI Renderer
```

### Source priority
1. Omarchy active theme (`omarchy theme current` / `omarchy theme dir` where available)
1. Catppuccin theme data
1. Base16/Base24 palette data
1. Pywal palette data
1. generic TOML/JSON palette sources
1. terminal/environment hints
1. TSEC fallback palette

The current 3.0 `theme.rs` does **not** implement this. It selects among hardcoded palette families (`Midnight`, `Graphite`, `Solarized*`, etc.) based mainly on `TERM`, `COLORFGBG` and `TSEC_PALETTE`. That is a useful semantic-color renderer, but it is not the agreed Omarchy adapter. Keep its color-depth degradation and semantic-role design; replace its palette-source detection with the adapter architecture above.

Semantic roles should include at least:
`background`, `foreground`, `muted`, `primary`, `secondary`, `accent`, `success`, `warning`, `error`, `info`, `border`, `highlight`, `selected`, `disabled`, `header`, `progress`.

---
## 11. Oniux execution boundary

Every operation marked `network = true` must pass through the network boundary. No capability, provider or command may call the OS spawn API directly.

```text
Capability task
    ↓
Runner
    ↓
Launcher
    ├── LOCAL  → direct argv
    └── NETWORK → ONIUX → provider argv
```

There is no `anonymity_enabled` switch and no direct-network fallback. A network task without a working Oniux boundary fails before launch.

### Important correction to the current implementation

The supplied 3.0 code documents itself against Oniux v0.4.0, but current Tor Project documentation now describes Oniux v0.10.0 and still documents the core model as a Linux namespace/Tor isolation tool. Therefore the final implementation must perform **runtime capability/version detection and install-time verification**, rather than assuming the v0.4.0 CLI forever. The official Tor Project documentation currently lists `oniux <CMD>` usage and v0.10.0 installation guidance. citeturn1search7

The 3.0 preflight idea is good and should remain: resolve the binary, verify its identity, run a harmless boundary probe, and refuse any network task when the boundary cannot be established. Tor Project describes Oniux as namespace-based isolation for arbitrary Linux applications. citeturn1search0turn1search7

Do not start or stop the host Tor service as part of TSEC. Oniux owns its transport boundary; TSEC owns enforcement of the boundary.

---
## 12. Ten-phase capability map

Read the new_plan_phase_1-5.md and new_plan_phase_6-10.md

---
## 13. Capability input model

The input system must be typed rather than string-only. Recommended input kinds:

- `domain`
- `hostname`
- `IP`
- `CIDR`
- `URL`
- `port set`
- `target`
- `file`
- `directory`
- `username`
- `password/secret (sensitive)`
- `hash`
- `wordlist`
- `interface`
- `capture file`
- `session`
- `LHOST/LPORT (sensitive operational input)`
- `cloud account/context`
- `repository`
- `API token (secret)`
- `custom constrained value`

Inputs are collected once per capability and referenced by tasks. A capability may request one input and fan it into ten operations, or request several inputs where different tasks need different subsets.

---
## 14. Execution scheduling

The scheduler should model dependencies explicitly. Example:

```text
T01 passive discovery ─────┐
T02 certificate discovery ─┼──> T06 normalized host set ──> T07 HTTP discovery
T03 DNS discovery ─────────┤                                  │
T04 search discovery ──────┘                                  ├──> T08 technology
T05 provider enrichment ─────────────────────────────────────┘
```

T01–T05 may run concurrently. T06 waits for their outputs. T07/T08 consume normalized assets. This is the difference between useful concurrency and simply spawning every command at once.

Required scheduler properties: bounded concurrency, per-provider limits, task dependencies, timeout, cancellation, process-group termination, failure isolation, deterministic task IDs, progress reporting and resumable manifests.

---
## 15. Provider verification

The new snapshot's idea of two independent verification gates is retained and strengthened:

1. Resolve the provider executable.
2. Determine installed version where possible.
3. Verify each operation's argv against the provider's documented/help-supported syntax.
4. Reject shell constructs from the catalog.
5. Refuse an unverified operation instead of guessing flags.
6. Record the exact provider/version/operation used in the manifest.

This matters because the architecture is intentionally provider-rich: the framework must remain trustworthy when one tool changes its CLI or is absent.

---
## 16. What happens to the old code

| Existing area | Decision | Treatment |
|---|---|---|
| `src/tools/phase01..phase10.rs` | **STUDY → MIGRATE** | Mine providers/modes/inputs, then move useful semantics into the capability catalog. Do not preserve the old tool-first UI. |
| `src/tools/types.rs` | **RECREATE** | Replace `Tool/Mode/Category` with capability/provider/operation/task domain models. |
| `src/executor.rs` | **REPLACE** | Keep useful timeout concepts; use structured argv and the new runner. |
| `src/parser.rs` | **AUGMENT** | Retain normalization ideas but expand provider-specific parsing and correlation. |
| `src/ui/menu.rs` | **RECOVER + RECREATE** | Recover the interaction model; rebuild it against capabilities and the adaptive theme. |
| `src/ui/output.rs` | **RECREATE** | Render consolidated findings rather than raw provider output. |
| `src/ui/output_viewer.rs` | **KEEP/ADAPT** | Make it understand the new primary artifact and evidence store. |
| `src/ui/spinner.rs` | **ADAPT** | Replace single-command spinner with multi-task progress state. |
| old hardcoded `theme.rs` | **REPLACE/REUSE PARTS** | Keep semantic roles and terminal-depth degradation; replace palette selection with source adapters. |
| old anonymity modules | **DECOMPOSE** | Remove anonymity-mode UX and proxy/host-spoofing abstraction; retain only components that are objectively useful to the new boundary/infrastructure model. |
| new `catalog/` | **KEEP + EXPAND** | This becomes the declarative capability registry. |
| new `domain/` | **KEEP + EXPAND** | This becomes the core model. |
| new `exec/` | **KEEP + HARDEN** | Retain the single-spawn boundary and bounded runner; fix Oniux compatibility/versioning. |
| new `store.rs` | **KEEP + ADAPT** | Keep atomic writes and manifests; add the single primary capability artifact. |
| new `ui/theme.rs` | **KEEP ENGINE, CHANGE SOURCE** | Preserve semantic styles/degradation; implement Omarchy/theme-source adapters. |

---
## 17. Things explicitly not to do

- Do not restore the old Tool → Mode menu as the final operator experience.
- Do not delete the ten phases.
- Do not reduce each phase to five capabilities merely to satisfy a minimum.
- Do not make a capability equal to one tool.
- Do not assume one provider equals one command.
- Do not use `sh -c` for catalog execution.
- Do not create direct-network fallback when Oniux fails.
- Do not expose an anonymity ON/OFF switch.
- Do not hard-code Omarchy colors into Rust.
- Do not call the hardcoded Midnight/Graphite palette selector an Omarchy adapter.
- Do not show raw provider output as the primary result.
- Do not discard unparseable evidence; preserve it and label it unparsed.
- Do not silently substitute a different provider when a required provider is missing.
- Do not claim a provider command is valid until its installed syntax is verified.
- Do not rewrite the entire repository before building the migration matrix and validating the new domain model.

---
## 18. Implementation sequence

1. Freeze the supplied old/new snapshots as reference material.
2. Build a machine-readable inventory of every old provider, mode, input, output format and command template.
3. Build the 160-capability catalog and classify every old mode as KEEP, MERGE, MOVE, DEPRECATE, AUGMENT or RECREATE.
4. Finalize the capability/provider/operation/task domain model.
5. Implement the interactive UI shell and keyboard navigation before migrating all capabilities, so `tsec` never regresses to a non-interactive status program.
6. Implement the Omarchy/theme-source adapter and semantic renderer.
7. Harden Oniux detection, preflight and version compatibility.
8. Implement the scheduler/DAG and progress model.
9. Implement provider-specific parsers, normalized assets/findings and correlation.
10. Implement the single primary TXT artifact plus machine-readable manifest/evidence store.
11. Migrate RECONNAISSANCE completely and validate the end-to-end operator flow.
12. Migrate the remaining nine phases in controlled groups.
13. Run catalog verification and integration tests for every available provider.
14. Run UI regression tests for every navigation state, resize condition, cancellation and output path.
15. Only then remove obsolete tool-centric code and update README/documentation to match the implemented system.

---
## 19. Definition of done

- [ ] `tsec` opens an interactive ten-phase terminal UI immediately.
- [ ] Every phase is selectable with arrows and I/J/K/L.
- [ ] Every phase contains at least 15 capabilities; the target catalog contains 16 per phase.
- [ ] The operator never needs to select a provider/tool to accomplish a capability.
- [ ] Every capability declares typed inputs.
- [ ] Every capability has at least five provider candidates and five operation slots, where technically meaningful.
- [ ] Independent operations execute concurrently within bounded limits.
- [ ] Dependent operations consume normalized outputs through the task graph.
- [ ] Every network-capable operation is forced through Oniux with no direct fallback.
- [ ] Every task preserves raw evidence and execution provenance.
- [ ] Every capability produces one clean primary TXT artifact named by timestamp, phase and capability.
- [ ] Harvesting deduplicates findings while preserving all sources.
- [ ] Assets/findings can feed later capabilities without manual copy/paste.
- [ ] The terminal theme follows the active Omarchy/theme source through a Rust adapter.
- [ ] No anonymity mode exists in the UI.
- [ ] Provider syntax is verified before execution.
- [ ] The README and architecture documentation describe the code that actually exists.

---
## 20. External methodology anchors

The capability model should be cross-checked against current enterprise attack-surface and adversary-technique coverage rather than copied from the old tool list. MITRE ATT&CK's current Enterprise matrix spans reconnaissance, resource development, initial access, execution, persistence, privilege escalation, credential access, discovery, lateral movement, collection, command and control, exfiltration and impact. OWASP's testing guidance likewise treats applications, domains, virtual hosts, exposed services, DNS, certificates, cloud-native services, containers, identity/authentication and business logic as part of modern testing scope. These sources are methodology anchors; they do not dictate TSEC's UI or provider choices. citeturn0search3turn0search8turn0search1turn0search16

---
## 21. Final architectural position

TSEC's differentiator should not be the number of binaries it can launch. The differentiator is the layer **above** the binaries: the operator states an objective, TSEC builds a multi-provider plan, executes it safely and concurrently, turns heterogeneous output into normalized intelligence, correlates it into an evolving asset/finding graph, and leaves behind a clean evidence artifact with provenance.

The old interactive terminal experience is therefore not cosmetic debt. It is part of the product contract and must be restored. The new execution/catalog/store architecture is also not disposable; it is the stronger foundation underneath that interface. The target system combines both: **old operator usability + new execution architecture + true adaptive theming + mandatory Oniux boundary + capability-scale intelligence harvesting.**

---
## Appendix A — Agent implementation rule

When an implementation agent is instructed to modify TSEC from this document, it must first inspect the current repository and produce a migration report before deleting or rewriting architectural components. It must preserve working functionality, prove replacements with tests, and never treat an unimplemented catalog entry as implemented merely because the TOML exists.

The agent must work from the sequence: **inspect → inventory → map → design → implement → test → migrate → remove obsolete code → document**.
