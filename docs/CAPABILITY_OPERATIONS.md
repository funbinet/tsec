# Capability operations and command mapping

This document explains where TSEC capability operations are defined, how command
templates are executed, and where to edit/add provider operations safely.

## Primary files

- `/home/runner/work/tsec/tsec/catalog/capabilities.toml`
  - Source of truth for capabilities, providers, operations, argument templates,
    output formats, and network/local execution flags.
- `/home/runner/work/tsec/tsec/src/catalog.rs`
  - Loads and validates the catalog, validates placeholders, builds concrete
    command vectors from templates and operator input.
- `/home/runner/work/tsec/tsec/src/ui/menu.rs`
  - Converts selected capability + collected inputs into executable jobs.
- `/home/runner/work/tsec/tsec/src/exec/mod.rs`
  - Executes commands, enforces network-boundary routing, captures stdout/stderr.
- `/home/runner/work/tsec/tsec/src/parser.rs`
  - Parses raw evidence based on per-operation `output` format.
- `/home/runner/work/tsec/tsec/src/store.rs`
  - Harvests, normalizes, deduplicates, correlates, and writes `output.txt/json`.

## Where command definitions live

Every executable operation is defined in `capabilities.toml` under:

- `[[capability]]`
- `[[capability.provider]]`
- `[[capability.provider.operation]]`

Important operation keys:

- `name` — operation label shown in execution UI.
- `args` — command argument template (one argv token per array element).
- `output` — parser mode (`lines`, `json`, `raw`, `nmap`).
- `network` — `true` for boundary-wrapped network execution, `false` for local.

## How templates become commands

`src/catalog.rs` (`Operation::command`) resolves `args` with validated inputs:

- Full-token placeholders: `{domain}` → one argv token.
- Embedded placeholders: `--rate={rate}`.
- Literal brace escapes: `{{` and `}}`.
- Literal printf-style tokens like `%{http_code}` are preserved.

Commands are built as argument vectors, not shell strings.

## How to edit an existing operation

1. Open `catalog/capabilities.toml`.
2. Find the capability and provider operation block.
3. Update `args`, `output`, and/or `network`.
4. Keep placeholders aligned with declared `inputs`.
5. Run validation:
   - `cargo fmt --check`
   - `cargo clippy --all-targets -- -D warnings`
   - `cargo test`

## How to add an operation

1. Add a new `[[capability.provider.operation]]` block under an existing provider.
2. Set unique `name` within that provider block.
3. Set `args` with valid placeholders.
4. Set correct `output` parser type.
5. Set `network = true/false` based on whether the command reaches network.
6. Run the same validation commands.

## How to add a provider to a capability

1. Add a new `[[capability.provider]]` block with `binary = "<tool>"`.
2. Add one or more `[[capability.provider.operation]]` blocks beneath it.
3. Ensure at least one operation is present.
4. Validate with status/test pipeline.

## Common failure points

- Placeholder not declared in `inputs` → catalog load failure.
- Shell syntax in args (`|`, `;`, etc.) → rejected by catalog validation.
- Wrong `output` mode for produced data → parser failures and poor harvesting.
- Provider not installed/resolvable → capability guidance shown; operation skipped.
