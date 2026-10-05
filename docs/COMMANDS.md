# Commands

Every command the framework exposes: the binary, the installer, the tool
resolver and the wordlist tooling.

## `tsec`

The framework binary. Without arguments it opens the interface.

```sh
tsec                  # the interface
tsec --status         # availability per phase, the network boundary, corpus health
tsec --version        # version
tsec --help           # usage
```

### `tsec --status`

Reports, without touching the network:

- the overall availability figure and a per-phase breakdown;
- the `oniux` boundary path, or why it is unusable;
- the resolved wordlist directory, or every list the catalog needs that is not
  there — with the one command that fixes it;
- any catalog notes: arguments that are shell operators, which means an unsplit
  command line.

```sh
$ tsec --status
TSEC 3.0.0
187/218 available
RECON          21/22
SURFACE        20/22
...
EXPLOITATION   25/27
WIRELESS       14/16
BOUNDARY       /usr/bin/oniux
WORDLISTS      /opt/tsec/wordlists
```

Exit status is 0 whether or not everything is installed: this is a report, not a
gate. A capability that cannot run says so by name when you select it.

### `TSEC_HOME`

Where the framework looks for `catalog/capabilities.toml`, in order:

1. `$TSEC_HOME`
2. `/opt/tsec`, if it holds a `catalog/`
3. the directory the binary was built from

```sh
TSEC_HOME="$PWD" cargo run --release      # run from a checkout, no install
```

The catalog's location also decides where `{wl:...}` references resolve, so
`TSEC_HOME` moves the wordlist corpus with it.

### `TSEC_WORDLIST_ROOT`

Overrides the wordlist corpus without moving anything else. Use it to point at a
shared copy instead of keeping one per install.

```sh
TSEC_WORDLIST_ROOT=/srv/tsec-wordlists tsec --status
```

## `install.sh`

Installs the binary, the catalog and the wordlist corpus.

```sh
cargo build --release
sudo ./install.sh
```

| Installs to | What |
|---|---|
| `/usr/bin/tsec` | the binary |
| `/opt/tsec/catalog/capabilities.toml` | the operational surface |
| `/opt/tsec/wordlists/` | the corpus, plus the four large lists |
| `/opt/tsec/{config,output,logs,scripts,tools}` | the runtime workspace |

The installer also checks `oniux`. It refuses nothing: a missing boundary or a
missing large wordlist is reported and the install completes, because the
framework can still run everything that does not depend on it.

`TSEC_ROOT` overrides the install location.

## `tools.sh`

Resolves and installs the provider binaries for one phase, straight from
`catalog/capabilities.toml` — so it cannot drift from what the framework runs.

```sh
./tools.sh -recon           # install what RECON is missing
./tools.sh -exploitation    # ... EXPLOITATION
./tools.sh -all             # every phase
./tools.sh -all -c          # check only: report, install nothing
```

| Phase | | Phase | |
|---|---|---|---|
| `-recon` | Reconnaissance | `-credentials` | Credentials |
| `-surface` | Attack Surface | `-lateral` | Lateral Movement |
| `-vulnerability` | Vulnerability | `-persistence` | Persistence & Defense Evasion |
| `-payload` | Payload | `-exploitation` | Exploitation |
| `-escalation` | Privilege Escalation | `-wireless` | Wireless |

`-c` exits non-zero when something is missing, so it works as a CI gate. Without
it, the script attempts an install and falls back to printing Arch and Kali
commands for whatever it could not install.

Wordlists are **not** handled here. They ship with the framework.

## `wordlists/fetch-wordlists.sh`

Retrieves the four corpora too large for a git repository. Both GitHub and
Codeberg refuse blobs over 100 MB, and `rockyou.txt` alone is 140 MB.

```sh
./wordlists/fetch-wordlists.sh            # download what is missing
./wordlists/fetch-wordlists.sh --check    # report only, download nothing
./wordlists/fetch-wordlists.sh --force    # re-download even if present
```

Idempotent, and each download is verified against a pinned SHA-256 before it is
accepted. Writes through a `.part` file, so an interrupted run cannot leave a
truncated list that later looks valid. Exits non-zero if anything is still
missing.

| List | Size |
|---|---|
| `passwords/rockyou.txt` | 140 MB |
| `users/top-1m.txt` | 85 MB |
| `passwords/openwall.txt` | 41 MB |
| `web/dirbuster-big.txt` | 15 MB |

## `wordlists/verify-wordlists.sh`

Checks the whole corpus: every declared list present and non-empty, and every
shipped copy matching `MANIFEST.sha256`.

```sh
./wordlists/verify-wordlists.sh
./wordlists/verify-wordlists.sh --quiet   # problems only
```

Exits non-zero on a missing or corrupt file, so a partial clone cannot pass
unnoticed in CI.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

`cargo test` loads and validates the shipped catalog, and confirms every
`{wl:...}` reference in it resolves to a non-empty file inside `wordlists/`.

---

TSEC 3.0 — terminal cybersecurity operations platform, built by funbinet.
© funbinet. All rights reserved.
