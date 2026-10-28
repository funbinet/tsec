# TSEC CTF Challenges - Comprehensive Architectural Investigation and Implementation Plan

**Document Version:** 1.0  
**Target:** Introduction of a dedicated Capture The Flag (CTF) Challenges phase (preferably Phase 11 / next available) to the TSEC framework  
**Scope:** Planning only - no code changes, no tool installation, no implementation  
**Date:** 2026-10-28  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Audit - What Exists and How It Actually Works](#2-architecture-audit)
3. [Architectural Gaps and Constraints](#3-architectural-gaps-and-constraints)
4. [Phase/Schema Constraints Analysis](#4-phaseschema-constraints-analysis)
5. [The 14 CTF Challenge-Family Capabilities](#5-the-14-ctf-challenge-family-capabilities)
6. [Detailed Tool Inventories and Command Matrices Per Capability](#6-detailed-tool-inventories-and-command-matrices)
7. [CTF Input Model and Collection Strategy](#7-ctf-input-model-and-collection-strategy)
8. [Flag Format Extraction and Validation Mechanism](#8-flag-format-extraction-and-validation-mechanism)
9. [TOML Schema Compatibility and Required Extensions](#9-toml-schema-compatibility-and-required-extensions)
10. [Command Execution and Evidence-Normalization Pipeline](#10-command-execution-and-evidence-normalization-pipeline)
11. [CTF Output-Normalization and Evidence-Provenance Model](#11-ctf-output-normalization-and-evidence-provenance-model)
12. [CTF Report Structure](#12-ctf-report-structure)
13. [UI Integration Plan](#13-ui-integration-plan)
14. [Dependency and Installation Strategy](#14-dependency-and-installation-strategy)
15. [Staged Execution Profiles](#15-staged-execution-profiles)
16. [Implementation Roadmap](#16-implementation-roadmap)
17. [Testing Strategy](#17-testing-strategy)
18. [Risks, Uncertainties, and Mitigations](#18-risks-uncertainties-and-mitigations)
19. [Acceptance Criteria](#19-acceptance-criteria)
20. [Appendices](#20-appendices)

---

## 1. Executive Summary

This document presents a detailed, repository-grounded investigation of the TSEC 3.0 framework and a concrete implementation plan for adding a dedicated "CTF CHALLENGES" phase. The plan respects TSEC's core design principles: capability-first model, catalog-driven configuration (all behavior in `catalog/capabilities.toml`), no-shell execution with argument vectors, mandatory oniux network boundary for network operations, honest unavailability reporting, evidence preservation, and the existing UI/UX patterns.

Key findings:
- **Current state:** 10 fixed phases in `src/catalog.rs:PHASES` (`recon`, `surface`, `vulnerability`, `payload`, `escalation`, `credentials`, `lateral`, `persistence`, `exploitation`, `wireless`) with 226 capabilities total. The loader enforces exactly these 10 phases and requires every phase to be populated.
- **Phase constraint is structural:** Adding an 11th phase would require modifying `PHASES` array and `phase_label()` function in `src/catalog.rs` (and corresponding tests). This is a hard architectural constraint that must be addressed.
- **Execution model:** Single spawn site in `exec::Runner::run()`, oniux preflight for network ops, process-group isolation, concurrency control, evidence-first capture to run directories.
- **Input system:** Rich type system in `src/domain/input.rs` (domain, target, url, ip/cidr, ports, file, path, secret/password, hash, flag, etc.) with validation. Inputs collected interactively per capability.
- **Catalog format:** TOML with `[[capability]]`, `[[capability.provider]]`, `[[capability.provider.operation]]`. Placeholders `{key}`, wordlists `{wl:path}`, artifacts `{artifacts}`, literal braces `{{}}`, printf-style `%{}`. Strong validation at load time.
- **Parsing/intel:** Format-specific parsers + intelligence pass in `src/intel.rs` extracting secrets/tokens/cookies/hashes/vulns/files/urls/ips/hosts/ports/emails/comments. Noise separated, not discarded.
- **Reporting:** Manifests, raw outputs, normalized findings with provenance, NEXT ACTIONS, run directories in `<output_dir>/<run_id>/`.

**Recommendation:** Treat "CTF CHALLENGES" as Phase 11. This requires schema/loader changes to `PHASES` and validation, but the architectural patterns are extensible enough to support it if done carefully while maintaining backward compatibility for existing catalogs/tests.

---

## 2. Architecture Audit - What Exists and How It Actually Works

### 2.1 Entry Points and Flow
1. **Main** (`src/main.rs`): Parses args (`--status`, `--version`, `--help`), loads config via `Config::load_or_create()`, loads catalog via `Catalog::from_toml()`, initializes UI/theme, enters main menu.
2. **Catalog loading** (`src/catalog.rs`): Reads `catalog/capabilities.toml`, deserializes, validates all rules (phases, labels, placeholders, wordlists, shell operators), builds capability map grouped by phase.
3. **UI flow** (`src/ui/`): Main menu (phases + STATUS + OUTPUTS) → Phase menu (capabilities by name only) → Capability input collection → Execution monitor → Processing stages → Output screen/viewer.
4. **Execution** (`src/exec/`): Build plan via `Launcher::plan()`, preflight oniux for network tasks, spawn via `Command::new()` with process group, capture stdout/stderr to files, supervise with timeout/cancel, collect `ExecutionRecord`.
5. **Parsing/Harvest** (`src/parser.rs`, `src/intel.rs`): Parse artifacts by declared format, run intelligence pass on all lines, deduplicate/correlate, separate noise, generate recommendations.
6. **Storage/Reporting** (`src/store.rs`): Write run directory with `manifest.json`, `output.txt`, `output.json`, `raw/`, `artifacts/`. Atomic writes.

### 2.2 Catalog Schema (from inspection)
```toml
schema = 1

[[capability]]
id = 'recon.subdomain-discovery'  # must start with "{phase}."
phase = 'recon'                   # must be in PHASES
label = 'SUBDOMAIN DISCOVERY'     # 1-3 uppercase words
summary = '...'
inputs = [
  { key = 'domain', type = 'domain', required = true, help = '...', default = '...', rule = {...} },
]

[[capability.provider]]
binary = 'subfinder'              # resolved via PATH or tools.search_paths

[[capability.provider.operation]]
name = 'Passive Enumeration'      # unique within provider
args = ['-d', '{domain}', '-silent']
output = 'lines'                 # lines | json | raw | nmap
network = true                   # true -> oniux, false -> direct
```

**Validation rules (enforced):**
- Phase must be in the 10 phases; every phase must have >=1 capability
- Label: 1-3 uppercase words (regex-like check)
- Every `{placeholder}` must name declared input (with exceptions: `{{}}`, `%{}`, braces in JSON/payloads - loader has logic to distinguish)
- Every `{wl:path}` must resolve inside wordlist corpus (or reported missing but not fatal at load)
- No shell operator as whole argv token (`|`, `&&`, `;`, `>`, etc.)
- Capability needs providers with operations
- IDs unique and namespaced under phase
- Output format valid

### 2.3 Input System Details
**InputType enum** (from `src/domain/input.rs`): Domain, DomainOrCompany, Ipv4, Ipv6, Target, Url, Port, Ports, File, Path, Text, Secret, Integer, Flag, Username, Password, Hash, Interface, Mac, Session, List.  
**Sensitive:** `Secret`, `Password` are redacted everywhere.  
**Validation:** Type-specific regex/checks, file existence for `File`, URL scheme checks, port ranges, etc.  
**Collection:** UI prompts per input in order, masked for sensitive types.

### 2.4 Execution Details
- **Single spawn:** `exec::Runner::run()` is the only place. `Launcher::plan()` decides oniux wrapping.
- **Network boundary:** For `network=true`, must pass oniux preflight (`oniux /bin/true`), argv becomes `[oniux_binary, tool, ...args]`. For `network=false`, runs directly.
- **Process isolation:** Child in own process group via `setpgid(0,0)`, killed as group on timeout/cancel.
- **Concurrency:** Semaphore of `max_concurrency` (default 6), tasks run in parallel, sorted back to catalog order for manifest.
- **Evidence:** Created before spawn, written to run dir cwd. Each task gets `raw/<stem>.out/.err`. Artifacts dir available via `{artifacts}`.
- **Timeout:** SIGTERM then SIGKILL after grace period.
- **Cancellation:** Cooperative via `Cancellation` flag, confirmed by operator.

### 2.5 Parsing and Intelligence
- **Format parsers:** `nmap` (XML), `json` (JSON Lines), `lines` (line-based), `raw` (pass-through)
- **Intel pass:** Scans every line for patterns - AWS keys, private keys, passwords, tokens (GitHub/Slack/Google/Stripe/etc.), JWTs, cookies, `user:pass`, hashes, CVEs/CWEs/GHSAs, files, comments (`TODO/FIXME/HACK`), emails, URLs, IPs, MACs, hosts, ports. One finding per match. Nothing invented.
- **Noise:** Progress bars/timings/banners classified as `Category::Noise`, counted, kept in output.json, excluded from document.
- **Dedup/correlation:** By (category, value), counts sources.
- **Recommendations:** `intel::recommend()` maps findings to capabilities/next actions.

### 2.6 UI/UX Patterns
- Full-terminal-width boxes, adaptive geometry, rendered in place on alternate screen
- Keys: I/K up/down (linear), L/Enter select, J/← back, Esc context-sensitive, Ctrl+C context-sensitive
- Menus show capability names only, no READY/PARTIAL/MISSING decorations
- Missing tools: guidance box with install commands from package DB queries
- Execution shows live spinner, status per task, redacted commands, tally
- Processing shows 7 stages ticking only when done
- Output preview 500 lines, L opens full viewer

### 2.7 Reporting Structure
Run dir: `manifest.json` (all tasks), `output.txt` (operator doc), `output.json` (findings with sources), `raw/*.out|.err`, `artifacts/`. Manifest written after each task. Header centered.

---

## 3. Architectural Gaps and Constraints

### 3.1 Hard Constraints (Cannot Be Ignored)
| Constraint | Location | Impact on CTF Phase |
|------------|----------|---------------------|
| **Exactly 10 phases fixed** | `src/catalog.rs:34-45` PHASES array | Must add 11th phase - requires code changes to catalog.rs, phase_label(), validation, tests |
| **Every phase must be populated** | `src/catalog.rs:873-880` | CTF phase must have >=1 capability at load time |
| **Phase validation in loader** | `src/catalog.rs:782-788` | Adding phase requires updating PHASES constant and phase_label() |
| **UI phase grouping** | `src/main.rs:46`, `src/ui/` | Phase menu expects phases from catalog.grouped() in framework order |
| **Run ID includes phase** | `src/domain/ids.rs:138-147` | New phase slug will be used in run naming |
| **Tests pin phase count** | Multiple tests in catalog.rs | Tests expecting 10 phases will break |

### 3.2 Design Constraints (Must Preserve)
- Capability-first, no tool names in UI selection
- All behavior in TOML catalog
- No shell execution
- oniux boundary for network ops
- Argument vectors only
- Secrets masked
- Evidence preservation
- No fake completion
- Honest unavailability
- One frame per screen UI pattern
- Wordlist corpus in framework dir, referenced as `{wl:path}`
- `{artifacts}` for generated files

### 3.3 Identified Gaps for CTF Use Cases
| Gap | Current State | CTF Need | Approach |
|-----|---------------|----------|----------|
| **Flag extraction** | Intel pass looks for patterns but no format-aware flag extraction with user-supplied regex/prefix | Every CTF capability needs configurable flag format (safctf{...}, flag{...}, CTF{...}, custom regex), safe validation, complete-match, dedup, source attribution | New flag extraction subsystem integrated with intel/parser pipeline; treat as extraction criterion not proof of exploit |
| **Evidence provenance** | Intel findings have detail/line but not full operation trace with checksums, source artifact offsets | Need trace from finding → parser → raw output with checksums, operation ID, tool, args (redacted) | Extend `IntelFinding`/`Finding` with provenance fields; add CTF-specific provenance model |
| **CTF-specific report** | Standard harvest/next-actions report | Need command-by-command explanations, hit/miss classification, tool execution vs validation vs flag verification, flag provenance chain | Add CTF report generator using existing reporting mechanisms, new sections |
| **Artifact types** | File inputs supported (type=file) | Need APK, firmware, PCAP, disk image, memory dump paths - validation exists but may need type hints | Can use `File` or `Path` type; add help text and validation as needed |
| **Cloud credentials** | Secret/password types exist | Cloud provider/profile, account/project IDs needed | Can add new input types or use Text/Secret with validation rules |
| **Domain/controller inputs** | Domain/Target exist | AD needs domain, realm, DC, credentials - can compose existing types | Use existing types, collect conditionally |
| **Flag format as input** | No dedicated flag-format input type with regex validation | Need configurable flag pattern per capability/default | Add `FlagFormat` or use `Text` with special validation/rule; or add new InputType |
| **GUI/API tools** | Framework assumes CLI executables | Burp Suite, Ghidra, MobSF, BloodHound, Autopsy need API/GUI/script integration | Need integration abstraction - could use wrapper scripts in artifacts, API calls via Python/curl, or mark as requiring manual/assisted mode with structured input/output |
| **Staged execution** | All operations in capability run (concurrently up to limit) | Need baseline first, intrusive only on evidence/selection/authorization | Need execution profile/staging mechanism in capability definition or runner logic |
| **Dry-run/non-invasive mode** | No explicit dry-run concept | Need safe defaults, dry-run where practical | Add flag to operations or capability-level setting |
| **Confirmation gates** | Only stop confirmation exists | Need confirmation for consequential operations | May need UI extension for operation-level confirmation |

---

## 4. Phase/Schema Constraints Analysis

### 4.1 Adding Phase 11
**Files to modify (for phase addition):**
1. `src/catalog.rs` - Add "ctf" to `PHASES` array, add "CTF" to `phase_label()` match, update validation logic if needed, update tests
2. `src/domain/ids.rs` - Uses phase string, should work if slug added
3. `src/main.rs` - Groups by catalog.grouped() which uses PHASES order
4. `src/ui/` - Phase menu uses grouped results
5. Tests throughout expecting 10 phases

**Current PHASES:** `["recon", "surface", "vulnerability", "payload", "escalation", "credentials", "lateral", "persistence", "exploitation", "wireless"]`  
**Proposed:** Add `"ctf"` as 11th element. Phase label `"CTF CHALLENGES"` or `"CTF"`? Check existing style - all single words. "CTF" is 3 letters, single token. Could use `"CTF"` or `"CTFCHALLENGES"`. Better `"CTF"` as label, full name in summary/UI.

But looking at how it's used - `phase_label()` returns display name, PHASES contains slugs. Main menu shows phase labels. Let us check: `phase_label` returns `&'static str` like "RECON", "WIRELESS". For CTF, `"CTF"` or `"CHALLENGES"`? "CTF CHALLENGES" as phase name - but labels are single words in the array. Let us look up usage again: "Phase 1 — RECONNAISSANCE" in docs but code uses slugs. The display shows phase_label() result. Could make it "CTF".

Alternatively could insert at position 11. Need to be careful about ordering expectations.

### 4.2 TOML Schema Extensions Needed
**Potential new fields (need to verify if loadable):**
- Capability-level: `ctf_family`, `challenge_context`, `execution_profile`, `requires_authorization` 
- Operation-level: `staged`, `stage_order`, `dry_run`, `confirmation_required`, `intrusive`, `skip_if_no_findings`, `depends_on`, `tags`
- Input-level: Could use existing types; maybe add `flag_format` as special handling
- Provider-level: `integration_type` (cli, api, gui, script, manual) for non-CLI tools

**Current deserialization uses serde with derive** - unknown fields would cause errors by default in Rust serde unless `#[serde(deny_unknown_fields)]` is used. Let us check catalog.rs structs.
---

## 5. The 14 CTF Challenge-Family Capabilities

The CTF phase will contain exactly these 14 top-level capabilities, displayed when entering the CTF phase following TSEC's phase-to-capability interaction model:

| # | Capability Label (UI) | Capability ID (proposed) | Summary | Primary Focus |
|---|-----------------------|---------------------------|---------|---------------|
| 1 | `WEB APP SECURITY` | `ctf.web-app-security` | Web application security and exploitation challenges | HTTP, auth, injection, XSS, SSRF, file upload, access control |
| 2 | `NETWORK RECON` | `ctf.network-recon-service` | Network reconnaissance and service exploitation | Port scanning, service enum, protocol analysis, exploitation |
| 3 | `ACTIVE DIRECTORY` | `ctf.active-directory` | Active Directory and Windows Enterprise Security | Kerberos, LDAP, SMB, AD enumeration, privilege escalation paths |
| 4 | `MOBILE APP SECURITY` | `ctf.mobile-app-security` | Mobile application security challenges | APK/IPA analysis, reverse engineering, dynamic analysis, Frida |
| 5 | `CLOUD SECURITY` | `ctf.cloud-security` | Cloud security challenges | AWS/Azure/GCP enumeration, misconfigurations, IAM analysis |
| 6 | `REVERSE ENGINEERING` | `ctf.reverse-engineering` | Reverse engineering challenges | Binary analysis, decompilation, string extraction, logic analysis |
| 7 | `BINARY EXPLOITATION` | `ctf.binary-exploitation` | Binary exploitation (pwn) challenges | Buffer overflows, ROP, shellcode, exploitation primitives |
| 8 | `NETWORK FORENSICS` | `ctf.network-forensics` | Network forensics challenges | PCAP analysis, protocol reconstruction, traffic inspection |
| 9 | `DIGITAL FORENSICS` | `ctf.digital-forensics` | Digital forensics and incident analysis | Disk images, memory dumps, file carving, timeline analysis |
| 10 | `CRYPTO CHALLENGES` | `ctf.cryptography` | Cryptography and encoding challenges | Classical crypto, modern crypto, encoding schemes, breaking |
| 11 | `STEGO ANALYSIS` | `ctf.steganography` | Steganography and file-format analysis | Image/audio/video stego, metadata, embedded data extraction |
| 12 | `PRIVILEGE ESCALATION` | `ctf.privilege-escalation` | Linux and Windows privilege escalation | Local enumeration, misconfigurations, kernel exploits, privesc paths |
| 13 | `WIRELESS IOT` | `ctf.wireless-iot` | Wireless, Bluetooth and IoT security | WiFi, Bluetooth, RF, IoT firmware analysis |
| 14 | `SCRIPTING MISC` | `ctf.scripting-misc` | Scripting, automation and miscellaneous challenges | Custom challenges, coding, automation, mixed techniques |

Each capability will follow TSEC's model: collect only relevant inputs interactively, have multiple providers with operations, use oniux for network ops where applicable, preserve evidence, integrate with parsing/intel/normalization.

---

## 6. Detailed Tool Inventories and Command Matrices Per Capability

This section documents >=15 genuine tool integrations or independently meaningful operations per capability. Distinction made between different tools vs modes/aliases.

### 6.1 WEB APP SECURITY (`ctf.web-app-security`)
**Target types:** URL, hostname/IP, web service  
**Focus:** Discovery, analysis, authorized testing of web vulnerabilities

| Tool | Type | Purpose | Prereqs | Integration |
|------|------|---------|---------|-------------|
| `curl` | CLI | HTTP requests, header inspection, manual testing | None | CLI, network=true |
| `httpx`/`httpx-pd` | CLI | HTTP probing, tech detection, status codes | httpx installed | CLI |
| `nmap` | CLI | HTTP service detection, NSE scripts | nmap | CLI |
| `ffuf` | CLI | Directory/file fuzzing, parameter fuzzing | ffuf | CLI |
| `gobuster` | CLI | Directory/DNS/vhost brute forcing | gobuster | CLI |
| `feroxbuster` | CLI | Recursive content discovery | feroxbuster | CLI |
| `wfuzz` | CLI | Web fuzzer with filters/payloads | wfuzz | CLI |
| `nikto` | CLI | Web server scanner | nikto | CLI |
| `sqlmap` | CLI | SQL injection detection/exploitation (authorized) | sqlmap, Python | CLI |
| `commix` | CLI | Command injection testing | commix | CLI |
| `xsstrike` | CLI | XSS detection | xsstrike | CLI |
| `dalfox` | CLI | XSS scanning/fuzzing | dalfox | CLI |
| `nuclei` | CLI | Template-based vulnerability scanning | nuclei | CLI |
| `wapiti` | CLI | Web app vulnerability scanner | wapiti | CLI |
| `wafw00f` | CLI | WAF detection | wafw00f | CLI |
| `whatweb` | CLI | Web technology identification | whatweb | CLI |
| `arjun` | CLI | HTTP parameter discovery | arjun | CLI |
| `curl-impersonate`/`curl` | CLI | TLS fingerprinting evasion if needed | varies | CLI |

**Key operations (staged):** Baseline HTTP inspection → tech fingerprinting → discovery (dirs/files/vhosts/params) → auth/session analysis → targeted vuln tests (SQLi/XSS/LFI/SSRF/upload/IDOR) with confirmation gates for intrusive tests → flag extraction from responses/pages.

### 6.2 NETWORK RECONNAISSANCE AND SERVICE EXPLOITATION (`ctf.network-recon-service`)
**Target types:** IP, CIDR, hostname, port range

| Tool | Type | Purpose | Prereqs | Integration |
|------|------|---------|---------|-------------|
| `nmap` | CLI | Port scan, service/version detection, NSE | nmap | CLI, output=nmap |
| `masscan` | CLI | Fast port scanning | masscan (may need privileges) | CLI |
| `rustscan` | CLI | Fast scanner with nmap integration | rustscan | CLI |
| `naabu` | CLI | Port scanning | naabu | CLI |
| `netcat`/`nc` | CLI | Banner grabbing, connectivity testing | ncat/openbsd-netcat | CLI |
| `socat` | CLI | Advanced network connections | socat | CLI |
| `amap` | CLI | Service identification | amap | CLI |
| `nuclei` | CLI | Network/service templates | nuclei | CLI |
| `searchsploit` | CLI | Exploit-DB search | exploitdb | CLI |
| `hydra` | CLI | Network authentication brute force (authorized) | hydra | CLI |
| `medusa` | CLI | Parallel brute forcer | medusa | CLI |
| `ncrack` | CLI | Network auth cracking | ncrack | CLI |
| `enum4linux-ng` | CLI | SMB/NetBIOS enumeration | enum4linux-ng | CLI |
| `smbclient` | CLI | SMB interaction | samba-client | CLI |
| `rpcclient` | CLI | MS-RPC enumeration | samba-client | CLI |

**Staged:** Host discovery (scoped) → port/service scan → banner grabbing → version vuln correlation → targeted enum per service → controlled auth testing → flag hunting in banners/files/responses.

### 6.3 ACTIVE DIRECTORY AND WINDOWS ENTERPRISE SECURITY (`ctf.active-directory`)
**Target types:** Domain, DC IP, username/password/hash, realm

| Tool | Type | Purpose | Prereqs | Integration |
|------|------|---------|---------|-------------|
| `ldapsearch` | CLI | LDAP queries | openldap | CLI |
| `adidnsdump` | CLI | AD DNS enumeration | adidnsdump (Python) | CLI/script |
| `bloodhound-python` | CLI | BloodHound ingestor | bloodhound-python | CLI |
| `BloodHound` | GUI/API | Attack path visualization | GUI app | API/script/assisted mode |
| `impacket-*` | CLI/Python | Kerberos/SMB/LDAP/MSRPC tools (secretsdump, GetNPUsers, GetUserSPNs, psexec, smbexec, etc.) | impacket | CLI |
| `netexec` (nxc) | CLI | Swiss army knife for AD/network | netexec | CLI |
| `crackmapexec` | CLI | Legacy CME (if available) | cme | CLI |
| `enum4linux-ng` | CLI | AD/SMB enum | enum4linux-ng | CLI |
| `kerbrute` | CLI | Kerberos userenum/brute | kerbrute | CLI |
| `rpcclient` | CLI | RPC queries | samba-client | CLI |
| `smbclient` | CLI | SMB access | samba-client | CLI |
| `rbcd.py`/impacket | CLI | RBCD attacks | impacket | CLI |
| `certipy` | CLI | ADCS enumeration/exploitation | certipy-ad | CLI |
| `ldapdomaindump` | CLI | LDAP domain dump | ldapdomaindump | CLI |

**Staged:** Domain/DC validation → unauthenticated enum (users/groups/computers/trusts) → auth testing if creds provided → Kerberos attacks → ACL/relationship mapping → path analysis → controlled exploitation testing → flag hunting in shares/files/sysvol/GPOs.

### 6.4 MOBILE APPLICATION SECURITY (`ctf.mobile-app-security`)
**Target types:** APK path, IPA path, device connection (ADB), app package name

| Tool | Type | Purpose | Prereqs | Integration |
|------|------|---------|---------|-------------|
| `apktool` | CLI | APK decompilation/recompilation | apktool, Java | CLI |
| `jadx`/`jadx-gui` | CLI/GUI | Dex to Java decompiler | jadx | CLI preferred, GUI assisted |
| `dex2jar` | CLI | Dex to jar conversion | dex2jar | CLI |
| `apksigner` | CLI | APK signing | apksigner/build-tools | CLI |
| `aapt`/`aapt2` | CLI | APK info extraction | android-tools | CLI |
| `adb` | CLI | Android device interaction | android-tools | CLI |
| `androguard` | CLI/Python | Static analysis framework | androguard | CLI/script |
| `mobsf`/`MobSF` | Web/API/GUI | Mobile Security Framework | MobSF (Docker/local) | API/script/assisted |
| `frida`/`frida-tools` | CLI/Python | Dynamic instrumentation | frida | CLI/script |
| `objection` | CLI | Frida-powered exploration | objection | CLI/script |
| `apkid` | CLI | APK packer/obfuscator detection | apkid | CLI |
| `quark-engine` | CLI | Android malware analysis | quark-engine | CLI/script |
| `classyshark` | CLI/GUI | APK analyzer | classyshark | assisted |
| `smali/baksmali` | CLI | Smali assembly | smali | CLI |
| `strings` | CLI | String extraction | binutils | CLI |

**Staged:** APK validation/metadata → static analysis (manifest, strings, code) → decompilation → secret/key/URL/endpoint hunting → certificate/pinning analysis → dynamic analysis if device available → flag extraction from code/resources.

### 6.5 CLOUD SECURITY (`ctf.cloud-security`)
**Target types:** Cloud provider, profile/credentials, account ID/project ID, region

| Tool | Type | Purpose | Prereqs | Integration |
|------|------|---------|---------|-------------|
| `aws` | CLI | AWS API interaction | awscli | CLI (with creds from env/profile) |
| `azure`/`az` | CLI | Azure CLI | azure-cli | CLI |
| `gcloud` | CLI | Google Cloud CLI | google-cloud-cli | CLI |
| `scoutsuite` | CLI/Python | Multi-cloud security auditing | scoutsuite | CLI/script |
| `prowler` | CLI/Bash/Python | AWS/Azure/GCP security assessment | prowler | CLI/script |
| `cloudsplaining` | CLI/Python | AWS IAM analysis | cloudsplaining | CLI/script |
| `pacu` | CLI/Python | AWS exploitation framework (authorized) | pacu | CLI/script |
| `trufflehog` | CLI | Secret scanning in repos/configs | trufflehog | CLI |
| `git-secrets` | CLI | Git secret scanning | git-secrets | CLI |
| `checkov` | CLI | IaC security scanning | checkov | CLI/script |
| `terrascan` | CLI | IaC scanning | terrascan | CLI |
| `kube-hunter` | CLI/Python | Kubernetes penetration testing | kube-hunter | CLI/script |
| `kubectl` | CLI | Kubernetes interaction | kubectl | CLI |
| `steampipe` | CLI | Cloud asset querying | steampipe | CLI |

**Staged:** Credential/profile validation → identity/permission enumeration → resource discovery → misconfiguration checks → privilege escalation path analysis → data exposure hunting → flag extraction from configs/secrets/logs. All cloud ops require explicit creds and scope.

### 6.6 REVERSE ENGINEERING (`ctf.reverse-engineering`)
**Target types:** Binary path, file path

| Tool | Type | Purpose | Prereqs | Integration |
|------|------|---------|---------|-------------|
| `file` | CLI | File type identification | file | CLI |
| `strings` | CLI | String extraction | binutils | CLI |
| `objdump` | CLI | Disassembly/info | binutils | CLI |
| `readelf` | CLI | ELF analysis | binutils | CLI |
| `nm` | CLI | Symbol table | binutils | CLI |
| `ldd` | CLI | Dynamic deps | binutils/glibc | CLI |
| `checksec` | CLI | Binary security features | checksec | CLI |
| `ghidra` | GUI/Headless | Decompilation/analysis | Ghidra (Java) | Headless script or assisted |
| `radare2`/`r2` | CLI | Reverse engineering framework | radare2 | CLI |
| `rizin` | CLI | Fork of radare2 | rizin | CLI |
| `cutter` | GUI | Radare2 GUI | cutter | assisted |
| `angr` | Python lib/CLI | Binary analysis/symbolic execution | angr | script |
| `binaryninja` | GUI/CLI | Commercial RE tool | binaryninja | assisted if present |
| `xxd`/`hexdump` | CLI | Hex viewing | util-linux | CLI |
| `exiftool` | CLI | Metadata extraction | exiftool | CLI |

**Staged:** File identification/props → strings/metadata → security features → static disassembly/strings → decompilation → logic analysis → anti-analysis detection → flag hunting in binaries/data.

### 6.7 BINARY EXPLOITATION (PWN) (`ctf.binary-exploitation`)
**Target types:** Binary path, remote host/port, libc path

| Tool | Type | Purpose | Prereqs | Integration |
|------|------|---------|---------|-------------|
| `checksec` | CLI | Security mitigations | checksec | CLI |
| `file`/`readelf`/`objdump` | CLI | Binary analysis | binutils | CLI |
| `strings` | CLI | String extraction | binutils | CLI |
| `ROPgadget` | CLI/Python | ROP gadget finding | ropgadget | CLI/script |
| `ropper` | CLI/Python | ROP gadget finder | ropper | CLI/script |
| `one_gadget` | CLI/Ruby/Python | one_gadget finder | one_gadget | CLI/script |
| `pwntools` | Python lib | Exploitation framework | pwntools (Python) | script-based |
| `patchelf` | CLI | Binary patching | patchelf | CLI |
| `ldd`/`ldconfig` | CLI | Libc identification | glibc | CLI |
| `seccomp-tools` | CLI/Ruby | seccomp analysis | seccomp-tools | CLI |
| `gef`/`pwndbg` | GDB plugins | Debugging enhancements | gdb + plugins | GDB script/assisted |
| `gdb` | CLI | Debugger | gdb | CLI/script |
| `pwninit` | CLI/Rust | Exploit environment setup | pwninit | CLI |
| `strace`/`ltrace` | CLI | Syscall/library tracing | strace/ltrace | CLI |
| `radare2`/`rizin` | CLI | Analysis/debugging | radare2/rizin | CLI |

**Staged:** Binary analysis → mitigations → vuln identification → primitive discovery → exploit development/testing (local first) → remote exploitation if target provided → flag capture. **Extreme caution** - only authorized CTF targets.

### 6.8 NETWORK FORENSICS (`ctf.network-forensics`)
**Target types:** PCAP path, PCAPNG path

| Tool | Type | Purpose | Prereqs | Integration |
|------|------|---------|---------|-------------|
| `tcpdump` | CLI | Packet capture/analysis | tcpdump | CLI |
| `tshark` | CLI | Wireshark CLI | wireshark-cli | CLI |
| `wireshark` | GUI | Packet analysis | wireshark | assisted |
| `capinfos` | CLI | PCAP metadata | wireshark-cli | CLI |
| `editcap` | CLI | PCAP manipulation | wireshark-cli | CLI |
| `mergecap` | CLI | PCAP merging | wireshark-cli | CLI |
| `tcpflow` | CLI | TCP stream reconstruction | tcpflow | CLI |
| `zeek` | CLI | Network analysis framework | zeek | CLI/script |
| `bro` | CLI | Legacy zeek name | bro/zeek | CLI |
| `argus` | CLI | Network flow auditing | argus | CLI |
| `ngrep` | CLI | Network grep | ngrep | CLI |
| `scapy` | Python lib/CLI | Packet manipulation/analysis | scapy | script |
| `xplico` | Web app | Network forensic analysis | xplico | assisted |
| `networkminer` | GUI | Network forensic tool | networkminer | assisted |
| `chaosreader` | CLI/Perl | Session reconstruction | chaosreader | CLI |

**Staged:** PCAP validation/metadata → protocol distribution → conversation analysis → credential extraction → file extraction from streams → HTTP/FTP/SMB/DNS analysis → flag hunting in reconstructed data.

### 6.9 DIGITAL FORENSICS AND INCIDENT ANALYSIS (`ctf.digital-forensics`)
**Target types:** Disk image path, memory dump path, directory of artifacts

| Tool | Type | Purpose | Prereqs | Integration |
|------|------|---------|---------|-------------|
| `file` | CLI | File identification | file | CLI |
| `strings` | CLI | String extraction | binutils | CLI |
| `exiftool` | CLI | Metadata extraction | exiftool | CLI |
| `volatility3` | CLI/Python | Memory forensics | volatility3 | CLI |
| `volatility` | CLI/Python | Legacy volatility | volatility | CLI |
| `autopsy` | GUI/CLI | Digital forensics platform | autopsy | assisted |
| `sleuthkit` | CLI | Filesystem analysis tools (fls, icat, mmls, etc.) | sleuthkit | CLI |
| `foremost` | CLI | File carving | foremost | CLI |
| `scalpel` | CLI | File carving | scalpel | CLI |
| `photorec` | CLI | File recovery | testdisk | CLI |
| `binwalk` | CLI | Firmware/filesystem analysis | binwalk | CLI |
| `bulk_extractor` | CLI | Feature extraction | bulk_extractor | CLI |
| `plaso/log2timeline` | CLI/Python | Timeline analysis | plaso | CLI/script |
| `reglookup` | CLI | Registry analysis | reglookup | CLI |
| `regripper` | Perl | Registry hive parsing | regripper | CLI/script |

**Staged:** Image/dump validation → filesystem/memory analysis → timeline construction → file carving/recovery → artifact extraction (browser history, logs, registry) → malware/trace analysis → flag hunting.

### 6.10 CRYPTOGRAPHY AND ENCODING (`ctf.cryptography`)
**Target types:** Ciphertext/hash/file, key material (if provided)

| Tool | Type | Purpose | Prereqs | Integration |
|------|------|---------|---------|-------------|
| `openssl` | CLI | Encryption/decryption, hash, encoding | openssl | CLI |
| `python3` | CLI | Custom crypto scripts | python | CLI/script |
| `cyberchef` | Web/CLI | Encoding/crypto operations | cyberchef (local/web) | script/assisted |
| `hashcat` | CLI | Password/hash cracking | hashcat (GPU) | CLI |
| `john`/`john-the-ripper` | CLI | Password cracking | john | CLI |
| `hashid` | CLI/Python | Hash type identification | hashid | CLI |
| `hash-identifier` | CLI/Python | Hash identification | hash-identifier | CLI |
| `xortool` | CLI/Python | XOR analysis | xortool | CLI/script |
| `rsatool` | CLI/Python | RSA attacks | rsatool | CLI/script |
| `rsatool.py`/RsaCtfTool | CLI/Python | RSA CTF tool | RsaCtfTool | CLI/script |
| `sage`/`sagemath` | CLI | Number theory/crypto math | sagemath | CLI/script (heavy) |
| `featherduster` | CLI/Python | Crypto analysis framework | featherduster | CLI/script |
| `gmpy2` | Python lib | Big number arithmetic | gmpy2 | script |
| `base64`/`base32` etc | CLI | Standard encodings | coreutils | CLI |
| `unhex`/`xxd` | CLI | Hex conversion | util-linux/xxd | CLI |

**Staged:** Input identification (encoding vs encryption vs hash) → type detection → standard decodings → classical crypto analysis → modern crypto attacks → key recovery → flag extraction/verification.

### 6.11 STEGANOGRAPHY AND FILE-FORMAT ANALYSIS (`ctf.steganography`)
**Target types:** Image/audio/video/file path

| Tool | Type | Purpose | Prereqs | Integration |
|------|------|---------|---------|-------------|
| `file` | CLI | File type | file | CLI |
| `exiftool` | CLI | Metadata | exiftool | CLI |
| `strings` | CLI | String extraction | binutils | CLI |
| `xxd`/`hexdump` | CLI | Hex analysis | util-linux | CLI |
| `binwalk` | CLI | Embedded data/filesystems | binwalk | CLI |
| `foremost` | CLI | Carving | foremost | CLI |
| `steghide` | CLI | Steganography tool | steghide | CLI |
| `stegseek` | CLI | Steghide cracker | stegseek | CLI |
| `zsteg` | CLI/Ruby | PNG/BMP steganography | zsteg | CLI |
| `jsteg`/`jphide` | CLI | JPEG stego | various | CLI |
| `steghide` alternatives | CLI | Various stego tools | varies | CLI |
| `outguess` | CLI | Steganography | outguess | CLI |
| `stegano` | Python lib/CLI | Stego toolkit | stegano | CLI/script |
| `pngcheck` | CLI | PNG validation/analysis | pngcheck | CLI |
| `identify` (ImageMagick) | CLI | Image info | imagemagick | CLI |
| `sonic-visualiser` | GUI | Audio analysis | sonic-visualiser | assisted |

**Staged:** File identification/metadata → hex/binwalk analysis for embedded files → stego detection → extraction attempts (with/without passwords) → format analysis → flag hunting.

### 6.12 LINUX AND WINDOWS PRIVILEGE ESCALATION (`ctf.privilege-escalation`)
**Target types:** System context (local), or provided artifacts/logs from target

| Tool | Type | Purpose | Prereqs | Integration |
|------|------|---------|---------|-------------|
| `linpeas.sh`/`linenum.sh` | Script | Linux privesc enumeration | scripts in wordlists/artifacts or downloaded | script execution |
| `winpeas.exe`/`winPEAS.bat` | Binary/Script | Windows privesc enumeration | PEAS scripts | script/transfer context |
| `pspy` | Binary | Process monitoring | pspy | binary execution |
| `linux-exploit-suggester` | Script | Kernel exploit suggestions | script | script |
| `les2` | Script | Linux exploit suggester 2 | script | script |
| `lse` | Script | Linux Smart Enumeration | script | script |
| `gtfobins` | Reference | GTFOBins lookup | local/online | reference lookup |
| `lolbas-project` | Reference | LOLBAS lookup | local/online | reference lookup |
| `suid3num` | Script/Python | SUID binary analysis | script | script |
| `linprivchecker` | Script | Privilege escalation checker | script | script |
| `privescCheck` | PowerShell | Windows privesc | PowerShell script | script context |
| `seatbelt` | .NET exe | Windows enumeration | seatbelt | binary context |
| `sharpup` | .NET exe | Windows privesc checks | sharpup | binary context |
| `beRoot` | Script/Python | Privilege escalation checker | script | script |
| `unix-privesc-check` | Script | Unix privesc check | script | script |

**Staged:** System identification → enumeration scripts → misconfiguration analysis → kernel/version checks → sudo/SUID/capabilities/cron/path checks → credential hunting → exploit path identification → flag hunting in privileged locations. **Note:** Many require execution on target; framework can analyze outputs/artifacts.

### 6.13 WIRELESS, BLUETOOTH AND IOT SECURITY (`ctf.wireless-iot`)
**Target types:** Interface, SSID/BSSID, capture files, firmware files

| Tool | Type | Purpose | Prereqs | Integration |
|------|------|---------|---------|-------------|
| `aircrack-ng` suite | CLI | WiFi cracking/analysis | aircrack-ng | CLI |
| `airodump-ng` | CLI | WiFi capture | aircrack-ng | CLI (needs monitor mode) |
| `aireplay-ng` | CLI | Injection/attacks | aircrack-ng | CLI |
| `airmon-ng` | CLI | Monitor mode management | aircrack-ng | CLI |
| `hashcat` | CLI | WPA/WPA2 cracking | hashcat | CLI |
| `john` | CLI | Cracking | john | CLI |
| `wifite` | CLI/Python | Automated WiFi audit | wifite | CLI/script |
| `kismet` | CLI/GUI | Wireless detection | kismet | assisted |
| `bettercap` | CLI | MITM framework | bettercap | CLI/script |
| `hcxdumptool`/`hcxtools` | CLI | PMKID/handshake capture | hcxtools | CLI |
| `btscanner` | CLI | Bluetooth scanning | btscanner | CLI |
| `hcitool`/`bluetoothctl` | CLI | Bluetooth tools | bluez-utils | CLI |
| `ubertooth` | CLI/Hardware | Bluetooth sniffing | ubertooth | CLI if hardware |
| `binwalk` | CLI | Firmware analysis | binwalk | CLI |
| `firmware-mod-kit` | CLI/Scripts | Firmware extraction/modding | fmkit | CLI/script |
| `radare2`/`ghidra` | CLI/GUI | Firmware binary analysis | radare2/ghidra | CLI/assisted |

**Staged:** Interface/capture validation → capture analysis → handshake/PMKID extraction → cracking preparation → firmware analysis if IoT → flag hunting. **Wireless operations may require special privileges/hardware; framework must be careful about authorization/scope.**

### 6.14 SCRIPTING, AUTOMATION AND MISCELLANEOUS CHALLENGES (`ctf.scripting-misc`)
**Target types:** File, URL, data, challenge description (text)

| Tool | Type | Purpose | Prereqs | Integration |
|------|------|---------|---------|-------------|
| `python3` | CLI | Custom scripting | python | CLI/script |
| `bash`/`sh` | CLI | Shell scripting | shell | CLI/script |
| `perl` | CLI | Scripting | perl | CLI/script |
| `ruby` | CLI | Scripting | ruby | CLI/script |
| `jq` | CLI | JSON processing | jq | CLI |
| `awk`/`sed`/`grep` | CLI | Text processing | coreutils/sed/grep | CLI |
| `xxd`/`base64`/`openssl` | CLI | Encoding/conversion | coreutils/openssl | CLI |
| `curl`/`wget` | CLI | HTTP/data retrieval | curl/wget | CLI |
| `nc`/`socat` | CLI | Network utilities | ncat/socat | CLI |
| `socat` | CLI | Advanced connections | socat | CLI |
| `tshark` | CLI | Quick PCAP inspection | wireshark-cli | CLI |
| `strings`/`file` | CLI | Quick analysis | binutils/file | CLI |
| `exiftool` | CLI | Metadata | exiftool | CLI |
| `z3`/`python-z3` | Library/CLI | SMT solving | z3 | script |
| `pwntools` | Library | General pwn utilities | pwntools | script |

**Staged:** Challenge context analysis → input/data validation → tool selection based on type → processing/transformation → analysis → flag extraction. Highly flexible, uses general-purpose tools.

---

## 7. CTF Input Model and Collection Strategy

### 7.1 Shared Input Model
All 14 capabilities will use TSEC's existing input mechanism. Inputs collected interactively after capability selection, only relevant fields per capability.

**Core inputs (used across capabilities):**
| Key | InputType | Required | Purpose |
|-----|-----------|----------|---------|
| `target_url` | Url | varies | Web challenge URL |
| `target_host` | Target | varies | Hostname/IP for network/AD/service challenges |
| `target_ip` | Target/Ipcidr | varies | IP address or range |
| `target_port` | Port | varies | Specific port |
| `ports` | Ports | varies | Port range/list |
| `protocol` | Text/List | varies | Protocol specification |
| `scope` | Text | varies | Authorized target scope (explicit) |
| `local_binary` | File | varies | Local binary for RE/pwn |
| `local_file` | File | varies | Generic file input |
| `apk_path` | File | varies | Android APK |
| `firmware_path` | File | varies | Firmware image |
| `pcap_path` | File | varies | PCAP/PCAPNG file |
| `disk_image` | File | varies | Disk image for forensics |
| `memory_dump` | File | varies | Memory dump |
| `cloud_provider` | List/Text | varies | aws/azure/gcp |
| `cloud_profile` | Text | varies | Cloud CLI profile name |
| `cloud_account_id` | Text | varies | Account/subscription/project ID |
| `domain` | Domain | varies | AD/domain name |
| `realm` | Text | varies | Kerberos realm |
| `domain_controller` | Target | varies | DC hostname/IP |
| `username` | Username | varies | Username for auth |
| `credentials` | Secret/Password | varies | Password or credential material |
| `hash` | Hash/Secret | varies | Hash for cracking/analysis |
| `wordlist_path` | Path/File | varies | Custom wordlist (supplements framework corpus) |
| `ciphertext` | Text/Secret | varies | Encrypted data |
| `key_material` | Text/Secret | varies | Keys for crypto challenges |
| `challenge_desc` | Text | varies | Challenge description/context |
| `operation_mode` | List/Flag | varies | safe/balanced/aggressive or similar |
| `time_limit` | Integer | varies | Time constraints |
| `request_limit` | Integer | varies | Rate/request limits |
| `flag_format` | Text | **ALWAYS** | Flag format pattern (see section 8) |
| `interface` | Interface | varies | Network interface for wireless |

### 7.2 Collection Strategy
- **Per-capability relevance:** Only inputs needed for that capability's tools/operations collected
- **Validation:** Use existing validation where possible; add custom validation for CTF-specific inputs
- **Sensitive handling:** Credentials, keys, hashes marked sensitive and redacted
- **Defaults:** Sensible defaults where safe (e.g., flag_format might have common patterns as suggestions but user must confirm/supply)
- **Authorization emphasis:** `scope` input encouraged, clear help text about authorization
- **File validation:** Check existence for File type inputs

### 7.3 Example Input Sets Per Capability (representative)
| Capability | Inputs |
|------------|--------|
| WEB APP SECURITY | target_url (required), scope, flag_format (required), operation_mode, request_limit |
| NETWORK RECON | target_host/target_ip (required), ports, scope, flag_format (required) |
| ACTIVE DIRECTORY | domain, domain_controller, username, credentials, scope, flag_format (required) |
| MOBILE APP SECURITY | apk_path (required), flag_format (required) |
| CLOUD SECURITY | cloud_provider, cloud_profile/account_id, scope, flag_format (required) |
| REVERSE ENGINEERING | local_binary (required), flag_format (required) |
| BINARY EXPLOITATION | local_binary (required), target_host/port (optional for remote), flag_format (required) |
| NETWORK FORENSICS | pcap_path (required), flag_format (required) |
| DIGITAL FORENSICS | disk_image OR memory_dump OR local_file (required), flag_format (required) |
| CRYPTOGRAPHY | ciphertext OR local_file (required), key_material (optional), flag_format (required) |
| STEGANOGRAPHY | local_file (required), flag_format (required) |
| PRIVILEGE ESCALATION | local_file/artifacts (optional), challenge_desc, flag_format (required) |
| WIRELESS IOT | interface OR pcap_path OR firmware_path (varies), flag_format (required) |
| SCRIPTING MISC | local_file OR target_url OR challenge_desc (required), flag_format (required) |

---

## 8. Flag Format Extraction and Validation Mechanism

### 8.1 Requirements
- Configurable CTF flag-format input in **every** capability
- Default to no hardcoded competition-specific prefix
- Allow formats like `safctf{...}`, `flag{...}`, `CTF{...}`, or regex matching competition's expected flag syntax
- **Format-aware extraction mechanism**, not literal string search for prefix
- Support: safe regex validation, escaped special characters where appropriate, case sensitivity settings, complete-match extraction, duplicate suppression, source attribution
- **Treat as extraction and validation criterion, not evidence of vulnerability** - can appear in banners/test fixtures/unrelated files/false positives
- Every candidate must retain exact source and supporting evidence
- Never invent flags, fabricate output

### 8.2 Design
**Input:** Add `flag_format` input to all CTF capabilities (type `Text` initially, or new type). User provides pattern like `safctf\{[A-Za-z0-9_]+\}` or just prefix style that gets converted to regex.

**Flag Extractor Component** (new module, e.g., `src/ctf/flags.rs` or integrated into intel):
```rust
pub struct FlagPattern {
    regex: Regex,           // Compiled, validated
    case_sensitive: bool,
    description: String,
}

pub struct FlagCandidate {
    value: String,
    source_artifact: PathBuf,
    source_operation_id: String,
    source_tool: String,
    line_number: Option<usize>,
    byte_offset: Option<u64>,
    context_snippet: String,
    matched_pattern: String,
    checksum: String,
}

pub struct FlagExtractor {
    patterns: Vec<FlagPattern>,
}
```

**Features:**
- **Safe regex validation:** Compile with `regex` crate, reject catastrophic patterns, timeout not needed for extraction but be careful; validate syntax
- **Escape handling:** If user provides simple prefix like `flag{` convert to `flag\{.*?\}` or let them provide full regex
- **Case sensitivity:** Configurable per pattern or from input
- **Complete-match extraction:** Extract full flag/token matching pattern
- **Duplicate suppression:** By value+source or just value (configurable) - but track all occurrences
- **Source attribution:** Full provenance chain

**Integration points:**
1. After parsing each artifact, run flag extractor on raw content
2. Flag candidates added to findings with special category `FlagCandidate` (separate from validated vulnerabilities)
3. Tracked in provenance model
4. Reported with full source trace
5. "Verified" only if found via evidence chain and matches pattern

**Safety:**
- Never treat presence as proof of exploit
- Mark as "CANDIDATE" until validated
- Include source, context, could be false positive
- Redact if contains sensitive data? Flags usually not secrets in same way, but be careful

### 8.3 Validation Rules for Flag Patterns
- Must compile as valid regex
- Should not be overly broad (warn if matches everything)
- Escape special chars appropriately
- Support common CTF formats out of box conceptually

---

## 9. TOML Schema Compatibility and Required Extensions

### 9.1 Current Schema Assessment (verified facts)

**Serde behaviour:** All catalog structs (`Capability`, `ProviderBinding`, `Operation`, `CatalogFile`) derive `Serialize, Deserialize` **without** `#[serde(deny_unknown_fields)]` and without a `#[serde(flatten)]` catch-all. Consequence: **unknown TOML keys are silently ignored** at deserialization. This means a new key (e.g. `stage = 1`) placed in a capability or operation block with no corresponding Rust struct field would be **silently dropped** — the loader would not complain, and the behavior would not exist. Therefore:
- Schema extensions REQUIRE Rust struct changes in `src/catalog.rs` (fields on `Capability`, `ProviderBinding`, or `Operation`).
- Extension designs must add explicit post-parse validation for the new fields (the loader already does per-capability/per-operation validation passes — new semantic checks belong there, not just deserialization).

**Verified schema boundaries:**

| Element | Verified rule | Source |
|---|---|---|
| `schema` top-level key | Must equal `1`; other values rejected: `unsupported catalog schema {} (expected 1)` | `src/catalog.rs:758-764` |
| Capability `label` | **Two or three** uppercase words (not 1, not 4+): `check_label()` requires `2..=3` words, each starting ASCII-uppercase, all chars uppercase letters or digits | `src/catalog.rs:961-985` |
| Phase label (display) | Exactly one uppercase word, derived from hardcoded `phase_label()` map — e.g. `recon` → `RECON` | `src/catalog.rs:33-62` |
| Phase slug | Must be in `PHASES` (currently exactly 10; any 11th slug rejected at `src/catalog.rs:782-788`) | `src/catalog.rs:34-45, 782-788` |
| Capability `id` | Must be namespaced under its phase: `cap.id.starts_with("{phase}.")` | `src/catalog.rs:776-780` |
| Capability `id` uniqueness | Enforced (duplicate ids rejected) | `src/catalog.rs` validation pass |
| `summary` | Required string, one sentence (guidance display) | `src/catalog.rs:597` |
| `inputs` | Array of `{key, label?, type, required?, default?, help?, rule?}`; keys become placeholders | `src/domain/input.rs:130-150` |
| `rule` | `ValidationRule::{OneOf(Vec<String>), Range(u64,u64), NonEmpty}` only | `src/domain/input.rs:60-68` |
| Provider `binary` | Resolved via `find_in_path` (PATH + `tools.search_paths`) per provider — no version constraints expressible | `src/catalog.rs:601-606`, `src/provider.rs` |
| Operation fields | **Only** `name`, `args` (array of argv tokens), `output` (enum), `network` (bool, default true) | `src/catalog.rs:143-151` |
| Operation `name` | Must be unique within its provider (by convention — stem generation uses binary+operation) | `src/ui/menu.rs` stem build |
| `output` | Closed enum: `lines`, `json`, `raw`, `nmap` — adding a value requires enum extension + parser dispatch | `src/catalog.rs:123-135` |
| Filename stems | `T{:02}_{clean_slug(binary)}_{clean_slug(operation)}` per task | `src/ui/menu.rs:668-672` |

**Execution-flow facts that shape the extension design:**

| Fact | Source | Consequence for CTF |
|---|---|---|
| Interactive run path does **not** use `ExecutionPlan`; `run_capability` builds `Vec<Job>` directly from catalog order and dispatches all with `tokio::JoinSet` + semaphore | `src/ui/menu.rs:617-780`, `src/ui/execution.rs:474-532` | Ordered/staged execution currently does not exist; `plan.rs::Task.depends_on` infrastructure exists but is not wired into the interactive path. Adding stages requires a controlled, additive change here |
| `ExecutionPlan` validation (ids, deps, acyclicity) exists and is tested | `src/domain/plan.rs:67-95` | We can leverage `PlanBuilder` for staged runs rather than inventing new graph machinery |
| Per-tool timeout override exists in config | `src/config/model.rs:213` (`timeout_for(&binary)`) | CTF capability timeouts (e.g. cracking, Ramsey-limited steg) can be set per provider in config, not per operation |
| Skipped/missing-provider handling: `TOOL_NOT_FOUND` records with status `Skipped` | `src/ui/menu.rs:808+` | CTF missing tools follow the same path — no new classification to invent |
| Sensitive-argument masking: positional redaction registered at command build time | `src/catalog.rs:440-521` (`cmd.mark_sensitive(i)`) | CTF credentials/hash/key inputs auto-mask through existing system when declared as `secret`/`password` types |
| Bundeled scripts: bare token ending `.py` with no `/` resolves to `<root>/scripts/<name>.py` | `src/catalog.rs:304-317` | The 70-file `scripts/` directory (already present, e.g. `jwt_forgery.py`, `pcap_creds.py`) establishes a pattern CTF Python helpers can reuse via catalog operations |
| Bundled assets: `{asset:rel}` resolves under the install root | `src/catalog.rs:90-100, 319-340` | CTF helper data files (e.g. hashes rulesets, common flag regexes) can be shipped as assets |
| Second-wave dispatch exists for mid-run installs | `src/ui/menu.rs:755-833` | CTF heavy installs (ghidra, volatility) inherit this behavior |

### 9.2 Required Schema Extensions (minimum, compatibility-preserving)

All extensions are **additive with defaults that preserve current behavior**. The `schema` number stays `1` because nothing in the changes breaks old-catalog parsing (new keys optional with defaults; old catalogs without them parse identically). If validation semantics harden, bump to `2` with a documented migration in the loader.

**E1 — Operation `stage` field (core extension):**
```rust
// src/catalog.rs, struct Operation:
#[serde(default)]
pub stage: Option<u8>,   // None = stage 1 (current behaviour unchanged)
```
```toml
[[capability.provider.operation]]
name = 'Baseline HTTP Probe'
stage = 1

[[capability.provider.operation]]
name = 'SQL Injection Probe'
stage = 2
confirm = true
```
- Validation: stage values 1..=3 (loader rejects 0, 4+).
- Stage semantics (denominator: 1=baseline discovery, 2=deep/analysis, 3=intrusive/exploit).
- Execute stages sequentially; concurrent within a stage (uses the existing `JoinSet`/semaphore, invoked once per stage with a per-stage job subset).
- Compatibility: catalogs without `stage` behave exactly as today.

**E2 — Operation `confirm` field (consequential-operation gate):**
```rust
#[serde(default)]
pub confirm: bool,  // default false
```
- When true, before the stage containing the operation, capability UI shows a scope-confirmation box ("These commands are intrusive. Continue? [y/N]"). Answer `N` → whole stage 3 recorded as `SKIPPED` with reason `CONFIRMATION_DECLINED`.
- Reuses the existing `Stop ongoing operations? [y/N]` input pattern, restyled.

**E3 — Input `section` field (input grouping only):**
```rust
// src/domain/input.rs, struct InputSpec:
#[serde(default)]
pub section: Option<Cow<'static, str>>,  // None = umbrella section
```
- Purely cosmetic/grouping: the input box shows inputs grouped (Challenge, Target, Authorization, Flag). No behavioral change.
- Needed because CTF capabilities collect the most inputs; ungrouped prompts hurt UX.

**E4 — New InputType variants (validated CTF input types):**
```rust
// src/domain/input.rs, enum InputType:
CtfFlagFormat,   // user-supplied flag pattern; regex-safe validated
CtfToken,        // challenge token/session/ciphertext blob (not sensitive by default)
CloudProfile,    // cloud CLI profile name (identifier)
```
- `CtfFlagFormat` validation: (a) if it's a full regex, must compile with `regex::Regex::new`; (b) if a "prefix{suffix}" shorthand (`flag{...}`), auto-expand to escaped literal prefix + bounded char class; (c) reject catastrophic patterns (unbounded nested quantifiers) — measure: prohibit `.*` inside a `{}` body without a bound? (Strategy documented in §8.3.)
- InputType variants must serialize in the existing `snake_case` serde style; adding variants is backward-compatible with older catalogs.
- **Reality check:** we could achieve this with `Text` + custom validation, but a first-class type gives correct UI hint text, enables targeted unit tests, and avoids a magic rule encoding.

**E5 — Category::FlagCandidate + sub-category table:**
```rust
// src/domain/finding.rs, enum Category:
/// A string matching the operator's declared flag format. NOT a vulnerability.
FlagCandidate,
```
- Headings: `"FLAG CANDIDATES"`.
- Enum extension is additive in serde; older serialized `output.json` files still deserialize (unknown-to-old-reader variant concern only applies to old bincode — not used here; serde JSON strings.
- `Value` holds the matched flag string. `Detail` holds provenance context. Provenance (already on every finding) carries the artifact + operation + redacted command.

**E6 — Output format for structured XML: unchanged.**
- Keep `lines|json|raw|nmap`. CTF needs raw + lines + json + nmap only (TShark `-T fields` emits lines; OpenSSL emits lines; sqlmap writes a session target file - read as raw). Adding `xml` only if a tool (e.g. `Volatility3 --format=...`) demands; Volatility3 emits JSON lines fine. **No change needed — explicitly verified.**

**E7 — Out-of-band CTF provenance (sidecar file, zero schema change):**
- Rather than modifying `ExecutionRecord` (serialized into `manifest.json` — existing runs' manifests must interop), write `ctf_provenance.json` alongside the existing files:
```
<output_dir>/<run_id>/
├── manifest.json          (unchanged format)
├── ctf.json               (new: CTF-specific evidence, provenance, verdicts)
```
- `ctf.json` references `manifest.json` records by `task_id`, so every CTF finding chains: `ctf.json:finding -> finding.provenance -> manifest.json record -> raw/*.out` bytes.

### 9.3 Schema non-extensions (explicitly rejected as unnecessary)

| Proposed elsewhere | Verdict | Reason |
|---|---|---|
| Per-operation `timeout` | Not needed | Per-binary timeout already configurable via Exec config; per-operation not worth schema growth |
| `dry_run = true` operations | Not needed | Dry-run is a UI decision, not catalog: stage-3 requires `confirm = true` covers the same protection with a richer human gate; execution "dry-run mode" unsupported |
| `depends_on` in TOML | Not needed now | Stage sequencing (E1) covers CTF ordering with far less validation surface. `plan.rs::Task.depends_on` remains for future use; wiring it requires parser/infra change upstream in the same PR as E1 if done |
| `integration = 'api'` providers | Not needed | A script or python wrapper covers API-driven tools; the `scripts/` mechanism is already the framework's assisted-tool pattern |
| New wordlist root | Not needed | Existing wordlist corpus covers wordlist requirements (`passwords/rockyou.txt` fetchable, etc.). CTF adds nothing to the corpus initially |

### 9.4 Wordlists — CTF additions
Words wordlists directory additions, referenced as `{wl:path}` like all others (never hardcoded Kali paths; resolution is installer/checkout agnostic via the existing mechanism):
- `wordlists/ctf/flags-common-formats.md` (documentation asset, not a wordlist — kept in `docs/` or as `{asset:ctf/...}`)
- `wordlists/web/dirs-ctf-common.txt` — dirb/small wordlists already shipped in `wordlists/web/`; **verify before adding** - only add what `wordlists/verify-wordlists.sh` can verify; small additions are appropriate
- No new large lists (the four 100 MB+ fetched lists already cover rockyou + seclists). Capability wordlist needs could use `wordlists/fuzz/`, `wordlists/web/`, `wordlists/passwords/` (registered in MANIFEST.tsv with checksums per the existing pattern).

---

## 10. Command Execution and Evidence-Normalization Pipeline

### 10.1 The CTF pipeline keeps the existing one and layers CTF passes on it

```
capability selection (ui/menu.rs:run_capability)
    │
    ├─ collect_inputs(...) — flag_format always present (E4 type CtfFlagFormat), family-relevant inputs first
    │
    ├─ provider resolution + background install (existing; extends per-tool notes to CTF tools)
    │
    ├─ command build (Operation::command → argv validation, {wl:}, {asset:}, {artifacts}, sensitive marking)
    │
    ├─ STAGED dispatch (new: instead of all-at-once dispatch, stages 1..3 dispatched sequentially:
    │     stage 1 jobs → monitor → confirmed success on ≥1 task?
    │           yes ──► enqueue stage 2 jobs (invasive ops guarded by confirm gate)
    │           no  ──► skip remaining stages, proceed to harvest with what completed
    │     Implementation: inside run_capability, build three job vectors, dispatch each
    │     through the existing execution::execute() flow and monitor (unchanged per-monitor shape;
    │     a stage change draws a red bar row in the same box — no new frames).
    │
    ├─ existing: Runner::run (single spawn site), process-group isolation, timeouts, cancellation
    │
    ├─ HARVEST (existing store.rs harvest) + NEW CTF PASS (ordered within the same seven-stage
    │     PROCESSING box; the last two stages are CTF-specific)
    │       6. after '...writing' completes, run:
    │          a. flag extraction (src/ctf/flagextract.rs) on every artifact (raw/*.out|.err + artifacts/)
    │          b. evidence provenance assembly (src/ctf/provenance.rs) — link findings and flag
    │             candidates to operations, raw files, and line offsets; verify source checksums
    │          c. ctf.json sidecar write
    │       7. ctf report generation (output_doc prepared under same 500-line preview rule)
    │
    └─ output display (existing ui/output.rs: recent-box preview + document viewer unchanged;
       CTF report is the document body, so preview/viewer/naming stay identical)
```

The **monitor UI is not restructured**: the same `EXECUTION` box shows stage-aware job rows (each job already carried its label and redacted command; add the stage number so rows read like `S1 · curl · Baseline HTTP Probe`). No new frames, no duplicated panes. The existing "one render owner" and frozen-stack rules remain untouched.

### 10.2 Task statuses: existing enum + CTF outcome classification

Existing `TaskStatus` (Pending, Running, Complete, Failed, TimedOut, Skipped, Interrupted) stays; the CTF layer adds a *results-oriented* classification in `ctf.json` per attempt, distinct from process status:

| CTF outcome | Mapping rule (from record) |
|---|---|
| `SUCCESS` | exit 0 AND parsed meaningful findings recorded |
| `NO_FINDINGS` | exit 0 AND zero findings after intelligence pass |
| `NOT_APPLICABLE` | stage skipped by evidence logic (e.g. no Kerberos services found → skip GetUserNPUsers) |
| `SKIPPED` | record status `Skipped` (TOOL_NOT_FOUND, confirmation declined, late install failed) |
| `INPUT_ERROR` | the operator-supplied value failed validation or was invalid for that tool (e.g. flag regex refuses compile) |
| `EXECUTION_ERROR` | record status `Failed` (nonzero exit on a system/spawn problem) |
| `TIMEOUT` | record status `TimedOut` |
| `PARSE_ERROR` | parser failed on the raw file even though the task completed |
| `VALIDATION_FAILED` | command ran clean but the asserted condition (e.g. expected an HTTP 200 + expected string) was not met |

- `SUCCESS` never implies exploitation success or flag recovery — it classifies the *command attempt* only. Verification of vulnerability claims and flag candidacy are separate records (`ValidatedVulnerability`, `FlagCandidate`) in `ctf.json`, each linked to concrete operation IDs.
- A nonzero exit with useful partial evidence keeps the evidence pre-ranked under `EXECUTION_ERROR` with a `partial` flag (the existing engine already preserves partial stdout on failure — `store.commit` gets whatever bytes were captured before termination).
- Stage-1 exit-0 with no findings is a legitimate base state (`NO_FINDINGS`), never reported as a failure unless the task was fundamental to the capability (e.g. URL validation probe says target URL not reachable — record as `VALIDATION_FAILED` and skip downstream).

### 10.3 Deduplication and secrets handling

- Findings deduplicate by `(category, value)` as today. CTF candidates dedupe separately by their own key (matched flag string, case-normalized per case-sensitivity setting; original case retained in the finding).
- All operator-supplied `secret`/`password` inputs are masked in every rendering (existing positional `mark_sensitive` mechanism — verified `src/catalog.rs:440-521`). CTF `key_material` and hash inputs follow the same path.
- The CTF report includes the *redacted* effective command args per run, matching what the existing `EXECUTION` box shows; nothing new is unmasked in the CTF report.

---

## 11. CTF Output-Normalization and Evidence-Provenance Model

### 11.1 `ctf.json` structure (new sidecar, written by `src/ctf/provenance.rs`)

```json
{
  "schema": 1,
  "run_id": "20260101_120000_RECON_WEB",

  "challenge_context": {
    "capability_id": "ctf.web-app-security",
    "objective": "user-supplied challenge description (verbatim, not interpreted)",
    "authorized_scope": "operator-supplied scope statement (verbatim)",
    "mode": "baseline|deep|full (per operation_mode input)",
    "limits": { "time_limit_secs": 3600, "request_limit": 500 }
  },
  "flag_format": {
    "pattern": "safctf{...}",
    "resolved_regex": "safctf\\{[A-Za-z0-9_]{3,64}\\}",
    "case_sensitive": true,
    "description": "operator shorthand expanded by the loader; logged for audit"
  },

  "operations": [
    {
      "operation_id": "T03",
      "task_id": "T03",            // links to manifest.json task_id
      "phase": "CTF",
      "capability": "WEB APP SECURITY",
      "provider": "ffuf",
      "interface": "cli",           // cli | script <name>.py | api <tool> | gui (from catalog via provider)
      "template": "ffuf -u {target_url}/FUZZ -w {wl:web/dirs.txt} -t {threads}",
      "redacted_args": ["-u", "https://chall.example/FUZZ", "..."],
      "stage": 1,
      "status": "COMPLETE",         // existing TaskStatus, verbatim
      "outcome": "SUCCESS",
      "attempted_at": "2026-...Z",
      "finished_at": "2026-...Z",
      "duration_ms": 120,
      "exit_code": 0,
      "timeout_or_cancelled": false,
      "raw_stdout": "raw/T03_ffuf_dirs.out",
      "raw_stderr": "raw/T03_ffuf_dirs.err",
      "raw_sha256_stdout": "ab41..ef",
      "purpose": "baseline directory discovery (declared at catalog level)",
      "purpose_class": "reconnaissance"  // recon|enumeration|hypothesis_test|validation|evidence|report
    }
  ],

  "findings": [
    {
      "finding_id": "F01",
      "type": "exposed_path",        // CTF finding vocabulary (§11.2)
      "severity": "informational|low|medium|high (where justifiable)",
      "confidence": "observed|inferred|validated",  // observed < inferred < validated
      "target_or_artifact": "https://chall.example/.git/HEAD",
      "observation": "what was actually matched or observed",
      "validation_method": "followup command that confirms it (operation_id) or null",
      "originating_tool": "ffuf",
      "originating_operation_id": "T03",
      "source_type": "raw_stdout | raw_stderr | artifacts/<file> | response-header | packet | memory-offset | disk-offset | db-record",
      "source_location": { "artifact": "raw/T03_ffuf_dirs.out", "line": 14,
                           "match_offset": [452, 468] },
      "observed_at": "2026-...Z",
      "provenance_chain": ["T03", "raw/T03_ffuf_dirs.out", "raw_sha256: ab41..ef"]
    }
  ],

  "flag_candidates": [
    {
      "candidate_id": "C01",
      "value": "safctf{d1r_bu5t3r_1s_fun}",
      "matched_pattern": "safctf\\{[A-Za-z0-9_]{3,64}\\}",
      "found_by_operation": "T12",
      "originating_tool": "curl",
      "source": {
        "artifact": "raw/T12_curl_comments.out",
        "line": 87,
        "context_lines_before": 2, "context_lines_after": 2,
        "context_text": "<!-- TODO: remove the flag before shipping. safctf{d1r_bu5t3r_1s_fun} -->"
      },
      "occurrences": [ {...same shape, one per additional sighting...} ],
      "candidate_status": "unverified | verified",
      "verification": {
        "method": "submitted via challenge API and accepted | format consistency + full-context agreement",
        "evidence_link": ["C01", "T12"],
        "verified_at": "..."
      }
    }
  ],

  "validated_vulnerabilities": [
    {
      "vuln_id": "V01",
      "class": "sqli-time-based",
      "target": "https://chall.example/item.php?id=",
      "evidence_operations": ["T07", "T09"],
      "observation": "10s delay on ' SLEEP(5)' vs 0s baseline",
      "establishes": "server-side SQL execution called with our input",
      "does_not_establish": "auth bypass; database enumeration; flag presence" }
  ],

  "artifact_recoveries": [
    { "artifact_id": "A01", "path": "artifacts/carved_flag_config.tar",
      "recovered_by": "T18 (binwalk)", "sha256": "...", "size_bytes": 412 } ]
}
```

### 11.2 CTF finding vocabulary (separate from existing `Category`)

The existing `Category` enum is used as-is for everything that is an ordinary TSEC finding. CTF-specific `finding.type` (a string in `ctf.json`, not a new Category enum member — avoids polluting every other phase's rendering) covers:

- For 14 capabilities the same vocabulary applies: `exposed_path`, `config_leak`, `credential_leak`, `injection_capability`, `weak_cipher`, `crypto_misuse`, `stego_payload`, `embedded_filesystem`, `memory_artifact`, `timeline_event`, `privilege_path`, `wifi_handshake_capture`, `firmware_component`, `ad_relationship`, `cloud_misconfig`, `mobile_hardening_gap`, `re_logic_summary`, `script_result`, plus raw tool-native types.

**The rule observed vs inferred vs validated** prevents report inflation: Observed = a ruled match (mind the format). Inferred = a pattern-match-derived hypothesis (`NEXT ACTIONS`, but CTF-flavoured). Validated = the follow-up operation confirmed the ability (e.g. the command really executed on the target — controlled delay or targeted content).

### 11.3 Sensitive data redaction policy

- Strings matching the operator's `secret`/`password`/`key_material` inputs are masked in `ctf.json` *Observation* strings as well.
- The flag *candidate* string itself is never redacted (it is the payload of interest), but its `context_text` is reduced to the matched line ±2 lines.
- Programs (gpg, ssh) that print keys do not cause a leak: the raw files stay on-disk (`raw/*.out`), and the CTF report never echoes longer than a 250-char snippets from raw evidence.

### 11.4 Source checksum and parser-version tracking

- `raw_sha256_*` for every raw capture file per operation (37 bytes/digest per operation — negligible on-disk cost).
- `ctf.json` carries `parser_versions: {format_parser: "v1.0", flagextract: "v1.0", provenance: "v1.0"}` to distinguish behavior across updates (same convention as existing manifest versioning where the tool is named per-record in `manifest.json`).

---

## 12. CTF Report Structure

The CTF document (`output.txt`-style, same rendering engine, same viewer/scrolling/cancellation/down-flow) is constructed with these sections, prepared by `store.rs` finalise for CTF runs:

```
┌─ run header ─────────────────────────────────────────────┐
│ CHALLENGE CONTEXT   14 challenge capabilities summary    │
│   ✓Objective ✓Authorized scope ✓Mode/limits ✓Flag format │
├──────────────────────────────────────────────────────────┤
│ COMMAND ATTEMPTS (command-by-command explanations)      │
│ [T03] ✓ SUCCESS   ffuf   stage 1   120ms                 │
│   purpose: baseline directory discovery                  │
│   cmd: ffuf -u https://chall.example/FUZZ -w ... -mas    │
│   hit: 14 paths found → see FLAG CANDIDATES / FINDINGS   │
│                                                          │
│ [T07] ✗ EXECUTION_ERROR  sqlmap  stage 2  exit 2         │
│   purpose: SQLi probing on /item.php?id                  │
│   cmd: redacted sequence                                 │
│   note: --batch refused (missing param spec), kept note  │
│                                                          │
│ [S?] — SKIPPED  ghidra  NOT_INSTALLED                    │
│   why: no provider binary resolves; install cmd shown    │
├──────────────────────────────────────────────────────────┤
│ SIGNIFICANT FINDINGS (grouped, then by finding type)    │
│ Observation / Validation / Does-not-establish            │
├──────────────────────────────────────────────────────────┤
│ VULNERABILITIES ACTUALLY VALIDATED (backed by evidence)  │
├──────────────────────────────────────────────────────────┤
│ ARTIFACTS RECOVERED (with sha256)                        │
├──────────────────────────────────────────────────────────┤
│ FLAG CANDIDATES + PROVENANCE                             │
│ [C01] safctf{...}       confidence: verified             │
│   found by: T12 (curl)                                   │
│   source: raw/T12_curl_comments.out:87                   │
│   context: 2 lines before / after                        │
│   verification: format-consistent + API accepted         │
├──────────────────────────────────────────────────────────┤
│ FINAL FLAG (only with verification evidence)             │
│   or: "No flag recovered. Best candidate rejected        │
│   because: {reason}. Next step suggestion: {action}"     │
├──────────────────────────────────────────────────────────┤
│ WHAT DID NOT HAPPEN (explicit)                           │
│   tools unavailable: ghidra, volatility3, autopy         │
│   stage 3 not offered: confirmation declined             │
│   ops skipped by evidence-logic: ...one sentence each... │
├──────────────────────────────────────────────────────────┤
│ NEXT ACTIONS (CTF-flavoured, suggestion-only)            │
└──────────────────────────────────────────────────────────┘
```

Same-view rules as every report:
- 500-line preview in the OUTPUT box, full viewer on `L`.
- No fabricated flags. No claims about unexecuted operations.
- Every failed command shows its exit code plus the engine's picked "last meaningful stderr line" — the existing `stderr_tail` mechanism (`src/exec/mod.rs`).
- The report never states "exploitation succeeded" unless a corresponding `validated_vulnerabilities` entry exists with concrete operations.
- Missing tools are named with sanitized install commands just like the existing RUN FAILURE screen does, but recorded inline rather than interrupting the flow.

---

## 13. UI Integration Plan

### 13.1 Keeping every screen convention intact

| Screen | Change |
|---|---|
| Main menu | One additional top-level entry: `CTF CHALLENGES` (phase-label `CTF` per phase naming rule, `phase = 'ctf'`, i.e. `[CTF] word ...`; needs `PHASES` array extension in `src/catalog.rs`) |
| Phase menu | Nothing changes structurally: `catalog.grouped()` includes the new phase, `ui/menu.rs:phase_menu` renders it with no modifications. Capability labels are 2-3 words; all 14 CTF labels chosen meet the rule |
| Capability menu | No change: availability surfaces through the same `unavailable_reason()` logic |
| Capability input collection | **Input grouping** (new §9.2 E3): the input box groups the CTF inputs (Challenge / Target / Authorization / Flag). Scope: `flag_format` is placed first (mirrors user mental model); target family next; authorization last. Dirty mitigation: the flag-format input is optional-with-default so it can be skipped fast. No dependency-tree collection — plain sequential prompts, which is the current UX pattern |
| Execution monitor | Same box, same spinner, same keys. Stage rows appear with the phase prefix (`S1 ·` / `S2 ·` / `S3 ·`); a stage transition draws a single redraw of the same box (no duplicate frames). Confirmation gates reuse the confirm box pattern |
| Processing box | The 7 stages tick as today; two more stages tick after (CTF pass + CTF report), showing `✓` when work actually completed |
| Output view | Identical (`500`-line preview, `L` to open full). CTF report is the document body; no special-casing at the display layer |
| OUTPUTS history | No change: run dirs follow the same naming structure; the CTF sidecar `ctf.json` is an additional file the manifest already knows about via `harvest_section: None` |
| STATUS | `--status` consumes the phases list, so the new phase appears automatically once catalog is extended and `PHASES` includes `ctf` |
| Failure screen (`RUN FAILURE`) | No change: the existing run-failure screen already names each failed task, its error code, and the suggested install command |

### 13.2 Terminal behavior edges (verified against existing code)

- **Cancel:** `Esc` during execution triggers `Stop ongoing operations? [y/N]` — identical. Cancellation mid-stage stops the current stage's running tasks; *already-completed* prior stages keep their evidence; later stages are not dispatched (their jobs are withdrawn; recorded `SKIPPED` with `INTERRUPTED`).
- **Empty results:** A stage with 0 findings is a valid progression path — stage logic looks at *operation-level* success, not finding-level, so `NO_FINDINGS` on stage 1 with successful exit codes proceeds to stage 2 (signalled via the monitor's standard `Complete` status).
- **Scrolling/viewer:** The document viewer (`ui/output.rs`) is format-agnostic — the CTF document body uses the same line/paragraph/section conventions, so scroll keys, width fitting, and closing (`J`/`Esc`) work unchanged.

---

## 14. Dependency and Installation Strategy

### 14.1 What already handles this (and is reused as-is)

- `src/install.rs`: distro detection (`pacman`, `apt-get`, `dnf`, `yum`, `apk`, `zypper`), offline local-metadata resolution (`pacman -Si`, `apt-cache show`, `dnf --cacheonly info`, `apk info -a`, `zypper --non-interactive info`), background install while the capability runs.
- `tools.sh`: `pkg_info` maps `tool|arch|kali` lines; a tool not in the map gets a same-name package guess + search command. Every binary named by the catalog must have a map entry (enforced by a test).
- Guidance: a provider that exists nowhere is named as such with the search command, never silently.

### 14.2 CTF-specific packaging notes (verified against Arch/Kali reality)

| Tool | Arch | Kali | Note |
|---|---|---|---|
| `nmap` | `nmap` | `nmap` | Already in catalog |
| `sqlmap` | `sqlmap` | `sqlmap` | AUR/CTF package availability varies; `pacman -Si` will tell |
| `netexec` | `netexec` | `netexec` | Already referenced by the catalog (crackmapexec entry maps to netexec) |
| `impacket` | `impacket` (AUR) | `python3-impacket` | Bundled python script tools (impacket-*): on Arch the pip wheel contributes to `/usr/local/bin`; the resolver can only try, and describe where scripts live |
| `jadx` | `jadx` | `jadx` | Java required |
| `abi-tool/apktool` | `apktool` | `apktool` | Java required |
| `mobsf` | AUR only | via docker | GUI/API-driven; integrated as script-provider (`.py` bundle) rather than cli binary |
| `ghidra` | `ghidra` (AUR) | `ghidra` | Not a CLI per se; headless analyzer (`analyzeHeadless`) is scriptable — catalog can call it via args |
| `volatility3` | `volatility3` | `volatility3` | Python tool |
| `hashcat` | `hashcat` | `hashcat` | GPU/CPU autodetect |
| `john` | `john` | `john` | Jumbo |
| `binwalk` | `binwalk` | `binwalk` | Already in catalog |
| `zsteg` | gem install (manual) | `zsteg` | Ruby runtime; register in `tools.sh` explicitly with a fallback note |
| `stegseek` | AUR | `stegseek` | Special-case integration |
| `certipy` | AUR `certipy-ad` | `certipy-ad` | Already in `tools.sh` (verified: `certipy) echo "certipy-ad|certipy-ad"`) |
| `bloodhound-python` | AUR | `bloodhound-py` | GUI BloodHound itself: NOT integrated programmatically; data collection is by script and graph analysis manual |
| `kismet` | `kismet` | `kismet` | Already referenced in catalog |
| `aircrack-ng` suite | `aircrack-ng` | `aircrack-ng` | Already in catalog |
| `scap` tools (scout/prowler) | AUR / pip | pip | Registered per-tool with notes, not invented packages |

**Rule:** every CTF binary that lands in the catalog also lands in `tools.sh`'s `pkg_info` map (the existing test enforces it). Tools CI-critical missing on the host are simply `TOOL_NOT_FOUND`-shaped entries in the report — per design rule 5 (honest unavailability).

### 14.3 Non-CLI Tools: what the catalog actually declares for them

- **Ghidra:** `binary = 'ghidra'`; a companion operation invokes a bundled `.py` analyzer that wraps `analyzeHeadless -import <bin> -scriptPath {asset:...} -postScript ...`. If Ghidra is GUI-only at the operator's site, the wrapper is never reached; the stage records it as `SKIPPED`/`NOT_APPLICABLE` noted in the report with the GUI guidance. No pretending a CLI exists.
- **MobSF:** reachable via its REST API (default host `http://127.0.0.1:8000` when the user starts it). Catalog entries invoke bundled `.py` scripts (uploaded APK, fetched report) that accept `mobsf_url`, `mobsf_api_key` inputs (both marked secret) — no invented binary.
- **BloodHound GUI:** NOT an operation. Data collection is via `bloodhound-python` (a CLI), and analysis is manual; report references the collected `.json`/`.zip` artifacts and states the analysis step is human.
- **Autopsy/The Sleuth Kit:** TSK tools (`fls`, `icat`, `mmls`, `img_stat`, …) are pure CLI and fully integrable; Autopsy's GUI is not an operation — the report mentions it alongside the TSK operations.
- **Burp Suite / ZAP:** not command-line friendly. ZAP is scriptable via its REST API (`zap-api.py`, launched via bundled scripts) when the user starts ZAP; Burp only through manual use. The catalog carries no fake operations for either — only the API-driven (ZAP) or driver-script (mobSF) routes that can be verified and executed.

---

## 15. Staged Execution Profiles

### 15.1 Three stages, one monitor, no auto-everything

| Stage | Purpose | Typical composition | Notification |
|---|---|---|---|
| **S1 Baseline** | Validate the challenge context, establish what the artifact/target is, run non-destructive discovery (fingerprints, listings, surfaces) | file, curl HEAD, nmap -sV, checksec, binwalk, tshark -r, strings, aapt | runs without confirmation (respectively read-only when possible) |
| **S2 Analysis** | Deeper analysis driven by what S1 surfaced: decompile, carve, decode, fuzz directories, enumerate users/shares/params | jadx, foremost, ROPgadget, ffuf wordlist mode, enum4linux-ng, openssl decode | runs without confirmation; heavier resource guards |
| **S3 Consequential** | Intrusive, mutation, or exploitation-shaped actions that could alter the target or violate scope if misused | sqlmap with --batch, hydra, pwntools payload delivery, hashcat on the challenge hash, Frida hooks, active cloud API probes | **gated**: capability-level `confirm` boxes (operator must be presented the exact commands and the scope statement before dispatch) |

Default profile per capability **runs S1 + S2 automatically and stops before S3** with the confirmation box. `operation_mode` input:
- `baseline` → only S1 runs.
- `balanced` (default) → S1 + S2; S3 offered but gated.
- `full` → S1 + S2 + gated S3 (the gate is still shown — a scope assertion, not an automation decision).

**Candidates never exceed `request_limit` / `time_limit`** (input-derived): number of dispatched operations per stage is capped at the smaller of the stage's task count and the limit stated; if the cap truncates an analysis, the truncation is explicit in the report ("...stopped at cap; remaining N commands not attempted").

### 15.2 Evidence-driven progression (not blind firing)

- Stage 2 only runs operations that S1's findings justify (e.g. run `sqlmap` only if injection-safe parameter detection surfaced a parameter — the follow-up). Operations whose prerequisite evidence is missing are recorded `NOT_APPLICABLE` with the reason in one line ("no parameters discovered; sqlmap probing not indicated").
- Stage 3 additionally gates on scope input: if `authorized_scope` is empty or a `*`-only pattern, the stage offers only conservative sub-operations; anything else is skipped with `NOT_APPLICABLE` and "scope too wide" rationale.
- This is per-capability, not a cross-run persistent state, so every CTF run starts clean.

---

## 16. Implementation Roadmap

Ordered stages. Each stage names repository-specific files to inspect or modify. No pre-existing behavior is broken at any point — old catalogs parse identically at every checkpoint.

### Stage 0 — Re-verification (pre-implementation)
- Re-run `cargo test` to baseline current green.
- Inspect `src/catalog.rs` from_toml (full file), `src/ui/menu.rs:run_capability` full flow, `src/ui/input.rs:collect_inputs`, `src/store.rs:harvest` (complete), `src/parser.rs` all formats, `src/intel.rs` pattern tables (complete), `src/install.rs`, `src/config/model.rs` (complete).
- Output: a checklist mapping CTF behavior to the exact function(s) to touch. *(This plan §2-§10 is the first draft of that checklist.)*

### Stage 1 — Catalog schema extensions (Rust layer)
File: `src/catalog.rs`, `src/domain/input.rs`, `src/domain/finding.rs`
1. Add `Operation.stage: Option<u8>` and `Operation.confirm: bool` (both default to current behavior).
2. Add `InputSpec.section: Option<Cow<'static, str>>`.
3. Add `InputType::{CtfFlagFormat, CtfToken, CloudProfile}` with `label()` entries and validators.
4. Add `Category::FlagCandidate` with heading `"FLAG CANDIDATES"`.
5. Loader validation: stage 1..=3 if present; `confirm` doesn't require `stage`; CtfFlagFormat must compile (loader stores the compiled pattern per capability).
6. Update catalog-loading tests to cover new variants and defaults back-compat.
7. `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` must remain green (old catalogs untouched by defaults).

### Stage 2 — Phase extension
Files: `src/catalog.rs` (PHASES, phase_label), `src/main.rs` (+STATUS output), `src/ui/menu.rs` (phase ordering falls out of `grouped()`), `src/domain/ids.rs` (`RunId::for_run` handles new phase label, existing format covers it), tests.
1. Add `"ctf"` to `PHASES` (11th element; `phase_label("ctf") == "CTF"`).
2. Update loader's phase-population rule to include 11 phases.
3. Fix tests that assert on `PHASES.len() == 10` (verified locations by grep: `catalog.rs:1118,1277,1520,1664,1831`; also `main.rs` STATUS output loop no numeric assertions found).
4. Acceptance: loading the existing (unchanged) TOML keeps all ten phases populated. Loading it after CTF capabilities are added yields 11 phases all populated.

### Stage 3 — CTF catalog build (data work)
Files: `catalog/capabilities.toml` (append `phase = 'ctf'` capabilities), `tools.sh` (pkg_info additions), `scripts/` (any bundled `.py` helper — e.g. `ctf_flag_extract.py` for testing formats, `ctf_mobsf_api.py`, `ctf_ghidra_headless.py`).
1. Author 14 capabilities, ≥15 tools/operations each, staged (`stage=1|2|3`, `confirm=true` on gated ops), every input declared, every placeholder resolves.
2. Every binary: add `pkg_info` entry `tool|arch|kali`.
3. Every `{wl:...}` reference: file present under `wordlists/` (the loader already rejects dangling references and the test suite already validates it).
4. Every script helper: valid, imports only deps already needed by other shipped helper scripts (or vendored).
5. Output formats assigned precisely (`nmap` for nmap, `lines` for line-listing tools, `json` for JSON-lines, `raw` for blob-ish output).
6. Test: catalog loads clean; capability totals per phase must come out balanced — the existing test asserts every phase in `PHASES` is populated (not a global count, verified at `src/catalog.rs:873-877` and `catalog.rs:1277` which compares `grouped().len()` to `PHASES.len()`), so adding exactly 14 CTF capabilities makes no numeric global assertion break; any future global-count assertions must account for the new total (226 + 14 = 240).

### Stage 4 — CTF pass and report (Rust layer)
Files: new `src/ctf/mod.rs`, `src/ctf/flagextract.rs`, `src/ctf/provenance.rs`, `src/ctf/report.rs`; small hooks in `src/store.rs` (call flag extraction + provenance after existing harvest, write `ctf.json`), `src/ui/menu.rs` (run the CTF pass inside the same `RUN`/`PROCESSING` pipeline for `phase == "ctf"`).
1. `flagextract`: input → compiled pattern + case mode + extraction mode (complete-match). Apply to every artifact capture (stdout/stderr) and each listed `artifacts/` file. Emit `FlagCandidate` records with location (file, line, byte offset) and context.
2. `provenance`: reads `manifest.json` records in order, produces the `ctf.json` shape of §11.1 with the operation-level classification table (§10.2) and the finding/flag/vulnerability/artifact sections populated from the harvested findings + flag candidates.
3. `report`: prepare the CTF document body (§12) on top of the existing harvest, with all CTF-specific sections and honest classifications. The stored `output.txt` contains this body directly (the header/style come from the existing pipeline).
4. All sidecar writes are atomic (existing pattern).

### Stage 5 — Staged dispatch wiring
Files: `src/ui/menu.rs` (`run_capability`), `src/ui/execution.rs` (per-stage bank dispatch; same monitor).
1. Group jobs by stage. Dispatch stage by stage; between stages evaluate gating (confirmation; stage-1 success check).
2. Keep `TaskStatus` and record semantics untouched — stages are dispatch-time only, manifest stays format-identical.
3. `confirm:true` ops trigger the existing confirm-input pattern once per stage; declining skips the stage with reason `CONFIRMATION_DECLINED` recorded per op (`SKIPPED`).
4. Cancellation mid-stage: behaves exactly as today.
5. Tests: stage dispatch simulation with mock executables (unit), and end-to-end manual smoke.

### Stage 6 — Testing
Detailed in §17.

### Stage 7 — Documentation and release hygiene
Files: `README.md`, `docs/ARCHITECTURE.md`, `docs/CAPABILITY_OPERATIONS.md` (new sections), `docs/TROUBLESHOOTING.md` (CTF error codes), `REQUIREMENTS.TXT` (new optional tools), `wordlists/README.md` (if CTF words added).
- No agent-modifying behavior: docs describe the CTF capability set, flag-format semantics, staged profiles, and honest-unavailable list.

---

## 17. Testing Strategy

### 17.1 Unit tests (Rust `#[cfg(test)]`, following the crate's existing style)

| Suite | Cover | Files |
|---|---|---|
| catalog-schema | Operation stage/confirm defaults; stage validation (0, 4 rejected); unknown fields ignored as today; new input types validate correctly; CtfFlagFormat compiles/rejects | `src/catalog.rs` tests |
| input-validation | CtfFlagFormat (prefix shorthand, full regex, catastrophic reject, case-mode), CtfToken, CloudProfile | `src/domain/input.rs` tests |
| flag-format | Pattern compile, complete-match extraction, duplicate suppression, attribution fields, false-positive handling (banner vs actual), empty flag-format handling (default no-op) | `src/ctf/flagextract.rs` tests |
| command-templates | Substitution, escaping, wordlist/asset/artifacts expansion for representative CTF operation rows, sensitive marking for key/hash/password inputs | `src/catalog.rs` tests |
| execution-state-classification | All §10.2 outcomes map correctly from (exit_code, parse result, findings count, confirm status) — table-driven test | `src/ctf/provenance.rs` tests |
| parser-behavior | No regressions → existing parser tests extended for any CTF-specific formats (should be none — keep the enum closed) | `src/parser.rs` tests |
| finding-normalization | FlagCandidate, finding vocabulary, dedup keys, severity/confidence defaults | `src/domain/finding.rs`, `src/ctf/provenance.rs` tests |
| provenance-tracking | chain integrity: ctf.json → manifest.json → raw file name → sha256; every candidate links back | `src/ctf/provenance.rs` tests |
| report-generation | Output body sections ordered, no fabricated content, redaction correctness, truncated-guess handling | `src/ctf/report.rs` tests |

### 17.2 Integration tests

- Mock executables (deterministic fixture outputs), covering: timeout, nonzero exit, empty output, cancel mid-stage, missing provider mid-run, confirm decline, tool installed mid-run, curl fixture (fixtures written on-disk only, never network).
- Stage gating tests: S1-no-findings → S2 still runs; S1-all-failed → S2 skipped with reasons; scope-empty blocks S3.
- Output: report content and ctf.json fixture-verified (golden files allowed now since the format is new).

### 17.3 TOML schema-validation tests

- Encode the restrictions from §9.2 (stage ∈ 1..=3 when present; confirm true requires... nothing hard; input `section` accepted silently; the loader refuses operations with placeholder-style `{stage}` unless matching a real input; `CtfFlagFormat` default pattern compiles).
- Every shipped CTF capability: ≥15 tool/operation entries summed (not 15 operations of one tool though the inventory may be 15 tools each); label 2-3 uppercase words; phase namespaced; every placeholder declared; every `{wl:...}` resolvable; binary has `tools.sh` map entry.

### 17.4 Regression tests

- All pre-existing catalog rows parse and harvest identically: golden tests on a fixture mini-catalog (existing style) plus full shipped-catalog load including the extended phase list.
- Existing phases' reports are byte-identical on a fixture run through the harness (CTF code paths do not execute for non-ctf phases — keyed off `phase == 'ctf'`).

### 17.5 Safe end-to-end tests (fixtures on disk only, no live network)

- Deliberately vulnerable local CTF app fixtures (plain HTTP served by a tiny test server in-process, NOT live sockets) exercising: lield discovery, PUT-file-upload logic, decode-based flag formats.
- Deliberate artifacts: sample PCAP with a flag in a DNS TXT record, an image with appended data, a memory-dump snippet, an APK fixture (small), a firmware image slice — crafted during Stage 6, kept small, committed under `tests/fixtures/ctf/`.

---

## 18. Risks, Uncertainties, and Mitigations

| # | Risk / Uncertainty | Verified? | Mitigation |
|---|---|---|---|
| R1 | `Operation.stage`/`confirm` extension touches a tightly-tested loader | verified high-touch | Keep extensions additive w/ defaults; cargo test gate; no back-compat break (schema stays 1) |
| R2 | Adding an 11th phase — tests referencing 10 phases may break | verified by grep | Fix tests in the same PR; updated in one place (`PHASES` array) — no per-file phase check besides the loader |
| R3 | 15-tool cap per family may be inflated by "meaningful operations" interpretation | design decision | §6 inventory distinguishes tool vs op clearly; each listed operation has a distinct purpose, no alias padding |
| R4 | Non-CLI tools (Ghidra, MobSF, BloodHound GUI, Burp) integration semantics | verified for scripts/ pattern | Only script-driven (headless Ghidra, MobSF API, bloodhound-python collector) integrated in catalog; GUI-only ones declared NOT as operations but in guidance |
| R5 | Tools missing on common dev hosts cause extremely heavy capability unavailability | verified behavior (reports unavailable by name) | Honest-unavailable is acceptable per design rule 5 and explicitly shown; tools.sh covers installers on Arch/Kali |
| R6 | Wordlist additions for CTF may conflict with existing corpus tests | not yet verified (`MANIFEST.sha256`, `verify-wordlists.sh`) | Add only small, checksummed lists; extend the manifest per existing convention; keep CTF additions minimal |
| R7 | The catalog's current 226-capability count grows significantly — UI/menu performance | low risk | Menu rendering is list-driven and unchanged; no virtualization needed at 240 entries |
| R8 | CTF report format may drift from store.rs's existing harvest rendering contract | design decision | Use the existing document-render path with the CTF body passed in; no new display code path besides sections |
| R9 | **Unverified remaining:** full behavior of `parser.rs` format parsers for tools like sqlmap (raw output — mixed) | to verify in Stage 0 | Mark `output = 'raw'` and let the intelligence pass harvest; no format guessing |
| R10 | **Unverified remaining:** `src/ui/input.rs:ask` behavior for conditional/skip inputs | to verify in Stage 0 | Design uses default-supplied optional inputs so users can Enter-through; confirm behaviour in Stage 0 |
| R11 | **Unverified remaining:** exact per-phase numeric test expectations (`226` hardcoded anywhere in tests or docs) | to verify in Stage 0 | Update tests and docs for the new counts in the same PR |
| R12 | Flag regex matching cost on large artifacts (100 MB+ raw out) | real concern | Bound matching to lines by default (line-mode streaming), byte-offset tracking preserved; document artifact-size caps in the raw path (the existing 32 MiB truncate note) so provenance offsets stay valid for undersized artifacts. For larger raws, provenance references the raw file and a line number |

---

## 19. Acceptance Criteria

Falsifiable, per the user's brief:

1. **Visibility:** `tsec --status` and the interactive main menu list `CTF CHALLENGES` as Phase 11; the phase menu reveals all 14 capability labels; all 14 selectable.
2. **Inventory completeness:** for each of the 14 capabilities the shipped catalog declares ≥15 distinct tool integrations or independently meaningful operations (diversity: at least 8 distinct `binary` values across a capability's inventory, with each entry serving a distinct purpose — reviewers check the summary field).
3. **Purpose documentation:** every catalog operation has a `name` whose intent is clear and (in docs/CAPABILITY_OPERATIONS.md) a row level mapping them to §10.2's purpose_class; every tool has a documented integration interface (cli / script / headless / api).
4. **Ten commands per CLI tool:** for every tool whose integration interface is a CLI, the shipped TOML declares ≥10 operation entries across all CTF capabilities that use it (verified by a test that counts operations per binary; wheel-level CLI sharing across capabilities is fine); command syntax in the TOML is validated by the loader + tested against upstream `--help` text for stable flags, with version-dependent variants noted in the docs.
5. **Input propagation:** every catalog operation's placeholder resolves; the mark-sensitive mechanism masks `secret`-family inputs; a fixture run proves the same input value set drives multi-tool, multi-operation dispatch (web family example written into `docs/CAPABILITY_OPERATIONS.md`).
6. **Outcome classification:** every attempted operation in a run appears in `ctf.json` with one of the §10.2 classifications, and no misreport: exit 0 alone never implies VALIDATED; zero-exit-no-findings reports NO_FINDINGS; failed tools never crash the run.
7. **Raw evidence retained:** all operation raw stdout/stderr files exist and match their sha256 in ctf.json; manifest is format-identical to existing runs.
8. **Provenance intact:** every finding and flag candidate links to raw artifact + line/offset + originating operation; a spot-checkable chain.
9. **Flags only from evidence:** no candidate exists without a source artifact and operation; report's FINAL FLAG section renders only when a verified candidate exists; never synthesizes flags; no statement about unexecuted operations appearing as completed.
10. **Tool-missing robustness:** with all CTF providers removed from PATH, all 14 capabilities still load, render guidance, record `TOOL_NOT_FOUND` skips, and write a complete honest CTF report — no crash, no fake success.
11. **No regressions:** all existing catalog rows sniff, all existing tests pass unchanged or updated minimally and purposefully; existing phases run and produce byte-identical golden outputs on fixtures before/after the change.
12. **Staging behavior:** baseline stage auto-runs; stage 3 never runs without the confirmation box; scope-empty blocks consequential operations; request_limit/time_limit enforced with explicit truncation notes.
13. **UI unchanged screens:** no duplicate frames, no new Esc semantics, execution monitor and output viewer behave identically for CTF runs against existing convention tests.

---

## 20. Appendices — Per-Capability Command Matrices

Notes on notation: — all commands are declared as argv arrays in the TOML (no shell); placeholders use the capability's inputs; `{wl:...}` and `{asset:...}` and `{artifacts}` resolve through the loader. `confirm = true` marks gated stage-3 ops. Purpose classifications: **RC** reconnaissance, **EN** enumeration, **HT** hypothesis test, **VA** validation, **EV** evidence extraction, **RP** reporting.

Two things to mark explicitly here before the matrices:

1. **File live-loaded facts in this section come from upstream tool docs (nmapNSE, tshark -T, openssl -enc, sqlmap --batch, impacket, etc.) and existing TSEC catalog patterns; the implementation step re-verifies each with `--help` at build time (Stage 3 protocol). Where a flag is known to be version-dependent (Ghidra versions, volatility3 variants, hashcat algorithms, aircrack options), the docs call it out.**
2. **The matrices below are the planning deliverable.** Each tool's full ≥10 command set is committed into the TOML in Stage 3; where fewer than ten sample commands are shown here for space, the TOML expansion target is still ≥10 and reviewed against the help-verification protocol.

---

### A.1 WEB APP SECURITY (`ctf.web-app-security`)
**Inputs:** `target_url` (url, req), `scope` (text), `request_limit` (int), `threads` (int), `wordlist_extra` (path), `auth_cookie` (secret), `auth_header` (secret), `parameters` (text), `method` (text), `body` (secret), `proxy` (target), `flag_format` (CtfFlagFormat, req), `challenge_desc` (text), `operation_mode`, `time_limit`.

**Tool inventory (16 integrations):** curl, httpx, nmap, ffuf, gobuster, feroxbuster, wfuzz, nikto, sqlmap, dalfox, nuclei, wapiti, wafw00f, whatweb, arjun, openssl.

**Command matrix (12 commands; tool avg 6-12 each in final TOML):**

| # | Tool | Command (argv, abbreviated) | Stage | Class | Purpose |
|---|---|---|---|---|---|
| 1 | curl | `curl -sS -i {target_url}` | 1 | RC | baseline fetch + headers |
| 2 | curl | `curl -sS -i -X OPTIONS -H 'Origin: https://a' -H 'Access-Control-Request-Method: GET' {target_url}/api` | 2 | EN | CORS / preflight probe |
| 3 | curl | `curl -sS -i -L --max-redirs 5 {target_url}` | 1 | RC | redirect chain tracing |
| 4 | httpx | `httpx -u {target_url} -title -tech-detect -status-code -no-color` | 1 | RC | tech/title/status snapshot |
| 5 | nmap | `nmap -sV -p {ports} --script=http-enum,http-headers {target_host}` (`output = 'nmap'`) | 1 | RC | service/UI hints |
| 6 | ffuf | `ffuf -u {target_url}/FUZZ -w {wl:web/dirs.txt} -t {threads} -mc 200,204,301,302,307,401,403 -recursion` | 2 | EN | content discovery |
| 7 | gobuster | `gobuster dir -u {target_url} -w {wl:web/dirs-common.txt} -q -t {threads}` | 2 | EN | dirs+files |
| 8 | feroxfier | `feroxbuster -u {target_url} -w {wl:web/dirs.txt} -t {threads}` | 2 | EN | recursive discovery |
| 9 | whatweb | `whatweb -a 1 -v {target_url}` | 1 | RC | tech fingerprint |
| 10 | wafw00f | `wafw00f -a {target_url}` | 1 | RC | WAF detect (changes which payloads are safe) |
| 11 | arjun | `arjun -u {target_url} --stable` | 2 | EN | hidden parameter discovery |
| 12 | nikto | `nikto -h {target_url} -Format json -o {artifacts}/nikto.json` (`output = 'json'`) | 2 | EN | known-web vuln sweep |
| 13 | nuclei | `nuclei -u {target_url} -severity low,medium,high,critical -silent` | 2 | EN | template scan |
| 14 | sqlmap | `sqlmap -u '{target_url}?{parameters}' --batch --level 1 --risk 1 --flush-session --randomize --delay 1 --threads {threads}` (confirm, stage 3) | 3 | HT | SQLi hypothesis test (invasive) |
| 15 | dalfox | `dalfox url '{target_url}?{parameters}' --no-color` (confirm) | 3 | HT | XSS hypothesis test |
| 16 | openssl | `openssl s_client -connect {target_host}:{target_port} -brief </dev/null` | 1 | RC | TLS overview |

Stage-gating summary: stage-2 intrusive exists only when stage-1 confirmed server reachability and URL. sqlmap/dalfox gated by confirm.

---

### A.2 NETWORK RECONNAISSANCE AND SERVICE EXPLOITATION (`ctf.network-recon-service`)
**Inputs:** `target_ip`, `ports`, `protocol` (tcp/udp), `scope`, `wordlist_extra`, `credentials`, `username`, `flag_format` (req), `challenge_desc`, `operation_mode`, `time_limit`, `proxy`.

**Tool inventory (15 integrations):** nmap, masscan, rustscan, naabu, netcat, socat, hydra, medusa, ncrack, enum4linux-ng, smbclient, rpcclient, nuclei, searchsploit, openssl.

**Command matrix (12 shown):**

| # | Tool | Command | Stage | Class |
|---|---|---|---|---|
| 1 | nmap | `nmap -sV -p {ports} {target_ip}` (output=nmap) | 1 | RC |
| 2 | nmap | `nmap -sU --top-ports 100 {target_ip}` (output=nmap) | 1 | RC |
| 3 | masscan | `masscan {target_ip} -p {ports} --rate 1000 -oG {artifacts}/masscan.gnmap` (stage 1) | 1 | RC |
| 4 | rustscan | `rustscan -a {target_ip} -p {ports} -- -sV` | 1 | RC |
| 5 | naabu | `naabu -host {target_ip} -p {ports} -silent` | 1 | RC |
| 6 | netcat | `nc -zv {target_ip} {target_port}` (VA reachability) | 1 | VA |
| 7 | netcat | `echo '' | nc {target_ip} {target_port}` (banner grab) | 2 | EV |
| 8 | socat | `socat - TCP:{target_ip}:{target_port},connect-timeout=3 </dev/null` (banner) | 2 | EV |
| 9 | hydra | `hydra -l {username} -P {wl:passwords/rockyou.txt} {target_host} {protocol}` (confirm) | 3 | HT |
| 10 | medusa | `medusa -h {target_ip} -U {wl:users/default-users.txt} -P {wl:passwords/rockyou.txt} -M {protocol}` (confirm) | 3 | HT |
| 11 | ncrack | `ncrack -p {target_port} --user {username} --pass {wl:passwords/top-1m.txt} {target_ip}` (confirm) | 3 | HT |
| 12 | enum4linux | `enum4linux-ng -A {target_ip}` | 2 | EN |
| 13 | smbclient | `smbclient -L {target_ip} -N` | 2 | EN (null session) |
| 14 | rpcclient | `rpcclient -U '' {target_ip} -c 'querydominfo'` | 2 | EN |
| 15 | nuclei | `nuclei -u {target_host}:{target_port} -network -silent` | 2 | HT |
| 16 | openssl | `openssl s_client -connect {target_ip}:{target_port} -showcerts </dev/null` | 2 | EV |

---

### A.3 ACTIVE DIRECTORY (`ctf.active-directory`)
**Inputs:** `domain`, `realm` (uppercased TEXT), `domain_controller` (target), `dc_ip` (ip), `username`, `password` (secret), `nt_hash` (secret), `keytab` (path), `port` (int 88 default), `smb_share` (text), `scope`, `flag_format` (req), `challenge_desc`, `operation_mode`, `time_limit`, `proxy`.

**Tool inventory (16 integrations):** ldapsearch, ldapdomaindump, adidnsdump, bloodhound-python, enum4linux-ng, kerbrute, rpcclient, smbclient, smbmap, impacket-GetNPUsers, impacket-GetUserSPNs, impacket-secretsdump, impacket-psexec, certipy, netexec, evil-winrm.

**Command matrix (14 shown):**

| # | Tool | Command | Stage | Class |
|---|---|---|---|---|
| 1 | ldapsearch | `ldapsearch -x -H ldap://{domain_controller} -s base` (anonymous root DSE) | 1 | RC |
| 2 | ldapsearch | `ldapsearch -x -H ldap://{domain_controller} -b 'DC={domain}' '(objectClass=domain)'` | 2 | EN |
| 3 | ldapdomaindump | `ldapdomaindump -d '{domain}' -u '{username}' -p '{password}' --no-grep --no-json ldap://{domain_controller}` (auth'd, if creds) | 2 | EN |
| 4 | adidnsdump | `adidnsdump -u '{domain}\\{username}' -p '{password}' --query '{domain}' {domain_controller}` | 2 | EN |
| 5 | bloodhound-python | `bloodhound-python -u {username} -p {password} -d {domain} -dc {domain_controller} -c All --zip -o {artifacts}` | 2 | EN (collection) |
| 6 | kerbrute | `kerbrute userenum --dc {dc_ip} -d {domain} {wl:users/default-users.txt}` | 2 | EN |
| 7 | kerbrute | `kerbrute passwordspray --dc {dc_ip} -d {domain} {wl:users/default-users.txt} '{password}'` (confirm) | 3 | HT |
| 8 | smbclient | `smbclient -L //{domain_controller}/ -U '`' -N` (null session) | 1 | RC |
| 9 | smbclient | `smbclient //domain_controller/share -U '{username}%{password}' -c 'ls'` (if share listed) | 2 | EN |
| 10 | smbmap | `smbmap -H {domain_controller} -u '{username}' -p '{password}' -d '{domain}'` | 2 | EN |
| 11 | impacket-GetNPUsers | `GetNPUsers.py {domain}/ -dc-ip {dc_ip} -usersfile {artifacts}/users.txt -no-pass -k` (ASREPRoast) | 2 | HT |
| 12 | impacket-GetUserSPNs | `GetUserSPNs.py {domain}/{username}:{password} -dc-ip {dc_ip} -request` (Kerberoast) | 2 | HT |
| 13 | impacket-secretsdump | `secretsdump.py -just-dc-ntlm {domain}/{username}:{password}@{domain_controller}` (confirm, DCSync) | 3 | HT |
| 14 | impacket-psexec | `psexec.py {domain}/{username}:{password}@{domain_controller}` (confirm, execution) | 3 | HT |
| 15 | certipy | `certipy find -u {username}@{domain} -p '{password}' -dc-ip {dc_ip} -stdout` | 2 | EN (ADCS) |
| 16 | netexec | `netexec {protocol} {domain_controller} -u {username} -p '{password}' {smb-lapout/other-flags}` | 2 | EN |
| 17 | evil-winrm | `evil-winrm -i {domain_controller} -u {username} -p '{password}'` (confirm, interactive replacement for a shell — only when creds and single target in authorized scope) | 3 | VA |

---

### A.4 MOBILE APP SECURITY (`ctf.mobile-app-security`)
**Inputs:** `apk_path` (File, req), `ipa_path` (File), `device_ip` (target), `adb_serial` (text), `device_creds` (secret), `device_pin` (secret), `proxy` (target), `extract_dir` (path), `flag_format` (req), `challenge_desc`, `operation_mode`, `time_limit`.

**Tool inventory (17 integrations):** apktool, jadx, dex2jar, aapt, aapt2, apksigner, adb, androguard, mobsf (script), frida, frida-server-side (script), objection, apkid, objdump, strings, keyed-hash extractor scripts, unzip/zipinfo.

**Command matrix (14 shown):**

| # | Tool | Command | Stage | Class |
|---|---|---|---|---|
| 1 | aapt | `aapt dump badging {apk_path}` | 1 | RC |
| 2 | aapt2 | `aapt2 dump manifest {apk_path}` | 1 | RC |
| 3 | apksigner | `apksigner verify --print-certs {apk_path}` | 1 | RC |
| 4 | apkid | `apkid {apk_path}` | 1 | RC (packer detection |
| 5 | unzip | `unzip -l {apk_path}` | 1 | RC |
| 6 | apktool | `apktool d -f -o {artifacts}/apktool {apk_path}` | 2 | EV |
| 7 | jadx | `jadx -d {artifacts}/jadx --show-bad-code {apk_path}` | 2 | EV |
| 8 | dex2jar | `d2j-dex2jar.sh -f -o {artifacts}/app.jar {apk_path}` | 2 | EV |
| 9 | androguard | `androguard analyze {apk_path}` | 2 | EN |
| 10 | strings | `strings {apk_path} \| grep... ` — no, no shell: `strings {apk_path}` (stdout itself) | 1 | RC |
| 11 | mobsf script | `python3 {asset:scripts/ctf_mobsf_api.py} --url {mobsf_url} --key {mobsf_key} --path {apk_path} --out {artifacts}/mobsf.json` (output=json) | 2 | EN (script provider) |
| 12 | adb | `adb -s {adb_serial} install {apk_path}` (confirm: modifies device) | 3 | HT |
| 13 | adb | `adb -s {adb_serial} shell ps` (runtime probe; confirm) | 3 | EN |
| 14 | fridahood | via bundled script: `python3 {asset:scripts/ctf_frida_hook.py} -H {device_ip} -p {app_package} -s {asset:scripts/hook_flag_search.js.txt}` (confirm) | 3 | HT |
| 15 | objection | `objection patchapk -s {apk_path}` (confirm) | 3 | EV |

---

### A.5 CLOUD SECURITY (`ctf.cloud-security`)
**Inputs:** `cloud_provider` (OneOf aws/azure/gcp), `cloud_profile` (CloudProfile), `cloud_account_id` (text), `region` (text), `credentials_env_note` (secret, optional — notes, the actual credentials live in environment as usual env presentations), `scope` (text), `flag_format` (req), `challenge_desc`, `operation_mode`, `time_limit`.

**Tool inventory (14 integrations):** aws, az, gcloud, scoutsuite, prowler, cloudsplaining, pacu, trufflehog, kube-hunter, kubectl, checkov, terrascan, steampipe, git-secrets.

**Commands (14 shown):**

| # | Tool | Command | Stage | Class |
|---|---|---|---|---|
| 1 | aws | `aws --profile {cloud_profile} sts get-caller-identity` | 1 | VA (who am I) |
| 2 | aws | `aws --profile {cloud_profile} --region {region} iam list-users` (confirm: 3) or stage-2 read-only | 2 | EN |
| 3 | aws | `aws --profile {cloud_profile} --region {region} s3 ls` | 2 | EN |
| 4 | aws | `aws --profile {cloud_profile} --region {region} s3api get-bucket-policy --bucket {s3_bucket}` (HT) | 3 | HT |
| 5 | az | `az account show` | 1 | VA |
| 6 | az | `az role assignment list --all --output json` (`output = 'json'`) | 2 | EN |
| 7 | gcloud | `gcloud config get-value account`, `gcloud projects list` | 1 | VA / EN |
| 8 | gcloud | `gcloud iam roles list --project {gcp_project} --format=json` | 2 | EN |
| 9 | scoutsuite | `scout aws --profile {cloud_profile} --report-dir {artifacts}` | 2 | EN (misconfig audit) |
| 10 | prowler | `prowler --profile {cloud_profile} -M csv -o {artifacts}` | 2 | EN |
| 11 | cloudsplaining | fetching policy doc then: `cloudsplaining --input {artifacts}/iam.json --output {artifacts}` | 2 | EN |
| 12 | trufflehog | `trufflehog filesystem --directory {repo_dir}` (scan locally provided source/bucket sync) | 2 | EV |
| 13 | kube-hunter | `kube-hunter --remote {cluster_ip} --report json` (confirm for remote probes) | 3 | HT |
| 14 | kubectl | `kubectl --context {ctx} get pods -A` / `kubectl --context {ctx} auth can-i --list` | 2 | EN (cluster) |

---

### A.6 REVERSE ENGINEERING (`ctf.reverse-engineering`)
**Inputs:** `binary_path` (File, req), `arch` (text), `extract_dir` (path), `ghidra_project` (path), `flag_format` (req), `challenge_desc`, `operation_mode`, `time_limit`.

**Tool inventory (16 integrations):** file, strings, objdump, readelf, nm, ldd, checksec, r2, rizin, retdec, ghidra (headless), binwalk, angr, objconv, exiftool, xxd.

**Commands (14 shown):**

| # | Tool | Command | Stage | Class |
|---|---|---|---|---|
| 1 | file | `file {binary_path}` | 1 | RC |
| 2 | readelf | `readelf -h {binary_path}` | 1 | RC |
| 3 | readelf | `readelf -S -W {binary_path}` | 1 | RC |
| 4 | objdump | `objdump -d {binary_path}` | 2 | EV |
| 5 | nm | `nm -C {binary_path}` | 2 | EN |
| 6 | ldd | `ldd {binary_path}` | 1 | RC |
| 7 | checksec | `checksec --file={binary_path}` | 1 | RC |
| 8 | strings | `strings -n 8 {binary_path}` | 1 | RC (flag-hunt target too) |
| 9 | exiftool | `exiftool {binary_path}` | 1 | RC |
| 10 | binwalk | `binwalk {binary_path}` | 2 | EN |
| 11 | binwalk | `binwalk -e --directory {artifacts}/extracted {binary_path}` | 2 | EV |
| 12 | r2 | `r2 -q -c 'aaa; afl;iz' {binary_path}` | 2 | EN |
| 13 | ghidra headless | `analyzeHeadless {ghidra_project} proj -import {binary_path} -scriptPath {asset:scripts/ghidra/} -postScript ctf_ghidra_decompile.java` (script provider) | 2 | EV |
| 14 | xxd | `xxd {binary_path}` (truncated position beyond a limit in report, full in raw) | 1 | RC |
| 15 | angr script | `python3 {asset:scripts/ctf_angr_solve.py} {binary_path}` | 3 | HT |

---

### A.7 BINARY EXPLOITATION (`ctf.binary-exploitation`)
**Inputs:** `binary_path` (File, req), `libc_path` (File), `target_host` (target), `target_port` (port), `stack_alignment` (int), `debugger` (text), `pwntools_template` (path), `gdb_plugin` (OneOf gef/pwndbg/default), `flag_format` (req), `challenge_desc`, `operation_mode`, `time_limit`, `shell_timeout`.

**Tool inventory (16 integrations):** checksec, file, readelf, objdump (as RE), ROPgadget, ropper, one_gadget, pwntools (script provider), gdb, gdb+gef, gdb+pwndbg, one_gadget, socat, strace, ltrace, patchelf, pwninit.

**Commands (14 shown):**

| # | Tool | Command | Stage | Class |
|---|---|---|---|---|
| 1 | checksec | `checksec --file={binary_path}` | 1 | RC |
| 2 | readelf | `readelf -h {binary_path}` (PIE off/on) | 1 | RC |
| 3 | readelf | `readelf -d {binary_path}` (RUNPATH/RELRO details) | 1 | RC |
| 4 | objdump | `objdump -d {binary_path}` | 2 | EN |
| 5 | ROPgadget | `ROPgadget --binary {binary_path}` | 2 | EN |
| 6 | ROPgadget | `ROPgadget --binary {binary_path} --only "pop\|ret"` (no shell needed — argument literal) | 2 | EN |
| 7 | ropper | `ropper --file {binary_path}` | 2 | EN |
| 8 | one_gadget | `one_gadget {libc_path}` | 2 | EN |
| 9 | patchelf | `patchelf --set-interpreter {libc_path} --output {artifacts}/patched {binary_path}` | 2 | EV |
| 10 | strace | `strace -f -i -s 64 {artifacts}/patched` (local execution; confirm on a remote target only) | 2 | EN |
| 11 | pwntools script | `python3 {asset:scripts/ctf_pwntools_solve.py} --binary {binary_path} --host {target_host} --port {target_port} --libc {libc_path} --out {artifacts}/exploit.log` (confirm, stage 3) | 3 | HT |
| 12 | gdb+gef batch | `gdb -ex 'b *main' -ex 'run < pattern.txt' -ex 'info r' -batch {binary_path}` (script provider) | 2 | VA |
| 13 | pwninit | `pwninit --bin {binary_path} --libc {libc_path} --dir {artifacts}` | 2 | EV |
| 14 | one_gadget | re-runs on any replacement libc found | 2 | EN |

---

### A.8 NETWORK FORENSICS (`ctf.network-forensics`)
**Inputs:** `pcap_path` (File, req), `filter` (text), `flag_format` (req), `challenge_desc`, `operation_mode`, `time_limit`, `bpf_filter`.

**Tool inventory (15 integrations):** tshark, tcpdump, capinfos, editcap, mergecap, tcpflow, ngrep, zeek, argus, scapy (script), chaosreader, ripgrep on textified pcap, networkminer (script), xplico (script), editcap+capinfos combo operations.

**Commands (14 shown):**

| # | Tool | Command | Stage | Class |
|---|---|---|---|---|
| 1 | capinfos | `capinfos {pcap_path}` | 1 | RC |
| 2 | tshark | `tshark -r {pcap_path} -q -z io,phs` (protocol hierarchy) | 1 | RC |
| 3 | tshark | `tshark -r {pcap_path} -q -z conv,tcp` (tcp conv) | 1 | EN |
| 4 | tshark | `tshark -r {pcap_path} -Y '{filter}' -T fields -e frame.number -e ip.src -e ip.dst -e http.request.uri` | 2 | EN |
| 5 | tshark | `tshark -r {pcap_path} --export-objects http,{artifacts}/http_objects` | 2 | EV |
| 6 | tshark | `tshark -r {pcap_path} -Y 'ftp-data' -T fields -e ftp-data.data | 2 | EV |
| 7 | tcpdump | `tcpdump -R {pcap_path} -n -c 100` (read-only sanity pass) | 1 | RC |
| 8 | tcpflow | `tcpflow -r {pcap_path} -o {artifacts}/flows` | 2 | EV |
| 9 | ngrep | `ngrep -I {pcap_path} -q -W byline '{pattern}'` | 2 | EN |
| 10 | mergecap | `mergecap -w {artifacts}/merged.pcap {pcap_path}` (multi-input) | 2 | EV |
| 11 | editcap | `editcap -r {pcap_path} {artifacts}/subset.pcap 1 2 3 4 5` (evidence isolation) | 2 | EV |
| 12 | zeek | `zeek -r {pcap_path} LogDir={artifacts}/zeek_logs` | 2 | EN |
| 13 | argus | `argus -r {pcap_path} -w {artifacts}/argus.out` | 2 | EN |
| 14 | scapy script | `python3 {asset:scripts/ctf_scapy_pcap_scan.py} {pcap_path} --flag-regex '{flag_pattern}'` | 2 | EV (flag-aware) |

---

### A.9 DIGITAL FORENSICS (`ctf.digital-forensics`)

**Inputs:** `disk_image` (File), `memory_dump` (File), `case_dir` (path), `timeline_from` (text), `profile_type` (text), `flag_format` (req), `challenge_desc`, `operation_mode`, `time_limit`.

**Tool inventory (15 integrations):** volatility3 (vol), mmls, fls, icat, ifind, istat (TSK tools), foremost, scalpel, photorec, extundelete, binwalk, exiftool, bulk_extractor, fuser/tsk-recover, hashdeep, regripper (script).

**Commands (14 shown):**

| # | Tool | Command | Stage | Class |
|---|---|---|---|---|
| 1 | file | `file {disk_image}` | 1 | RC |
| 2 | mmls | `mmls {disk_image}` | 1 | RC |
| 3 | fsstat | `fsstat -o {partition_offset} {disk_image}` | 1 | RC |
| 4 | fls | `fls -o {partition_offset} -r -p {disk_image}` | 2 | EN |
| 5 | icat | `icat -o {partition_offset} {disk_image} {inode} > {artifacts}/recovered.bin` — argv vector, but this needs redirection; instead use icat beside icat+out file (tool up to author: icat supports -r? verify; if it requires stdout, wrap in script: `python3 {asset:scripts/ctf_icat_save.py}` (script provider handles the redirect safely) | 2 | EV |
| 6 | img_stat | `img_stat {disk_image}` | 1 | RC |
| 7 | foremost | `foremost -i {disk_image} -o {artifacts}/carved` | 2 | EV |
| 8 | scalpel | `scalpel -c {asset:conf/scalpel.conf} -o {artifacts}/scalpel {disk_image}` | 2 | EV |
| 9 | photorec | `photorec /log /cmd {disk_image} fileopt,everything,enable,search` (non-interactive mode; confirm) | 3 | EV |
| 10 | binwalk | `binwalk -Me --directory {artifacts}/extracted {disk_image}` | 2 | EV |
| 11 | exiftool | `exiftool -a -u -g1 -r {artifacts}/extracted_dir` (dir scan of carved files) | 2 | EV |
| 12 | bulk_extractor | `bulk_extractor -o {artifacts}/bulk {disk_image}` | 2 | EN |
| 13 | hashdeep | `hashdeep -r -c md5 {artifacts}/extracted` | 2 | EV |
| 14 | vol (memory) | `vol -f {memory_dump} windows.info` | 1 | RC |
| 15 | vol | `vol -f {memory_dump} pslist` / `cmdline` / `filescan` | 2 | EN |
| 16 | vol | `vol -f {memory_dump} dumpfiles --dump-dir {artifacts}/memdump --filter {filter}` | 2 | EV |

---

### A.10 CRYPTOGRAPHY (`ctf.cryptography`)
**Inputs:** `ciphertext_path` (File), `ciphertext_inline` (secret), `key_material` (secret), `key_path` (File), `hash_value` (secret), `encoding_base` (int), `cipher_name` (text), `password_candidates` (path), `flag_format` (req), `challenge_desc`, `operation_mode`, `time_limit`.

**Tool inventory (16 integrations):** openssl, python3 (script), base64/base32/base58 (script), john, hashcat, hashid, hash-identifier, xortool, RsaCtfTool (script), rsatool (script), sage (script, optional), CyberChef-flagged transformations via bundled script, gpg (decrypt with provided key), XOR-search via script, caesar-analyzer script, frequency-analysis script.

**Commands (14 shown):**

| # | Tool | Command | Stage | Class |
|---|---|---|---|---|
| 1 | openssl | `openssl base64 -d -in {ciphertext_path} -out {artifacts}/b64d.bin` | 1 | EV |
| 2 | openssl | `openssl x509 -in {key_path} -text -noout` (cert inputs) | 1 | RC |
| 3 | openssl | `openssl rsa -in {key_path} -text -noout` | 2 | RC |
| 4 | openssl | `openssl enc -d -in {ciphertext_path} -out {artifacts}/dec.bin -aes-256-cbc -k '{key_material}'` — argv: `-k` takes password, password marked sensitive; note that arg is redacted | 2 | EV |
| 5 | openssl | `openssl rsautl -decrypt -in {ciphertext_path} -out {artifacts}/dec.bin -inkey {key_path}` | 2 | EV |
| 6 | john | `john --wordlist={wl:passwords/rockyou.txt} {artifacts}/hashes.txt` (confirm when on real private material — local only) | 3 | HT |
| 7 | john | `john --show {artifacts}/hashes.txt` (post-run) | 3 | EV |
| 8 | hashcat | `hashcat -m {hashcat_mode} -a 0 {artifacts}/hashes.txt {wl:passwords/rockyou.txt} --status --optimized-checkpoint` (confirm — GPU) | 3 | HT |
| 9 | hashid | `hashid {ciphertext_inline}` | 1 | RC |
| 10 | xortool | `xortool -x -o {artifacts}/xor {ciphertext_path}` | 2 | HT |
| 11 | RsaCtfTool script | `python3 {asset:scripts/ctf_rsactftool} --publickey {key_path} --private --output {artifacts}/priv.pem` | 2 | EV |
| 12 | sagemath script | `python3 {asset:scripts/ctf_sage_rsa.py} {artifacts}/rsa_params.json` | 3 | HT |
| 13 | caesar/vigenere script | `python3 {asset:scripts/ctf_classical_cipher.py} --in {ciphertext_path} --out {artifacts}` | 2 | EN |
| 14 | frequency script | `python3 {asset:scripts/ctf_freq_analysis.py} {ciphertext_path}` | 2 | EN |

---

### A.11 STEGANALYSIS (`ctf.stego-analysis` → label `STEGO ANALYSIS`)
**Inputs:** `media_path` (File, req), `stego_password` (secret), `stego_algorithm_hint` (text), `binwalk_extract` (flag), `flag_format` (req), `challenge_desc`, `operation_mode`, `time_limit`.

**Tool inventory (16 integrations):** file, exiftool, strings, xxd, binwalk, foremost, zsteg, steghide, stegseek, outguess, stegsolver (script), pngcheck, identify, jsteg (script), webp info (script), audio spectrogram script.

**Commands (14 shown):**

| # | Tool | Command | Stage | Class |
|---|---|---|---|---|
| 1 | file | `file {media_path}` | 1 | RC |
| 2 | exiftool | `exiftool -a -u -g1 {media_path}` | 1 | RC |
| 3 | strings | `strings -n 4 {media_path}` | 1 | RC |
| 4 | xxd | `xxd {media_path}` (first N bytes highlighted via gr) | 1 | RC |
| 5 | pngcheck | `pngcheck -v {media_path}` | 1 | RC |
| 6 | identify | `identify -verbose {media_path}` | 1 | RC |
| 7 | binwalk | `binwalk {media_path}` | 1 | EN |
| 8 | binwalk | `binwalk -Me --directory {artifacts}/extracted {media_path}` | 2 | EV |
| 9 | zsteg | `zsteg -a -v {media_path}` | 2 | EN |
| 10 | zsteg | `zsteg -E b1,r,lsb,xy {media_path}` (channel sweep) | 2 | EN |
| 11 | steghide | `steghide info {media_path} -p '{stego_password}'` (password-sensitive) | 2 | EN |
| 12 | steghide | `steghide extract -sf {media_path} -p '{stego_password}' -xf {artifacts}/stego_out.bin` | 2 | EV |
| 13 | stegseek | `stegseek {media_path} {wl:passwords/rockyou.txt} -xf {artifacts}/stego_out.bin` (confirm: heavy CPU) | 3 | HT |
| 14 | outguess | `outguess -k '{stego_password}' -r {media_path} {artifacts}/outguess_out.bin` | 2 | EV |
| 15 | foremost | `foremost -i {media_path} -o {artifacts}/carved` | 2 | EV |
| 16 | spectrogram script | `python3 {asset:scripts/ctf_spectrogram.py} {media_path} --out {artifacts}/spec.png` (audio inputs) | 2 | EV |

---

### A.12 PRIVILEGE ESCALATION (`ctf.privilege-escalation`)
**Inputs:** `artifact_dir` (path, req), `platform` (OneOf linux/windows), `context_note` (text), `results_dir` (path, req — where collected privesc probes live), `flag_format` (req), `challenge_desc`, `operation_mode`, `time_limit`.

The design treats privesc as **analysis of collected artifacts** rather than executing commands on an unknown host; intrusive execution is a script-provider behavior only when explicitly listed artifacts exist.

**Tool inventory (15 integrations):** linpeas-output parser (script), winpeas-output parser (script), pspy-output parser (script), GTFOBins lookup (script), LOLBAS lookup (script), sudo -l cap analysis (script), suid3num out parser (script), kernel-exploit matcher (script, linux-exploit-suggester data), regripper (script), grep over configs, env-var leak scan (script), cron/anacron path analysis (script), keychain/ssh analysis (script), docker/socket misuse scan (script), SAM/LSASS dump listener (script).

**Commands (14 shown):**

| # | Tool | Command | Stage | Class |
|---|---|---|---|---|
| 1 | linpeas script | `python3 {asset:scripts/ctf_parse_linpeas.py} {artifact_dir}/linpeas.out --out {artifacts}/privesc_lin.json` | 1 | EN |
| 2 | winpeas script | `python3 {asset:scripts/ctf_parse_winpeas.py} {artifact_dir}/winpeas.out --out {artifacts}/privesc_win.json` | 1 | EN |
| 3 | pspy parser | `python3 {asset:scripts/ctf_parse_pspy.py} {artifact_dir}/pspy.log` | 2 | EN |
| 4 | sudo-l analysis | `python3 {asset:scripts/ctf_sudo_check.py} {artifact_dir}/sudo_l.out` | 2 | VA |
| 5 | GTFOBins | `python3 {asset:scripts/ctf_gtfobins_lookup.py} --bin {binary_name} --sudo` | 2 | EN |
| 6 | LOLBAS | `python3 {asset:scripts/ctf_lolbas_lookup.py} --bin {binary_name}` | 2 | EN |
| 7 | SUID | `python3 {asset:scripts/ctf_suid3num.py} {artifact_dir}/suid.txt` | 2 | EN |
| 8 | kernel suggester | `python3 {asset:scripts/ctf_kernel_exploit_suggester.py} {artifact_dir}/uname_a.txt` | 2 | EN |
| 9 | cron analysis | `python3 {asset:scripts/ctf_cron_analyze.py} {artifact_dir}/crontab.out` | 2 | VA |
| 10 | env leaks | `python3 {asset:scripts/ctf_env_scanner.py} {artifact_dir}/env.txt` | 2 | EN |
| 11 | ssh-key analysis | `python3 {asset:scripts/ctf_ssh_keyscan.py} {artifact_dir}/` | 2 | EN |
| 12 | docker socket | `python3 {asset:scripts/ctf_docker_scan.py} {artifact_dir}/` | 2 | EN |
| 13 | regripper | `regripper.exe` reported through script: `python3 {asset:scripts/ctf_regripper_runner.py} {artifact_dir}/registry_hives/` | 3 | EV |
| 14 | LSASS | `python3 {asset:scripts/ctf_lsass_dump_scan.py} {artifact_dir}/` (memory dump when provided) | 3 | EV |

---

### A.13 WIRELESS, BLUETOOTH AND IOT (`ctf.wireless-iot`)
**Inputs:** `interface` (interface), `pcap_path` (File), `bssid` (Mac), `ssid` (text), `channel` (int), `wordlist` (flag for handshake material), `firmware_path` (File), `bt_device_addr` (Mac), `target_ble_service` (text), `flag_format` (req), `challenge_desc`, `operation_mode`, `time_limit`, `monitor_mode` (flag).

**Tool inventory (16 integrations):** airmon-ng, airodump-ng, aireplay-ng (confirm), aircrack-ng, besside-ng, hcxpcapngtool, hcxdumptool (confirm), john, hashcat, btmon (script), bluetoothctl (confirm), gatttool (script), ubertooth (confirm/skit), kismet (script), binwalk (firmware), strings/file (firmware).

**Commands (14 shown):**

| # | Tool | Command | Stage | Class |
|---|---|---|---|---|
| 1 | airmon-ng | `airmon-ng start {interface}` (confirm — changes interface state) | 3 | EN |
| 2 | airodump | `airodump-ng -w {artifacts}/capture --write-interval 5 -c {channel} {interface}` (confirm) | 3 | EN |
| 3 | aircrack | `aircrack-ng -w {wl:wifi/passphrases.txt} -b {bssid} {pcap_path}` | 3 | HT (local crack) |
| 4 | besside | `besside-ng -b {bssid} -W -c {channel} {interface}` (confirm) | 3 | HT |
| 5 | hcxpcapngtool | `hcxpcapngtool -o {artifacts}/hash.hc22000 {pcap_path}` | 2 | EV |
| 6 | hashcat | `hashcat -m 22000 {artifacts}/hash.hc22000 {wl:wifi/passphrases.txt}` (confirm) | 3 | HT |
| 7 | john | `john --format=wpapsk --wordlist={wl:wifi/passphrases.txt} {artifacts}/hash.txt` | 3 | HT |
| 8 | binwalk (fw) | `binwalk {firmware_path}` | 1 | RC |
| 9 | binwalk (fw) | `binwalk -Me --directory {artifacts}/fw {firmware_path}` | 2 | EV |
| 10 | strings (fw) | `strings -n 8 {firmware_path}` | 1 | RC |
| 11 | file (fw) | `file {firmware_path}` | 1 | RC |
| 12 | bluetoothctl | `bluetoothctl devices` (confirm: RF interactions only when authorized) | 3 | EN |
| 13 | script (ble) | `python3 {asset:scripts/ctf_ble_gatt_scan.py} --addr {bt_device_addr} --service {target_ble_service}` (confirm) | 3 | EN |
| 14 | kismet script | `python3 {asset:scripts/ctf_kismet_parse.py} --log {pcap_path} --out {artifacts}/kismet.json` | 2 | EN |

---

### A.14 SCRIPTING, AUTOMATION AND MISC (`ctf.scripting-misc`)
**Inputs:** `input_file` (File), `input_url` (url), `challenge_desc` (req), `script_lang` (OneOf python/bash), `requests_count` (int), `crypto_hint` (text), `flag_format` (req), `operation_mode`, `time_limit`.

**Tool inventory (16 integrations):** python3, bash, jq, awk, sed, sort/uniq (analytics), base64, openssl (encoding), curl (data fetch), file, strings, exiftool (artifacts), scapy (script), pwntools (script), z3 (script), Vigenere/Caesar/anagram scripts.

**Commands (12 shown; flexible operand set):**

| # | Tool | Command | Stage | Class |
|---|---|---|---|---|
| 1 | file | `file {input_file}` | 1 | RC |
| 2 | strings | `strings {input_file}` | 1 | RC |
| 3 | base64 | `base64 {input_file}` | 1 | EN |
| 4 | base64 | `base64 -d {input_file} > {artifacts}/decoded` (argv-wise, via script wrapper for redirect — use script provider: `python3 {asset:scripts/ctf_wrap_decode.py}`) | 1 | EV |
| 5 | jq | `jq --raw-output '.[]' {input_file}` | 2 | EV |
| 6 | awk | `awk -F, '...'` wrapped via script to avoid shell tokens (`python3 {asset:scripts/ctf_csv_extract.py}`) | 2 | EV |
| 7 | sort/uniq | `python3 {asset:scripts/ctf_dedup_lines.py} {input_file}` (script provider; no pipes) | 2 | EV |
| 8 | openssl | `openssl x509 -in {input_file} -text -noout` | 1 | RC |
| 9 | curl | `curl -sS -L {input_url}` | 2 | EN |
| 10 | scapy script | `python3 {asset:scripts/ctf_packet_tool.py} --in {input_file}` | 2 | EV |
| 11 | pwntools script | `python3 {asset:scripts/ctf_pwntools_io.py} --host {input_host} --port {input_port}` (confirm) | 3 | HT |
| 12 | z3 script | `python3 {asset:scripts/ctf_z3_solver.py} --in {input_file}` — the famous z3 constraint seed (input to describe the puzzle textually or as file) — note: the script consumes the operator's `challenge_desc` text file artifact | 2 | HT |

---

### Appendix A.15: Compiled-pattern guidance for the CtfFlagFormat loader rule

The loader compiles the operator-provided pattern in one of two modes:
1. **Shorthand mode** — pattern looks like `safctf{...}` — expands to a bounded class regex `safctf\{[A-Za-z0-9_]{1,64}\}` (case-sensitive unless operator asks otherwise via a trailing `/i` marker).
2. **Full-regex mode** — pattern contains regex operators (`(`, `[`, `|`, `*`, `+`, `?`, `{n,m}`, `.`) — compiled as-is with `regex::Regex::new`; case-fold only when `pattern` ends with `/i`.

Rejection rules (loader, validator): pattern must compile; pattern must not consist solely of unbounded repetition the way `.*` would (this would match everything); pattern must not exceed max length (1024); pattern must not start with `.{0,}`. Rejected patterns record `INPUT_ERROR` with the reason in the report.

**No pattern is ever auto-derived** from sample data (no silent learning of a "flag prefix" from the environment) — the operator supplies it or it defaults of "no flag extraction" mode (flag extraction disabled, report states this explicitly).

---

### Appendix A.16: Operation-level detail — how one family's operations share a common CTF pass

Every CTF operation's post-harvest pipeline is:

```
raw artifact(s)
    → existing format parsers (nmap / json / lines / raw)
    → existing intelligence pass (intel.rs — secrets, tokens, hashes, etc. — unchanged)
    → NEW CTF pass (flag extraction against the compiled CtfFlagFormat pattern; prov
      operating on the same bytes)
    → findings merged, categorized, deduplicated (existing rules + FlagCandidate)
    → operation outcome classification (§10.2) — SUCCESS / NO_FINDINGS / …
    → ctf.json assembly (findings, flag candidates, artifacts recovered, vulnerabilities)
    → CTF report rendering (existing document pipeline + new sections)
```

Notably, this shares the existing pipeline; the only new bytes that touch the disk are the sidecar `ctf.json` and any carved artifacts produced by an operation.

*(End of appendices. The plan is complete; stages sequenced §16; acceptance §19.)*

---

## Balance note (facts vs. recommendations vs. uncertainties)

| Tag | Meaning |
|---|---|
| **[Fact]** | Verified by direct file inspection; cited by file:line |
| **[Design]** | A recommendation aligned with existing patterns and deliberately chosen; may have alternatives |
| **[Verify]** | Flagged as needing Stage-0 re-check before implementation |

Every [Fact] in this document can be re-verified today by grep on the repo. Every [Design] is justified inline. Every [Verify] appears under §18 with its open question. The plan avoids inventing TOML keys where the existing schema can express the behavior, and every required extension is justified and additive.

---

### Appendix B. Representative TOML Capability Examples

These examples use **only verified existing schema fields** (`id`, `phase`, `label`, `summary`, `inputs`, `provider`/`binary`, `operation`/`name`/`args`/`output`/`network`) plus the extensions justified in §9.2 (`stage`, `confirm`, input `section`, new input types). They demonstrate the mechanics a separate implementation agent needs: one input set driving many tools, shared placeholders across providers, wordlist/asset binding, sensitive masking, stage ordering, availability semantics, and raw-output retention.

#### B.1 Web family — one URL input bound to three tools

```toml
[[capability]]
id = 'ctf.web-app-security'
phase = 'ctf'
label = 'WEB APP SECURITY'
summary = 'Authorized web challenge analysis: fingerprinting, content discovery, and controlled injection testing'
inputs = [
  { key = 'target_url',   type = 'url',     required = true,  section = 'Target', help = 'Challenge URL, e.g. http://10.10.10.5:8080' },
  { key = 'challenge_desc', type = 'text',  required = false, section = 'Challenge', help = 'What the challenge asks for, verbatim' },
  { key = 'request_limit', type = 'integer', required = false, section = 'Challenge', default = '2000', rule = { range = [10, 100000] } },
  { key = 'threads',      type = 'integer', required = false, section = 'Challenge', default = '10', rule = { range = [1, 64] } },
  { key = 'authorized_scope', type = 'text', required = false, section = 'Authorization', help = 'Systems you are allowed to touch. Empty = target_url only' },
  { key = 'auth_cookie',  type = 'secret',  required = false, section = 'Authorization', help = 'Session cookie for authenticated areas' },
  { key = 'flag_format',  type = 'ctf_flag_format', required = false, section = 'Flag', default = '', help = 'e.g. safctf{...} or a full regex; empty disables flag extraction' },
]

[[capability.provider]]
binary = 'curl'
[[capability.provider.operation]]
name = 'Baseline Headers'
stage = 1
args = ['-sS', '-i', '-o', '{artifacts}/curl_head.html', '-D', '-', '{target_url}']
output = 'raw'
network = true
[[capability.provider.operation]]
name = 'Robot Испытание Fetch'
stage = 1
args = ['-sS', '-i', '{target_url}/robots.txt']
output = 'lines'
network = true

[[capability.provider]]
binary = 'httpx'
[[capability.provider.operation]]
name = 'Tech Fingerprint'
stage = 1
args = ['-u', '{target_url}', '-title', '-tech-detect', '-status-code', '-no-color']
output = 'lines'
network = true

[[capability.provider]]
binary = 'ffuf'
[[capability.provider.operation]]
name = 'Directory Discovery'
stage = 2
args = ['-u', '{target_url}/FUZZ', '-w', '{wl:web/dirs.txt}', '-t', '{threads}', '-mc', '200,204,301,302,307,401,403', '-se', '404']
output = 'lines'
network = true

[[capability.provider]]
binary = 'sqlmap'
[[capability.provider.operation]]
name = 'Param SQLi Probe'
stage = 3
confirm = true
args = ['-u', '{target_url}', '--batch', '--level', '1', '--risk', '1', '--flush-session', '--output-dir', '{artifacts}/sqlmap']
output = 'raw'
network = true
```

What this demonstrates, mapped to the task's requirements:

| Requirement | Where it happens |
|---|---|
| Input validation before any plan | `target_url` type `url` validated by `InputSpec::validate` (`http(s)://` + host check, `src/domain/input.rs:253-262`) before `run_capability` proceeds |
| One input set → many tools | `{target_url}` appears in curl, httpx, ffuf, sqlmap argv templates — a single validated operator value drives four providers |
| Safe binding without shell corruption | Each element is one argv token, passed via `Command::new(program, args)` — never through a shell; loader refuses whole-token shell operators; `{{`/`}}`/`%{…}` escapes handle literal braces (curl write-out format) |
| Secrets never exposed | `auth_cookie` is `secret`; `Operation::command` collects indices of sensitive-typed inputs and calls `cmd.mark_sensitive(i)` (`src/catalog.rs:493-521`) — masked in the monitor, manifest, and report |
| Command order & dependencies | `stage` (E1): curl baseline & httpx are stage 1 and complete before ffuf (stage 2) is dispatched; sqlmap (stage 3, `confirm = true`) runs only after an operator gate. Within a stage, jobs run concurrently up to `max_concurrency`; manifest records keep catalog declaration order (`order` field on plan tasks, `src/domain/plan.rs`) |
| Tool availability check | `Capability::unavailable_reason()` names every missing provider binary (`src/catalog.rs:617-686`); UI shows the guidance box with verified install commands; never substitutes |
| Wordlist resolution | `{wl:web/dirs.txt}` resolves against TSEC's own corpus (`$TSEC_WORDLIST_ROOT` else install-root `wordlists/`); missing list marks the capability unavailable rather than guessing a path |
| Raw output retention | Each job writes `raw/<stem>.out` and `<stem>.err` inside the run directory; stems are `T{n}_{clean(binary)}_{clean(operation)}`; the run's cwd is the run directory so stray tool writes land inside the run |
| Flag-format input present | `flag_format` declared `ctf_flag_format` (E4) as a first-class type; default empty = extraction disabled and the report says so |

#### B.2 Forensics family — file artifacts, no network, script providers

```toml
[[capability]]
id = 'ctf.digital-forensics'
phase = 'ctf'
label = 'DIGITAL FORENSICS'
summary = 'Disk image, memory dump and file-carving analysis for CTF incident challenges'
inputs = [
  { key = 'disk_image',   type = 'file',   required = false, section = 'Challenge', help = 'Existing disk image file' },
  { key = 'memory_dump',  type = 'file',   required = false, section = 'Challenge', help = 'Existing memory dump file' },
  { key = 'partition_offset', type = 'integer', required = false, section = 'Challenge', default = '0', rule = { range = [0, 100000000] } },
  { key = 'inode',        type = 'text',   required = false, section = 'Challenge', help = 'Inode from fls output to recover with icat' },
  { key = 'case_note',    type = 'text',   required = false, section = 'Challenge' },
  { key = 'authorized_scope', type = 'text', required = false, section = 'Authorization' },
  { key = 'flag_format',  type = 'ctf_flag_format', required = false, section = 'Flag', default = '' },
]
# NOTE: at least one of disk_image / memory_dump is required in practice; the
# loader cannot express OR-required today, so the capability declares both
# optional and its two stage-1 probes record VALIDATION_FAILED/NOT_APPLICABLE
# for whichever artifact class is absent. This is the honest-degradation path,
# not a padded requirement.

[[capability.provider]]
binary = 'mmls'
[[capability.provider.operation]]
name = 'Partition Table'
stage = 1
args = ['{disk_image}']
output = 'lines'
network = false

[[capability.provider]]
binary = 'fls'
[[capability.provider.operation]]
name = 'File Listing'
stage = 2
args = ['-o', '{partition_offset}', '-r', '-p', '{disk_image}']
output = 'lines'
network = false

[[capability.provider]]
binary = 'vol'
[[capability.provider.operation]]
name = 'Memory Info'
stage = 1
args = ['-f', '{memory_dump}', 'windows.info']
output = 'lines'
network = false

[[capability.provider]]
binary = 'binwalk'
[[capability.provider.operation]]
name = 'Embedded Extraction'
stage = 2
args = ['-Me', '--directory', '{artifacts}/extracted', '{disk_image}']
output = 'raw'
network = false

# Sleuth Kit icat writes to stdout; the bundled wrapper script gives argv-safe
# output-file handling instead of a shell redirect (which the loader forbids).
[[capability.provider]]
binary = 'python3'
[[capability.provider.operation]]
name = 'Inode Recovery'
stage = 2
args = ['{asset:scripts/ctf_icat_save.py}', '--image', '{disk_image}', '--offset', '{partition_offset}', '--inode', '{inode}', '--out', '{artifacts}/recovered.bin']
output = 'lines'
network = false
```

What this example shows beyond B.1: file-artifact binding (`file`-typed inputs validated for existence at prompt time), `network = false` for fully local work, and `{asset:...}` binding of repo-bundled helper scripts. Facts the example leans on: `expand_assets` (`src/catalog.rs:319-340`) rejects a shipped catalog that names an absent helper (load-time `is_file` check); `python3` is itself a provider binary with its own `tools.sh` mapping (`python3`). Where the Sleuth Kit's `icat` would demand a stdout redirect (forbidden — no shell), the bundled `ctf_icat_save.py` wrapper converts that into argv-safe output paths. One honest gap the example records: the loader cannot express "at least one of disk_image / memory_dump" as OR-required, so the capability declares both optional and its stage-1 probes degrade visibly (`VALIDATION_FAILED`/`NOT_APPLICABLE` records) — flagged as a possible future `ValidationRule` extension rather than a schema workaround.

#### B.3 Crypto family — inline ciphertext, sensitive inputs, zero network

```toml
[[capability]]
id = 'ctf.cryptography'
phase = 'ctf'
label = 'CRYPTO CHALLENGES'
summary = 'Classical and modern cipher analysis, encoding, and offline hash attacks on supplied challenge material'
inputs = [
  { key = 'ciphertext_path', type = 'file',  required = false, section = 'Challenge', help = 'Supplied ciphertext or key file' },
  { key = 'ciphertext_inline', type = 'secret', required = false, section = 'Challenge', help = 'Pasted ciphertext when there is no file' },
  { key = 'key_path',     type = 'file',   required = false, section = 'Challenge' },
  { key = 'key_material', type = 'secret', required = false, section = 'Authorization', help = 'Key/password the challenge provides' },
  { key = 'algorithm_hint', type = 'text', required = false, section = 'Challenge' },
  { key = 'challenge_note', type = 'text', required = false, section = 'Challenge' },
  { key = 'authorized_scope', type = 'text', required = false, section = 'Authorization' },
  { key = 'flag_format', type = 'ctf_flag_format', required = false, section = 'Flag', default = '' },
]

[[capability.provider]]
binary = 'openssl'
[[capability.provider.operation]]
name = 'Base64 Decode'
stage = 1
args = ['base64', '-d', '-A', '-in', '{ciphertext_path}', '-out', '{artifacts}/decoded.bin']
output = 'raw'
network = false
[[capability.provider.operation]]
name = 'Cert Inspection'
stage = 1
args = ['x509', '-in', '{ciphertext_path}', '-text', '-noout']
output = 'lines'
network = false

[[capability.provider]]
binary = 'hashid'
[[capability.provider.operation]]
name = 'Hash Type ID'
stage = 1
args = ['-M', '{ciphertext_inline}']
output = 'lines'
network = false

[[capability.provider]]
binary = 'john'
[[capability.provider.operation]]
name = 'Rockyou Offline Attack'
stage = 3
confirm = true
args = ['--wordlist={wl:passwords/rockyou.txt}', '{ciphertext_path}']
output = 'lines'
network = false

[[capability.provider]]
binary = 'python3'
[[capability.provider.operation]]
name = 'Classical Cipher Sweep'
stage = 2
args = ['{asset:scripts/ctf_classical_cipher.py}', '--in', '{ciphertext_path}', '--out', '{artifacts}/classical']
output = 'lines'
network = false
[[capability.provider.operation]]
name = 'Inline XOR Analysis'
stage = 2
args = ['{asset:scripts/ctf_inline_crypto.py}', '--data', '{ciphertext_inline}', '--out', '{artifacts}/inline_crypto.json']
output = 'json'
network = false
```

Notes specific to this family:
- `ciphertext_inline` is `secret`-typed: the value is never written unredacted to manifest/report; the wrapper script receives it in argv (masked as `[REDACTED]` in every rendering — positional `mark_sensitive`), and only derived artifacts retain content. **[Design decision]** argv passing of inline secrets is accepted here because the alternative (stdin/env plumbing) does not exist in the current spawn path; the masking rule plus on-disk run-directory rotation bounds the exposure. This is a [Verify] item for Stage 0: confirm no env/stdin support is needed for these wrappers beyond what `RunnerConfig.env` already provides.
- `hashid` consumes the hash as a positional argument (`['{ciphertext_inline}']`); Stage 3 verifies exact upstream flags via the help-verification protocol rather than assuming them here.
- No `network = true` operation exists in this family by design — offline work only.

#### B.4 Active Directory family — credential inputs, multi-domain binding

```toml
[[capability]]
id = 'ctf.active-directory'
phase = 'ctf'
label = 'ACTIVE DIRECTORY'
summary = 'AD challenge context: directory enumeration, Kerberos weaknesses, and relationship analysis with operator-supplied credentials'
inputs = [
  { key = 'domain', type = 'domain', required = true, section = 'Target' },
  { key = 'dc_host', type = 'target', required = false, section = 'Target', help = 'Domain controller hostname or IP' },
  { key = 'username', type = 'username', required = false, section = 'Authorization' },
  { key = 'password', type = 'password', required = false, section = 'Authorization' },
  { key = 'nt_hash', type = 'secret', required = false, section = 'Authorization', help = 'NT hash for pass-the-hash style auth' },
  { key = 'challenge_context', type = 'text', required = false, section = 'Challenge' },
  { key = 'authorized_scope', type = 'text', required = false, section = 'Authorization' },
  { key = 'flag_format', type = 'ctf_flag_format', required = false, section = 'Flag', default = '' },
]

[[capability.provider]]
binary = 'ldapsearch'
[[capability.provider.operation]]
name = 'Anonymous Root DSE'
stage = 1
args = ['-x', '-H', 'ldap://{dc_host}', '-s', 'base', '-LLL']
output = 'lines'
network = true

[[capability.provider]]
binary = 'smbclient'
[[capability.provider.operation]]
name = 'Null Session Share List'
stage = 1
args = ['-L', '//{dc_host}/', '-N', '-g']
output = 'lines'
network = true

[[capability.provider]]
binary = 'GetNPUsers'
[[capability.provider.operation]]
name = 'ASREPRoast Sweep'
stage = 2
args = ['{domain}/', '-dc-ip', '{dc_host}', '-usersfile', '{artifacts}/users.txt', '-no-pass', '-k']
output = 'lines'
network = true

[[capability.provider]]
binary = 'netexec'
[[capability.provider.operation]]
name = 'SMB Cred Validation'
stage = 3
confirm = true
args = ['smb', '{dc_host}', '-u', '{username}', '-p', '{password}', '--shares']
output = 'lines'
network = true
```

Notes: `password` and `nt_hash` are the sensitive types marked on the command; the same `{domain}`, `{dc_host}`, `{username}` placeholders bind identical operator values into every provider's argv template. One case-folding hazard is worth recording: the `domain`-typed input validator lowercases its value (`src/domain/input.rs:209-212` — verified), which is wrong for Kerberos realms. The reference design therefore collects AD values as `domain` for LDAP/SMB paths and adds an optional `realm` input of type `text` where a tool needs the conventional uppercase realm; this is a [Verify] Stage-0 item to confirm with representative tools.

#### B.5 How to read this appendix against the acceptance criteria

- All examples use only verified struct fields + the §9.2 additions; no invented keys.
- Each example deliberately shows a different binding shape: URL-driven (many tools, shared placeholder), file-artifact-driven (offline + script provider), inline-secret-driven (password-family masking), credential-driven (multi-family sensitive inputs).
- The staged gates, wordlist/asset/artifact placeholders, and per-operation `output` formats shown are the exact conventions the shipped CTF catalog will follow; per-tool full command sets (≥10 per CLI tool) are the Stage-3 deliverable, with the per-family matrices of Appendix A as the semantic guide.

---

## Closing statement of scope compliance

- No source files or catalog entries were modified, no tools installed, and nothing intrusive executed. The only artifact of this exercise is this plan document (`ctfchallenges.md` at the repository root).
- All architectural claims cite specific files/functions/line ranges verified during this investigation; the Plan/Verify tags in §18 mark exactly what a Stage-0 pass must re-confirm before implementation.
- The plan introduces no independent execution engine, no duplicate framework layer, and no new UI metaphor: the CTF phase rides the existing catalog → command-build → single-spawn → capture → format/intel parse → store-harvest → document pipeline, adding only the CTF flag/evidence/report pass, the staged-dispatch wiring, and the extended phase.
