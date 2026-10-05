# TSEC wordlists

Every wordlist the framework can reach, in one place. The operator supplies a
target and a few operation-specific values; they never supply a path to a
wordlist. Cloning this repository gives you every list below marked **ship**,
so a fresh install runs end to end with no downloads.

Copyright (c) funbinet. All rights reserved.
Part of TSEC terminal cybersecurity operations platform by funbinet.

---

## Why these live in the repository

A tool that takes `-w some.txt` is only as portable as `some.txt`. When the
path is left to the operator, a run fails on someone else's machine because the
path was `/usr/share/seclists/...` and they do not have SecLists installed, or
because the file existed only on the box where the wordlist was downloaded.

So the catalog never names a system wordlist directory. It names a path inside
this one:

```toml
args = ['-w', '{wl:ssh/passwords.txt}', '{rhost}']
```

At run time that resolves to an absolute path inside `wordlists/`, which the
loader derives from the location of the installed framework. Nothing is
requested from the operator and nothing is assumed about the host.

### Resolution order

1. `$TSEC_WORDLIST_ROOT/<path>`, when that variable is set. Use this for a
   relocated or shared corpus.
2. `<install root>/wordlists/<path>`, where the install root is the directory
   containing `catalog/`, `config/` and this `wordlists/`.

If the resolved file is missing, the capability says so by name rather than
letting the tool fail with a bare "no such file". See
[Missing wordlists](#missing-wordlists).

---

## One list per attack, not one list for everything

`rockyou.txt` is not an answer to every question. It is the right corpus for
offline hash cracking and a poor one for an SSH password spray, an SMB spray, a
web login form or a WPA handshake. Each service therefore has its own directory,
built from the parts of the corpus that actually apply to it:

| Directory | What it is for | Typical entries |
|---|---|---|
| `passwords/` | Offline hash cracking: NTLM, Kerberos, NetNTLM, JWT, archives, PMKID, `/etc/shadow` | `rockyou.txt` (14.3M), `top-1m.txt` (1M), `top-100k.txt`, `common-10k.txt`, `rockyou-75.txt` |
| `users/` | General account-name enumeration where no service applies | `top-1m.txt` (xato, 10M), `names.txt`, `defaults.txt` |
| `ssh/` | `hydra -X ssh`, key passphrase attacks | `users.txt` (841), `passwords.txt` (64k), `passphrases.txt` |
| `smb/` | `nxc`, `hydra -X smb`, Windows authentication | `users.txt`, `passwords.txt` |
| `ftp/` | FTP login attacks | `users.txt`, `passwords.txt` |
| `mail/` | SMTP, IMAP and POP login attacks | `users.txt`, `passwords.txt` |
| `db/` | `mysql`, `psql`, `mongosh`, `redis-cli` and similar authentication | `users.txt` (vendor defaults), `passwords.txt` |
| `ad/` | Active Directory: AS-REP roast, Kerberoast, LDAP enumeration | `users.txt`, `privileged.txt`, `passwords.txt`, `attributes.txt` |
| `web/` | Content, directory and parameter discovery, path fuzzing | `common.txt`, `big.txt`, `raft-medium.txt`, `api-endpoints.txt`, `burp-parameter-names.txt`, `logins.txt`, `wp-plugins.txt`, `cms-backups.txt`, `spring-boot.txt` |
| `dns/` | Subdomain brute force, zone transfer work, virtual host discovery | `subdomains-5000.txt`, `subdomains-20000.txt`, `deepmagic-50000.txt`, `hostnames.txt`, `tlds.txt`, `services.txt` |
| `fuzz/` | `ffuf`, `wfuzz` and friends: LFI, SSRF, SSTI, XSS, XXE, SSI, format string, IDOR, LDAP injection | `lfi.txt`, `ssrf.txt`, `ssti.txt`, `xss.txt`, `xxe.txt`, `ids.txt`, `injections.txt`, ... |
| `wifi/` | WPA handshake, PMKID, evil twin and rogue AP work | `psk-defaults.txt`, `passphrases.txt`, `wpa-pairs.txt`, `ssid-names.txt`, `psk-8-digit.txt` |
| `network/` | Port and protocol lists for sweeps and pin ranges | `ports-top-100.txt`, `ports-all.txt`, `protocols.txt` |
| `osint/` | Naming conventions for public cloud object stores | `buckets.txt` |
| `rules/` | `hashcat` mutation rule files | `best66.rule`, `dive.rule`, `rockyou-30000.rule` |

---

## Getting the large lists

Four lists are too large for a git repository. GitHub and Codeberg both refuse
blobs over 100 MB, and `rockyou.txt` alone is 140 MB, so it is not in the
history. Fetch it once:

```bash
./fetch-wordlists.sh
```

| List | Size | Pinned SHA-256 |
|---|---|---|
| `passwords/rockyou.txt` | 140 MB | `6dfa76aa…c1076` |
| `users/top-1m.txt` | 85 MB | `19b5af05…b1da5` |
| `passwords/openwall.txt` | 41 MB | `0d54baab…8f725` |
| `web/dirbuster-big.txt` | 15 MB | `236f19b1…61b34` |

The fetcher is idempotent, verifies each digest before accepting the file, and
writes through a `.part` temporary so an interrupted run cannot leave a
truncated list that later looks valid. Check without downloading:

```bash
./fetch-wordlists.sh --check
```

Every list that is missing is reported by name, so a gap is always visible
rather than discovered mid-attack.

## Verifying the corpus

```bash
./verify-wordlists.sh
```

Confirms every declared list is present and non-empty and that each shipped copy
matches `MANIFEST.sha256`. Exits non-zero on a missing or corrupt file, so a
partial clone cannot pass unnoticed in CI.

---

## Provenance

`MANIFEST.tsv` is the source of truth: one row per list with its tier, pinned
digest where applicable, upstream URL and a note saying what it is for. Most
lists come from [SecLists](https://github.com/danielmiessler/SecLists) and the
mutation rules from [hashcat](https://github.com/hashcat/hashcat); the rest are
curated here and marked `derived` or `curated` in the note, with the derivation
spelled out.

```
MANIFEST.tsv      path, tier, digest, upstream URL, purpose
MANIFEST.sha256   digests of the committed lists, checked by verify-wordlists.sh
```

Both are plain tab-separated files, so adding a list is a one-line edit:

```
wordlists/web/example.txt	ship	-	https://example.org/example.txt	What it is for
```

Then regenerate the digests:

```bash
cd wordlists && find . -type f \( -name '*.txt' -o -name '*.rule' \) \
  -not -name 'MANIFEST*' | sed 's|^\./||' | sort \
  | xargs sha256sum > MANIFEST.sha256
```

---

## Missing wordlists

A capability that needs a list which is not on disk is reported as unavailable,
by name, in `tsec --status` and in the capability menu, alongside a missing tool
binary. It is never silently skipped and never silently pointed at some other
list, because substituting `rockyou.txt` for a missing SSH corpus produces a
run that looks successful and finds nothing.

The rest of the capability still runs. Only the operations that actually need
the absent list are withheld.

---

## Licence

The upstream corpora keep their own licences. SecLists is MIT licensed; the
`rockyou.txt` dump originates from a leaked database and is redistributed by
several projects under their own terms. Review an upstream project's licence
before redistributing this directory as part of something else.
