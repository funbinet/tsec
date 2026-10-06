#!/usr/bin/env bash
# ==============================================================================
# TSEC 3.0 Tool Dependency Resolver & Installer
# Copyright (c) funbinet. All rights reserved.
# Part of TSEC terminal cybersecurity operations platform by funbinet.
#
# The tool list for each phase is read straight from catalog/capabilities.toml
# (the same catalog the TUI executes), so this script can never drift from
# what the framework actually runs.
#
# Wordlists are not handled here: they ship with the framework under
# wordlists/, and the catalog resolves them itself. Run
# wordlists/fetch-wordlists.sh for the four too large to commit, or
# wordlists/verify-wordlists.sh to check the corpus.
#
# Usage:
#   ./tools.sh -recon            # resolve & install tools for RECONNAISSANCE
#   ./tools.sh -surface          # ... ATTACK SURFACE
#   ./tools.sh -vulnerability    # ... VULNERABILITY
#   ./tools.sh -payload          # ... PAYLOAD
#   ./tools.sh -escalation       # ... PRIVILEGE ESCALATION
#   ./tools.sh -credentials      # ... CREDENTIALS
#   ./tools.sh -lateral          # ... LATERAL MOVEMENT
#   ./tools.sh -persistence      # ... PERSISTENCE & DEFENSE EVASION
#   ./tools.sh -exploitation     # ... EXPLOITATION
#   ./tools.sh -wireless         # ... WIRELESS
#   ./tools.sh -all              # every phase
#   ./tools.sh -recon -c         # check only; never install
# ==============================================================================

set -euo pipefail

BOLD="\033[1m"
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
CYAN="\033[0;36m"
RESET="\033[0m"

export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$HOME/go/bin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin:$PATH"

CATALOG="catalog/capabilities.toml"
CHECK_ONLY=false

# Distro detection drives the install command and the guidance shown. The
# framework itself (src/install.rs) drives the same six managers; keeping the two
# in step means `./tools.sh` and a capability run never disagree about what this
# host is.
IS_ARCH=false
IS_DEBIAN=false
IS_FEDORA=false
IS_ALPINE=false
IS_SUSE=false
DISTRO_NAME=""
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO_NAME="${PRETTY_NAME:-${NAME:-unknown}}"
    case "${ID:-}:${ID_LIKE:-}" in
        *arch*|*manjaro*|*omarchy*) IS_ARCH=true ;;
        *kali*|*debian*|*ubuntu*|*mint*|*pop*) IS_DEBIAN=true ;;
        *fedora*|*rhel*|*centos*|*rocky*|*alma*) IS_FEDORA=true ;;
        *alpine*) IS_ALPINE=true ;;
        *suse*|*opensuse*) IS_SUSE=true ;;
    esac
fi

# An AUR helper, preferring paru. Both names are checked because a host may have
# either, and a fresh Arch install has neither.
aur_helper() {
    for h in paru yay; do
        command -v "$h" >/dev/null 2>&1 && { echo "$h"; return 0; }
    done
    echo ""
}

# The manager this host uses, or empty when it has none of the six.
pkg_manager() {
    if [ "$IS_ARCH" = true ]; then echo pacman
    elif [ "$IS_DEBIAN" = true ]; then echo apt
    elif [ "$IS_FEDORA" = true ]; then
        command -v dnf >/dev/null 2>&1 && { echo dnf; return 0; }
        echo yum
    elif [ "$IS_ALPINE" = true ]; then echo apk
    elif [ "$IS_SUSE" = true ]; then echo zypper
    else echo ""
    fi
}

check_tool() {
    local bin="$1"
    command -v "$bin" >/dev/null 2>&1 && return 0
    for p in "$HOME/.cargo/bin/$bin" "$HOME/.local/bin/$bin" "$HOME/go/bin/$bin" \
             "/usr/local/bin/$bin" "/usr/bin/$bin" "/sbin/$bin" "/usr/sbin/$bin"; do
        [ -x "$p" ] && return 0
    done
    return 1
}

# ---------------------------------------------------------------------------
# Tool -> package mapping: "tool|arch package|kali package".
# Anything not listed falls back to a same-name package guess plus a
# yay/apt search command, so every tool always gets usable guidance.
# ---------------------------------------------------------------------------
pkg_info() {
    local tool="$1"
    case "$tool" in
        # 7
        7z) echo "p7zip|p7zip-full" ;;
        # a
        airbase-ng|aircrack-ng|airdecap-ng|aireplay-ng|airmon-ng|airodump-ng) echo "aircrack-ng|aircrack-ng" ;;
        amap) echo "nmap|nmap" ;;
        amass) echo "amass|amass" ;;
        anew) echo "tomnomnom|tomnomnom" ;;
        arjun) echo "arjun|arjun" ;;
        arp) echo "iproute2|iproute2" ;;
        arp-scan) echo "arp-scan|arp-scan" ;;
        arping) echo "iputils|arping" ;;
        arpspoof) echo "arpspoof|arpspoof" ;;
        asleap) echo "wpa-supplicant|wpasupplicant" ;;
        asnmap) echo "asnmap|asnmap" ;;
        assetfinder) echo "assetfinder|assetfinder" ;;
        at) echo "at|at" ;;
        atq) echo "at|at" ;;
        awk) echo "gawk|gawk" ;;
        aws) echo "aws-cli|awscli" ;;
        # b
        b2sum|base64) echo "coreutils|coreutils" ;;
        bash) echo "bash|bash" ;;
        besside-ng) echo "aircrack-ng|aircrack-ng" ;;
        bluetoothctl|btmon) echo "bluez-utils|bluez" ;;
        bettercap) echo "bettercap|bettercap" ;;
        blackbird) echo "blackbird|blackbird" ;;
        binwalk) echo "binwalk|binwalk" ;;
        bully) echo "bully|bully" ;;
        # c
        capsh) echo "libcap|libcap2-bin" ;;
        cargo-audit) echo "cargo-audit|cargo-audit" ;;
        capinfos) echo "wireshark-cli|wireshark-cli" ;;
        cat|chmod|comm|cp|cut|sha1sum|size|sort|type) echo "coreutils|coreutils" ;;
        cdncheck) echo "cdncheck|cdncheck" ;;
        certipy) echo "certipy-ad|certipy-ad" ;;
        certutil) echo "adfind|adfind" ;;
        cewl) echo "cewl|cewl" ;;
        checksec) echo "checksec|checksec" ;;
        chisel) echo "chisel|chisel" ;;
        chkconfig) echo "chkconfig|init-system-helpers" ;;
        chpasswd) echo "shadow|passwd" ;;
        clamscan) echo "clamav|clamav" ;;
        cloud_enum) echo "cloud-enum|cloud-enum" ;;
        cloudbrute) echo "cloudbrute|cloudbrute" ;;
        cmseek) echo "cmseek|cmseek" ;;
        coercer) echo "impacket|python3-impacket" ;;
        collaborator-free) echo "interactsh-client|interactsh-client" ;;
        commix) echo "commix|commix" ;;
        crackmapexec) echo "netexec|netexec" ;;
        crontab) echo "cronie|cron" ;;
        crowbar) echo "crowbar|crowbar" ;;
        crunch) echo "crunch|crunch" ;;
        ctfr) echo "ctfr-git|ctfr" ;;
        curl) echo "curl|curl" ;;
        # d
        dalfox) echo "dalfox|dalfox" ;;
        detect-secrets) echo "detect-secrets|detect-secrets" ;;
        dig) echo "bind|dnsutils" ;;
        dirb) echo "dirb|dirb" ;;
        dirsearch) echo "dirsearch|dirsearch" ;;
        dnscat2) echo "dnscat2|dnscat2" ;;
        dnsenum) echo "dnsenum|dnsenum" ;;
        dnsmasq|dnsspoof) echo "dnsmasq|dnsmasq-base" ;;
        dnsrecon) echo "dnsrecon|dnsrecon" ;;
        dnsx) echo "dnsx|dnsx" ;;
        donut) echo "donut|donut" ;;
        dpkg) echo "dpkg|dpkg" ;;
        driftnet) echo "driftnet|driftnet" ;;
        droopescan) echo "droopescan|droopescan" ;;
        dsniff) echo "dsniff|dsniff" ;;
        du) echo "coreutils|coreutils" ;;
        # e
        eaphammer) echo "eaphammer|eaphammer" ;;
        echo|env) echo "coreutils|coreutils" ;;
        editcap) echo "wireshark-common|wireshark-common" ;;
        enum4linux-ng) echo "enum4linux-ng|enum4linux-ng" ;;
        enumerate-iam) echo "enumerate-iam|enumerate-iam" ;;
        ettercap) echo "ettercap|ettercap" ;;
        evil-winrm) echo "evil-winrm|evil-winrm" ;;
        exiftool) echo "perl-image-exiftool|libimage-exiftool-perl" ;;
        exiv2) echo "exiv2|exiv2" ;;
        # f
        fcrackzip) echo "fcrackzip|fcrackzip" ;;
        feroxbuster) echo "feroxbuster|feroxbuster" ;;
        ferret) echo "ferret|ferret" ;;
        ffuf) echo "ffuf|ffuf" ;;
        fierce) echo "fierce|fierce" ;;
        file) echo "file|file" ;;
        find) echo "findutils|findutils" ;;
        findomain) echo "findomain|findomain" ;;
        fping) echo "fping|fping" ;;
        freeradius-wpe) echo "freeradius-wpe|freeradius-wpe" ;;
        fuzzdb) echo "fuzzdb|fuzzdb" ;;
        # g
        garble) echo "garble|garble" ;;
        gau) echo "gau|gau" ;;
        gf) echo "gf|gf" ;;
        go-audit) echo "go-audit|go-audit" ;;
        gsutil) echo "google-cloud-cli|google-cloud-sdk" ;;
        gcc) echo "gcc|gcc" ;;
        geoiplookup) echo "geoip-bin|geoip-bin" ;;
        getcap|getpcaps) echo "libcap|libcap2-bin" ;;
        getent) echo "glibc|libc-bin" ;;
        ghauri) echo "ghauri|ghauri" ;;
        gitleaks) echo "gitleaks|gitleaks" ;;
        go) echo "go|golang" ;;
        gobuster) echo "gobuster|gobuster" ;;
        gospider) echo "gospider|gospider" ;;
        gowitness) echo "gowitness|gowitness" ;;
        gpg) echo "gnupg|gnupg" ;;
        gpsd) echo "gpsd|gpsd" ;;
        gpxlogger) echo "gpxlogger|gpxlogger" ;;
        grep) echo "grep|grep" ;;
        grype) echo "grype|grype" ;;
        hping3) echo "hping|hping3" ;;
        gatttool) echo "bluez|bluez" ;;
        # h
        hakrawler) echo "hakrawler|hakrawler" ;;
        hamster) echo "hamster|hamster" ;;
        hash-identifier) echo "hash-identifier|hash-identifier" ;;
        hashcat) echo "hashcat|hashcat" ;;
        hashid) echo "hashid|hashid" ;;
        havoc) echo "havoc|havoc" ;;
        hcxdumptool|hcxhashtool|hcxpcapngtool|hcxtools) echo "hcxtools|hcxtools" ;;
        head) echo "coreutils|coreutils" ;;
        horst) echo "horst|horst" ;;
        host) echo "bind|dnsutils" ;;
        gzip) echo "gzip|gzip" ;;
        hciconfig|hcitool) echo "bluez|bluez" ;;
        hostapd) echo "hostapd|hostapd" ;;
        hostapd-mana) echo "hostapd-mana|hostapd" ;;
        hostapd-wpe) echo "hostapd-wpe|hostapd" ;;
        hping3) echo "hping|hping3" ;;
        httpx-pd) echo "-|-" ;;
        hydra) echo "hydra|hydra" ;;
        # i
        id) echo "coreutils|coreutils" ;;
        ike-scan) echo "ikecraft|ikecraft-sniffer" ;;
        impacket-GetNPUsers|impacket-atexec|impacket-dcomexec|impacket-dementor|impacket-findDelegation|impacket-getArch|impacket-getST|impacket-getTGT|impacket-getUserSPNs|impacket-lookupsid|impacket-mssqlclient|impacket-net|impacket-ntlmrelayx|impacket-printbugger|impacket-psexec|impacket-reg|impacket-secretsdump|impacket-smbclient|impacket-smbexec|impacket-wmiexec) echo "impacket|python3-impacket" ;;
        inveigh) echo "inveigh|inveigh" ;;
        iodined) echo "iodine|iodine" ;;
        ip) echo "iproute2|iproute2" ;;
        iptables) echo "iptables|iptables" ;;
        iw) echo "iw|iw" ;;
        iwconfig|iwlist) echo "wireless_tools|wireless-tools" ;;
        # j
        java) echo "jre-openjdk-headless|default-jre-headless" ;;
        john) echo "john|john" ;;
        joomscan) echo "joomscan|joomscan" ;;
        journalctl) echo "systemd|systemd" ;;
        impacket-addcomputer|impacket-describeTicket|impacket-getUsers|impacket-services|impacket-smbserver|impacket-atexec|impacket-dcomexec|impacket-dementor|impacket-findDelegation|impacket-getArch|impacket-getST|impacket-getTGT|impacket-getUserSPNs|impacket-lookupsid|impacket-mssqlclient|impacket-net|impacket-ntlmrelayx|impacket-printbugger|impacket-psexec|impacket-reg|impacket-secretsdump|impacket-smbclient|impacket-smbexec|impacket-wmiexec|impacket-GetNPUsers) echo "impacket|python3-impacket" ;;
        interactsh-client) echo "interactsh-client|interactsh-client" ;;
        jq) echo "jq|jq" ;;
        jwt_tool) echo "jwt_tool|jwt_tool" ;;
        # k
        katana) echo "katana|katana" ;;
        keytool) echo "jre-openjdk-headless|default-jre-headless" ;;
        kismet) echo "kismet|kismet" ;;
        kiterunner) echo "kiterunner|kiterunner" ;;
        klist) echo "krb5-client|krb5-user" ;;
        kubectl) echo "kubectl|kubectl" ;;
        kubelet) echo "kubernetes-client|kubelet" ;;
        kwprocessor) echo "hashcat|hashcat" ;;
        # l
        ldapsearch) echo "openldap|ldap-utils" ;;
        ligolo-ng|ligolo-proxy) echo "ligolo-ng|ligolo-ng" ;;
        ldd) echo "glibc|libc-bin" ;;
        linkfinder) echo "linkfinder|linkfinder" ;;
        ls) echo "coreutils|coreutils" ;;
        ltrace) echo "ltrace|ltrace" ;;
        macchanger) echo "macchanger|macchanger" ;;
        md5sum) echo "coreutils|coreutils" ;;
        kalibrate-rtl) echo "kalibrate-rtl|kalibrate-rtl" ;;
        lynis) echo "lynis|lynis" ;;
        # m
        maigret) echo "maigret|maigret" ;;
        mapcidr) echo "mapcidr|mapcidr" ;;
        maskprocessor) echo "hashcat|hashcat" ;;
        masscan) echo "masscan|masscan" ;;
        mat2) echo "mat2|mat2" ;;
        md5sum|mkdir) echo "coreutils|coreutils" ;;
        mdk4) echo "mdk4|mdk4" ;;
        mediainfo) echo "mediainfo|mediainfo" ;;
        medusa) echo "medusa|medusa" ;;
        mergecap) echo "wireshark-common|wireshark-common" ;;
        mitm6) echo "impacket|python3-impacket" ;;
        mongo) echo "mongodb|mongodb-clients" ;;
        mongosh) echo "mongodb|mongodb-mongosh" ;;
        mosquitto_sub) echo "mosquitto|mosquitto-clients" ;;
        mount) echo "util-linux|util-linux" ;;
        mpack) echo "mpack|mpack" ;;
        msfconsole|msfvenom) echo "metasploit|metasploit-framework" ;;
        mysql) echo "mariadb-libs|mariadb-client" ;;
        # n
        naabu) echo "naabu|naabu" ;;
        name-that-hash) echo "name-that-hash|name-that-hash" ;;
        nbtscan) echo "nbtscan|nbtscan" ;;
        npm) echo "npm|npm" ;;
        nc) echo "netcat-openbsd|netcat-openbsd" ;;
        ncat) echo "nmap|ncat" ;;
        ncrack) echo "ncrack|ncrack" ;;
        one-sixtyone) echo "onesixtyone|onesixtyone" ;;
        netdiscover) echo "netdiscover|netdiscover" ;;
        networkminer) echo "networkminer|networkminer" ;;
        nikto) echo "nikto|nikto" ;;
        nm|nmcli) echo "networkmanager|network-manager" ;;
        nmap|nping) echo "nmap|nmap" ;;
        npm-audit) echo "npm|npm" ;;
        nslookup) echo "bind|dnsutils" ;;
        nuclei) echo "nuclei|nuclei" ;;
        nxc) echo "netexec|netexec" ;;
        # o
        objcopy|objdump) echo "binutils|binutils" ;;
        oledump.py|olevba) echo "oletools|python3-oletools" ;;
        onesixtyone) echo "onesixtyone|onesixtyone" ;;
        openssl) echo "openssl|openssl" ;;
        openvpn) echo "openvpn|openvpn" ;;
        osv-scanner) echo "osv-scanner|osv-scanner" ;;
        # p
        p0f) echo "p0f|p0f" ;;
        packetspammer) echo "packetspammer|packetspammer" ;;
        paramspider) echo "paramspider|paramspider" ;;
        pcapfix) echo "pcapfix|pcapfix" ;;
        pdfinfo) echo "poppler|poppler-utils" ;;
        php) echo "php|php" ;;
        phpggc) echo "phpggc|phpggc" ;;
        ping) echo "iputils|iputils-ping" ;;
        pip-audit) echo "python-pip-audit|python3-pip-audit" ;;
        pixiewps) echo "pixiewps|pixiewps" ;;
        plink) echo "putty|putty-tools" ;;
        pmapper) echo "pmapper|pmapper" ;;
        printenv) echo "coreutils|coreutils" ;;
        prowler) echo "prowler|prowler" ;;
        proxychains4) echo "proxychains-ng|proxychains4" ;;
        ps) echo "procps-ng|procps" ;;
        psql) echo "postgresql-libs|postgresql-client" ;;
        puredns) echo "puredns|puredns" ;;
        pwgen) echo "pwgen|pwgen" ;;
        pwncat-cs) echo "pwncat|pwncat" ;;
        pyarmor) echo "pyarmor|pyarmor" ;;
        pyinstaller) echo "pyinstaller|pyinstaller" ;;
        pyrit) echo "pyrit|pyrit" ;;
        python3) echo "python|python3" ;;
        # r
        rabin2) echo "radare2|radare2" ;;
        r2) echo "radare2|radare2" ;;
        radamsa) echo "radamsa|radamsa" ;;
        rar2john) echo "john|john" ;;
        readelf) echo "binutils|binutils" ;;
        reaver) echo "reaver|reaver" ;;
        redis-cli) echo "redis|redis-tools" ;;
        responder) echo "responder|responder" ;;
        rfkill) echo "util-linux|rfkill" ;;
        rg|ripgrep) echo "ripgrep|ripgrep" ;;
        rm) echo "coreutils|coreutils" ;;
        rpcclient) echo "samba-common-bin|samba-common-bin" ;;
        rpcdump|rpcinfo) echo "rpcbind|rpcbind" ;;
        rpm) echo "rpm|rpm" ;;
        rustscan) echo "rustscan|rustscan" ;;
        # s
        crtndstry) echo "crtndstry|crtndstry" ;;
        s3scanner) echo "s3scanner|s3scanner" ;;
        scapy) echo "scapy|scapy" ;;
        scp) echo "openssh|openssh-client" ;;
        shuffledns) echo "shuffledns|shuffledns" ;;
        sqlite3) echo "sqlite|sqlite3" ;;
        strip) echo "binutils|binutils" ;;
        sublist3r) echo "sublist3r|sublist3r" ;;
        scoutsuite) echo "scoutsuite|scoutsuite" ;;
        searchsploit) echo "exploitdb|exploitdb" ;;
        sed) echo "sed|sed" ;;
        semgrep) echo "semgrep|semgrep" ;;
        sendemail) echo "sendemail|sendemail" ;;
        setcap) echo "libcap|libcap2-bin" ;;
        sha256sum|sort|stat) echo "coreutils|coreutils" ;;
        shc) echo "shc|shc" ;;
        sherlock) echo "sherlock|sherlock" ;;
        showmount) echo "nfs-utils|nfs-common" ;;
        sliver) echo "sliver|sliver" ;;
        smbclient) echo "smbclient|smbclient" ;;
        smbmap) echo "smbmap|smbmap" ;;
        snmpwalk) echo "net-snmp|snmp" ;;
        socat) echo "socat|socat" ;;
        sdptool) echo "bluez|bluez" ;;
        socialscan) echo "socialscan|socialscan" ;;
        sqlmap) echo "sqlmap|sqlmap" ;;
        sqsh) echo "freetds|freetds-bin" ;;
        ss) echo "iproute2|iproute2" ;;
        ssdeep) echo "ssdeep|ssdeep" ;;
        ssh|ssh-keygen|ssh-keyscan) echo "openssh|openssh-client" ;;
        ssh-audit) echo "ssh-audit|ssh-audit" ;;
        ssh2john) echo "john|john" ;;
        sshuttle) echo "sshuttle|sshuttle" ;;
        sslscan) echo "sslscan|sslscan" ;;
        sslyze) echo "sslyze|sslyze" ;;
        strace) echo "strace|strace" ;;
        strings) echo "binutils|binutils" ;;
        subfinder) echo "subfinder|subfinder" ;;
        subjs) echo "subjs|subjs" ;;
        subzy) echo "subzy|subzy" ;;
        sudo) echo "sudo|sudo" ;;
        swaks) echo "swaks|swaks" ;;
        syft) echo "syft|syft" ;;
        sysctl) echo "procps-ng|procps" ;;
        systemctl|systemd-run) echo "systemd|systemd" ;;
        # t
        tail) echo "coreutils|coreutils" ;;
        tshark) echo "wireshark-cli|wireshark-cli" ;;
        tcpdump) echo "tcpdump|tcpdump" ;;
        testssl.sh) echo "testssl.sh|testssl.sh" ;;
        theharvester) echo "theharvester|theharvester" ;;
        tlsx) echo "tlsx|tlsx" ;;
        tplmap) echo "tplmap|tplmap" ;;
        tracepath|traceroute) echo "traceroute|traceroute" ;;
        trivy) echo "trivy|trivy" ;;
        trufflehog) echo "trufflehog|trufflehog" ;;
        tshark) echo "wireshark-cli|wireshark-cli" ;;
        # u
        umount) echo "util-linux|util-linux" ;;
        uname) echo "coreutils|coreutils" ;;
        unrar) echo "unrar|unrar" ;;
        unshadow|useradd|userdel|usermod) echo "shadow|passwd" ;;
        unzip) echo "unzip|unzip" ;;
        update-rc.d) echo "init-system-helpers|init-system-helpers" ;;
        upx) echo "upx-ucl|upx-ucl" ;;
        urless) echo "urless|urless" ;;
        urlsnarf) echo "urlsnarf|urldump" ;;
        uro) echo "uro|uro" ;;
        # w
        wafw00f) echo "wafw00f|wafw00f" ;;
        wapiti) echo "wapiti|wapiti" ;;
        wash) echo "reaver|reaver" ;;
        wavemon) echo "wavemon|wavemon" ;;
        waybackurls) echo "waybackurls|waybackurls" ;;
        waymore) echo "waymore|waymore" ;;
        wc) echo "coreutils|coreutils" ;;
        webanalyze) echo "webanalyze|webanalyze" ;;
        weevely) echo "weevely|weevely" ;;
        wfuzz) echo "wfuzz|wfuzz" ;;
        wget) echo "wget|wget" ;;
        whatweb) echo "whatweb|whatweb" ;;
        proxychains) echo "proxychains-ng|proxychains" ;;
        packetforge-ng) echo "packetforge-ng|packetforge-ng" ;;
        diff) echo "diffutils|diffutils" ;;
        wpa_supplicant) echo "wpa_supplicant|wpa_supplicant" ;;
        which) echo "which|debianutils" ;;
        whois) echo "whois|whois" ;;
        windapsearch) echo "windapsearch|windapsearch" ;;
        wlanhcx2john) echo "hcxtools|john" ;;
        wpscan) echo "wpscan|wpscan" ;;
        # x
        x8) echo "x8|x8" ;;
        xfreerdp) echo "freerdp|freerdp2-x11" ;;
        xsstrike) echo "xsstrike|xsstrike" ;;
        xxd) echo "xxd|xxd" ;;
        # y
        yara) echo "yara|yara" ;;
        ysoserial) echo "ysoserial|ysoserial" ;;
        # z
        zgrab2) echo "zgrab|zgrab" ;;
        zip) echo "zip|zip" ;;
        zip2john) echo "john|john" ;;
        # Anything the catalog names that is not listed above falls back to a
        # same-name package, which is the right guess for most Go and Rust tools
        # and is still verified before anything is installed.
        *) echo "$tool|$tool" ;;
    esac
}

# Guidance when an automated install fails or check-only is set.
manual_commands() {
    local tool="$1"
    local info arch_pkg kali_pkg pkg
    info=$(pkg_info "$tool")
    arch_pkg="${info%%|*}"
    kali_pkg="${info##*|}"
    # Fedora, Alpine and openSUSE all carry the Arch spelling upstream, so the
    # first field is the right one for every non-Debian family.
    pkg="$arch_pkg"

    local helper
    helper=$(aur_helper)

    # The host's own manager first, because that is the command that will work
    # here. The other two follow so the note is still useful when this run is
    # read on a different machine, or when the script is copied elsewhere.
    case "$(pkg_manager)" in
        pacman)
            echo "    this host  : $DISTRO_NAME — sudo pacman -S $arch_pkg"
            [ -n "$helper" ] && echo "                  AUR: $helper -Ss $arch_pkg"
            ;;
        apt)
            echo "    this host  : $DISTRO_NAME — sudo apt install -y $kali_pkg"
            echo "                  if absent: apt search $kali_pkg"
            ;;
        dnf|yum)
            echo "    this host  : $DISTRO_NAME — sudo $(pkg_manager) install -y $pkg"
            echo "                  if absent: $(pkg_manager) search $pkg"
            ;;
        apk)
            echo "    this host  : $DISTRO_NAME — sudo apk add $pkg"
            echo "                  if absent: apk search -x $pkg"
            ;;
        zypper)
            echo "    this host  : $DISTRO_NAME — sudo zypper install -y $pkg"
            echo "                  if absent: zypper search $pkg"
            ;;
        *)
            echo "    no supported package manager found on this host"
            echo "    Arch Linux : sudo pacman -S $arch_pkg"
            echo "    Kali Linux : sudo apt install -y $kali_pkg"
            ;;
    esac
    echo "    otherwise  : install $tool from its upstream release and place it on PATH"
}

try_install() {
    local tool="$1"
    local info arch_pkg kali_pkg pkg
    info=$(pkg_info "$tool")
    arch_pkg="${info%%|*}"
    kali_pkg="${info##*|}"
    # Fedora, Alpine and openSUSE all carry the Arch spelling upstream, so the
    # first field is the right one for every non-Debian family.
    pkg="$arch_pkg"

    # oniux: built from source (crates.io has only a placeholder release).
    if [ "$tool" = "oniux" ]; then
        echo -e "    ${CYAN}[..] installing oniux from source (gitlab.torproject.org)...${RESET}"
        local tmp
        tmp=$(mktemp -d)
        if git -q clone --depth 1 --branch v0.13.0 \
             https://gitlab.torproject.org/tpo/core/oniux "$tmp/oniux" 2>/dev/null &&
           (cd "$tmp/oniux" && cargo build --release >/dev/null 2>&1) &&
           install -Dm755 "$tmp/oniux/target/release/oniux" "$HOME/.local/bin/oniux" 2>/dev/null; then
            rm -rf "$tmp"
            return 0
        fi
        rm -rf "$tmp"
        echo "    every distro : cargo install --git https://gitlab.torproject.org/tpo/core/oniux oniux"
        echo "    Arch Linux   : paru -S oniux   (or: yay -S oniux)"
        return 1
    fi

    local helper
    helper=$(aur_helper)

    case "$(pkg_manager)" in
        pacman)
            # Official repository first: it is verifiable, and it is what a
            # rollback will use. The AUR is the fallback, not the other way round.
            if command -v pacman >/dev/null 2>&1 &&
               sudo -n pacman -S --noconfirm --needed "$arch_pkg" >/dev/null 2>&1; then
                return 0
            fi
            if [ -n "$helper" ] &&
               "$helper" -S --noconfirm --needed "$arch_pkg" >/dev/null 2>&1; then
                return 0
            fi
            ;;
        apt)
            # --no-install-recommends keeps a phase install from pulling in a
            # desktop environment through a single package.
            if command -v apt-get >/dev/null 2>&1 &&
               sudo -n env DEBIAN_FRONTEND=noninteractive \
                    apt-get install -y --no-install-recommends "$kali_pkg" >/dev/null 2>&1; then
                return 0
            fi
            ;;
        dnf|yum)
            if command -v "$(pkg_manager)" >/dev/null 2>&1 &&
               sudo -n "$(pkg_manager)" install -y "$pkg" >/dev/null 2>&1; then
                return 0
            fi
            ;;
        apk)
            if command -v apk >/dev/null 2>&1 &&
               sudo -n apk add --no-cache "$pkg" >/dev/null 2>&1; then
                return 0
            fi
            ;;
        zypper)
            if command -v zypper >/dev/null 2>&1 &&
               sudo -n zypper --non-interactive install -y "$pkg" >/dev/null 2>&1; then
                return 0
            fi
            ;;
    esac
    return 1
}

# Extract the unique provider binaries for a phase from the TOML catalog.
tools_for_phase() {
    local phase="$1"
    python3 - "$CATALOG" "$phase" <<'PY'
import sys, re

path, phase = sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else ""
text = open(path, encoding="utf-8").read()

cap_re = re.compile(r"^\[\[capability\]\](.*?)^(?=\[\[capability\]\]|\Z)", re.S | re.M)
bin_re = re.compile(r"^binary\s*=\s*'([^']+)'", re.M)
phase_re = re.compile(r"^phase\s*=\s*'([^']+)'", re.M)

bins = []
for block in cap_re.finditer(text):
    body = block.group(1)
    m = phase_re.search(body)
    if phase in ("", "all") or (m and m.group(1) == phase):
        for bm in bin_re.finditer(body):
            b = bm.group(1)
            if b not in bins:
                bins.append(b)
print(" ".join(bins))
PY
}

resolve_phase() {
    local phase="$1"
    local phase_names="recon surface vulnerability payload escalation credentials lateral persistence exploitation wireless"

    if [ ! -f "$CATALOG" ]; then
        # Allow running from anywhere: fall back to the script's directory.
        local script_dir
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        CATALOG="$script_dir/$CATALOG"
    fi
    if [ ! -f "$CATALOG" ]; then
        echo -e "${RED}catalog not found: catalog/capabilities.toml${RESET}"
        exit 1
    fi
    if [ "$phase" != "all" ] && ! [[ " $phase_names " == *" $phase "* ]]; then
        echo -e "${RED}Unknown phase: $phase${RESET}"
        echo "Valid phases: $phase_names, all"
        exit 1
    fi

    local tools
    tools=$(tools_for_phase "$phase")
    if [ -z "$tools" ]; then
        echo -e "${RED}no tools found for phase: $phase${RESET}"
        exit 1
    fi

    local total
    total=$(wc -w <<<"$tools")
    echo -e "${BOLD}${CYAN}=== TSEC tool resolver: ${phase^^} ($total tools) ===${RESET}"

    local installed=0 missing=0
    local missing_tools=()
    for tool in $tools; do
        if check_tool "$tool"; then
            printf "  ${GREEN}OK ${RESET} %s\n" "$tool"
            installed=$((installed + 1))
        else
            printf "  ${RED}-- ${RESET} %s (missing)\n" "$tool"
            missing=$((missing + 1))
            missing_tools+=("$tool")
        fi
    done

    echo ""
    echo -e "${BOLD}Summary: ${installed} installed, ${missing} missing${RESET}"

    if [ "$missing" -eq 0 ]; then
        echo -e "${GREEN}All tools for phase ${phase} are ready.${RESET}"
        return 0
    fi

    if [ "$CHECK_ONLY" = true ]; then
        echo ""
        echo -e "${BOLD}${YELLOW}Missing tools - installation commands:${RESET}"
        echo "----------------------------------------------------------------"
        for tool in "${missing_tools[@]}"; do
            echo -e "${BOLD}$tool${RESET}"
            manual_commands "$tool"
        done
        echo "----------------------------------------------------------------"
        return 1
    fi

    echo ""
    echo -e "${BOLD}Attempting automated installation of missing tools...${RESET}"
    local still_missing=()
    for tool in "${missing_tools[@]}"; do
        echo -e "Installing ${BOLD}$tool${RESET}..."
        if try_install "$tool" && check_tool "$tool"; then
            echo -e "  ${GREEN}OK installed $tool${RESET}"
        else
            echo -e "  ${YELLOW}! could not install automatically${RESET}"
            still_missing+=("$tool")
        fi
    done

    if [ "${#still_missing[@]}" -gt 0 ]; then
        echo ""
        echo -e "${BOLD}${YELLOW}Manual installation commands for remaining tools:${RESET}"
        echo "----------------------------------------------------------------"
        for tool in "${still_missing[@]}"; do
            echo -e "${BOLD}$tool${RESET}"
            manual_commands "$tool"
        done
        echo "----------------------------------------------------------------"
    else
        echo -e "${GREEN}All missing tools were successfully installed.${RESET}"
    fi
}

usage() {
    echo -e "${BOLD}TSEC 3.0 tool dependency manager${RESET}"
    echo "Usage: $0 [-<phase> ...] [-c]"
    echo ""
    echo "Phases:"
    echo "  -recon           Reconnaissance"
    echo "  -surface         Attack Surface"
    echo "  -vulnerability   Vulnerability"
    echo "  -payload         Payload"
    echo "  -escalation      Privilege Escalation"
    echo "  -credentials     Credentials"
    echo "  -lateral         Lateral Movement"
    echo "  -persistence     Persistence & Defense Evasion"
    echo "  -exploitation    Exploitation"
    echo "  -wireless        Wireless"
    echo "  -all             Every phase"
    echo ""
    echo "Options:"
    echo "  -c               Check only: report missing tools and their"
    echo "                   Arch + Kali install commands; install nothing"
    exit 0
}

main() {
    [ $# -eq 0 ] && usage

    local phases=()
    for arg in "$@"; do
        case "$arg" in
            -c|--check) CHECK_ONLY=true ;;
            -h|--help) usage ;;
            -*) phases+=("$(echo "$arg" | sed 's/^--*//')") ;;
            *)  phases+=("$arg") ;;
        esac
    done
    [ ${#phases[@]} -eq 0 ] && usage

    local rc=0
    for phase in "${phases[@]}"; do
        resolve_phase "$phase" || rc=1
        echo ""
    done
    exit "$rc"
}

main "$@"
