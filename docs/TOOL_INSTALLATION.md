# TSEC Tool Installation Guide

TSEC relies on a variety of external scripts and tools to perform reconnaissance, vulnerability assessment, payload generation, privilege escalation, and lateral movement.

For maximum reliability and to ensure tools are consistently available, TSEC expects python scripts and bash scripts to be located in absolute paths, specifically `/opt/tsec/tools/`.

## Prerequisites

Ensure the directory exists and you have write permissions:
```bash
sudo mkdir -p /opt/tsec/tools/
sudo chown -R $USER:$USER /opt/tsec/tools/
```

## Installing Impacket Tools (phase06, phase07, phase09)

Impacket tools (`secretsdump.py`, `smbexec.py`, `wmiexec.py`, `psexec.py`, `ntlmrelayx.py`, `smbserver.py`, etc.) are heavily used for credential dumping, lateral movement, and SMB sharing.

Instead of relying on the system `PATH`, download the raw python scripts directly from the Impacket repository:

```bash
cd /opt/tsec/tools/
wget https://raw.githubusercontent.com/fortra/impacket/master/examples/secretsdump.py
wget https://raw.githubusercontent.com/fortra/impacket/master/examples/smbexec.py
wget https://raw.githubusercontent.com/fortra/impacket/master/examples/wmiexec.py
wget https://raw.githubusercontent.com/fortra/impacket/master/examples/psexec.py
wget https://raw.githubusercontent.com/fortra/impacket/master/examples/ntlmrelayx.py
wget https://raw.githubusercontent.com/fortra/impacket/master/examples/lookupsid.py
wget https://raw.githubusercontent.com/fortra/impacket/master/examples/atexec.py
wget https://raw.githubusercontent.com/fortra/impacket/master/examples/dcomexec.py
wget https://raw.githubusercontent.com/fortra/impacket/master/examples/smbserver.py

chmod +x *.py
```

## Installing Privilege Escalation Scripts (phase05)

### LinPEAS
LinPEAS is a script that searches for possible paths to escalate privileges on Linux/Unix/MacOS hosts.

```bash
cd /opt/tsec/tools/
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
```

### SUDO_KILLER
A tool to identify and exploit sudo rules' misconfigurations.

```bash
cd /opt/tsec/tools/
git clone https://github.com/TH3xACE/SUDO_KILLER.git
cp SUDO_KILLER/sudo_killer.sh .
chmod +x sudo_killer.sh
```

### Linux Exploit Suggester 2
```bash
cd /opt/tsec/tools/
wget https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.py
chmod +x linux-exploit-suggester-2.py
```

### Windows Exploit Suggester (wes.py)
```bash
cd /opt/tsec/tools/
wget https://raw.githubusercontent.com/bitsadmin/wesng/master/wes.py
chmod +x wes.py
```

## Installing Reconnaissance & Payload Scripts

### Cloud Enum (phase01)
```bash
cd /opt/tsec/tools/
wget https://raw.githubusercontent.com/initstring/cloud_enum/master/cloud_enum.py
chmod +x cloud_enum.py
```

### Unicorn (phase04, phase08)
```bash
cd /opt/tsec/tools/
wget https://raw.githubusercontent.com/trustedsec/unicorn/master/unicorn.py
chmod +x unicorn.py
```

### DNS Exfiltrator (phase09)
```bash
cd /opt/tsec/tools/
wget https://raw.githubusercontent.com/Arno0x/DNSExfiltrator/master/dnsExfiltrator.py -O dns-exfiltrator.py
chmod +x dns-exfiltrator.py
```

## Moving Existing Tools to /opt/tsec/tools/

If you already have these tools installed via `apt` or `pip`, you can simply create symbolic links to `/opt/tsec/tools/`.

For example, if `secretsdump.py` is in your `~/.local/bin/` directory:

```bash
ln -s ~/.local/bin/secretsdump.py /opt/tsec/tools/secretsdump.py
```

By ensuring all tools are located in `/opt/tsec/tools/`, TSEC commands will execute reliably without PATH environment variable issues.
