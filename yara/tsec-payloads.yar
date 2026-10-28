// TSEC payload triage rules.
//
// The distribution's `yara-rules` package ships documentation only, so a scan
// has nothing to match against and reports every file as clean — which is the
// worst possible answer, because it reads as a pass. These rules cover what a
// generated payload actually looks like: packer sections, shellcode markers,
// hardcoded credentials, and reverse-shell shapes.
//
// A match means "look at this", not "this is malware". The rules are
// deliberately coarse and high-signal: a false positive costs one read of the
// file, and a false negative costs the whole scan.

rule tsec_upx_packer
{
    meta:
        description = "UPX-packed executable"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx2 = "UPX!"
    condition:
        uint16(0) == 0x5A4D and (2 of them)
}

rule tsec_meterpreter_stager
{
    meta:
        description = "Metasploit stager or reflective loader"
    strings:
        $mz = { 4D 5A }
        $metsrv = "metsrv" ascii nocase
        $reflective = "ReflectiveLoader" ascii
        $inject = "VirtualAlloc" ascii
    condition:
        $mz at 0 and any of ($metsrv, $reflective, $inject)
}

rule tsec_reverse_shell_payload
{
    meta:
        description = "Generated reverse shell"
    strings:
        $bash = "/dev/tcp/" ascii
        $bash2 = "/dev/udp/" ascii
        $nc = "nc -e /bin/sh" ascii
        $sock = "socket.socket(socket.AF_INET" ascii
        $sh = "/bin/bash -i >& /dev/tcp/" ascii
    condition:
        any of them
}

rule tsec_embedded_credential
{
    meta:
        description = "Hardcoded credential in a generated artefact"
    strings:
        $aws = /AKIA[0-9A-Z]{16}/ ascii
        $priv = "BEGIN RSA PRIVATE KEY" ascii
        $priv2 = "BEGIN OPENSSH PRIVATE KEY" ascii
        $pw = "password=" nocase ascii
    condition:
        any of them
}

rule tsec_webshell_one_liner
{
    meta:
        description = "Inline PHP execution gadget"
    strings:
        $a = "<?php system(" nocase
        $b = "<?php passthru(" nocase
        $c = "<?php shell_exec(" nocase
        $d = "assert($_POST" nocase
        $e = "eval($_REQUEST" nocase
    condition:
        any of them
}

rule tsec_office_macro
{
    meta:
        description = "Office document carrying a macro"
    strings:
        $vba = "VBA project" ascii nocase
        $auto = "AutoOpen" ascii nocase
        $shell = "Shell(" ascii
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
    condition:
        $ole at 0 and any of ($vba, $auto, $shell)
}

rule tsec_persistence_marker
{
    meta:
        description = "Persistence mechanism in a generated artefact"
    strings:
        $run = "CurrentVersion\\Run" ascii nocase
        $cron = "crontab" ascii
        $sched = "schtasks" ascii nocase
        $ssh = "authorized_keys" ascii
    condition:
        any of them
}
