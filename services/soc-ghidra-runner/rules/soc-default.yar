rule Suspicious_PowerShell_EncodedCommand
{
    meta:
        description = "PowerShell encoded command or hidden execution strings"
        mitre = "T1059.001"
    strings:
        $a = "-EncodedCommand" nocase
        $b = "FromBase64String" nocase
        $c = "powershell" nocase
        $d = "-nop" nocase
        $e = "-w hidden" nocase
    condition:
        $a or ($b and $c) or ($c and ($d or $e))
}

rule Suspicious_Windows_Process_Injection_Strings
{
    meta:
        description = "Common Windows process injection API strings"
        mitre = "T1055"
    strings:
        $a = "VirtualAlloc" ascii wide
        $b = "WriteProcessMemory" ascii wide
        $c = "CreateRemoteThread" ascii wide
        $d = "OpenProcess" ascii wide
    condition:
        3 of them
}

rule Suspicious_Persistence_Registry_RunKey
{
    meta:
        description = "Windows Run key persistence strings"
        mitre = "T1547.001"
    strings:
        $a = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $b = "RegSetValue" ascii wide
        $c = "schtasks" ascii wide nocase
    condition:
        $a or ($b and $c)
}

rule Suspicious_Credential_Access_Strings
{
    meta:
        description = "Credential access related strings"
        mitre = "T1003"
    strings:
        $a = "lsass" ascii wide nocase
        $b = "MiniDumpWriteDump" ascii wide
        $c = "sekurlsa" ascii wide nocase
        $d = "mimikatz" ascii wide nocase
    condition:
        any of them
}
