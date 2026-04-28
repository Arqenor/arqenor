/*
   Encoded / obfuscated PowerShell — common offensive patterns.

   Sources / inspiration:
   - SpectreOps — Invoke-Obfuscation
   - Microsoft Defender ATP threat reports on PS-based loaders
*/

rule ARQENOR_PowerShell_EncodedCommand
{
    meta:
        author      = "arqenor"
        description = "Encoded PowerShell command-line invocation in memory"
        family      = "PowerShellLoader"
        attack_id   = "T1059.001"
        severity    = "High"
    strings:
        $p1 = "powershell" ascii wide nocase
        $f1 = "-EncodedCommand" ascii wide nocase
        $f2 = "-EncodedC" ascii wide nocase
        $f3 = "-enc " ascii wide nocase
        $f4 = "-NoP" ascii wide nocase
        $f5 = "-W Hidden" ascii wide nocase
        $f6 = "-WindowStyle Hidden" ascii wide nocase
        $f7 = "FromBase64String" ascii wide nocase
    condition:
        $p1 and 2 of ($f*)
}

rule ARQENOR_PowerShell_Loader_Reflection
{
    meta:
        author      = "arqenor"
        description = "PowerShell reflection / Add-Type loader patterns"
        family      = "PowerShellLoader"
        attack_id   = "T1059.001"
        severity    = "High"
    strings:
        $r1 = "System.Reflection.Assembly" ascii wide
        $r2 = "[System.Reflection.AssemblyName]" ascii wide
        $r3 = "Reflection.Emit" ascii wide
        $r4 = "DllImport" ascii wide
        $r5 = "Invoke-Expression" ascii wide nocase
        $r6 = "IEX (" ascii wide nocase
        $r7 = "DownloadString(" ascii wide nocase
    condition:
        3 of them
}
