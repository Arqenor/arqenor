/*
   PE injection / reflective loading indicators.

   Sources / inspiration:
   - Stephen Fewer — original ReflectiveLoader (https://github.com/stephenfewer/ReflectiveDLLInjection)
   - TrustedSec / Specula write-ups on reflective DLL injection
*/

rule ARQENOR_PE_Injection_Reflective
{
    meta:
        author      = "arqenor"
        description = "Reflective PE/DLL loader artifacts in non-image memory"
        family      = "ReflectivePE"
        attack_id   = "T1055.001"
        severity    = "High"
        reference   = "https://github.com/stephenfewer/ReflectiveDLLInjection"
    strings:
        $mz = { 4D 5A }                  // MZ header
        $pe = "PE\x00\x00"
        $reflective = "ReflectiveLoader" ascii
        $r1 = "_ReflectiveLoader@4" ascii
        $r2 = "GetProcAddressR" ascii
        $r3 = "LoadLibraryR" ascii
    condition:
        $mz at 0 and $pe and ($reflective or any of ($r*))
}

rule ARQENOR_PE_Injection_Donut
{
    meta:
        author      = "arqenor"
        description = "Donut shellcode loader artifacts"
        family      = "Donut"
        attack_id   = "T1055"
        severity    = "High"
        reference   = "https://github.com/TheWover/donut"
    strings:
        // Strong indicators — present only in donut payloads.
        $a1 = "DONUT_INSTANCE" ascii
        $a3 = { B8 6E F4 79 18 }     // donut signature constant
        // Weak indicators — common in benign code:
        // - "donut.exe" can be a developer build artefact name
        // - "Microsoft.Win32.SafeHandles" is in every .NET binary's metadata
        $a2 = "donut.exe" ascii nocase
        $a4 = "Microsoft.Win32.SafeHandles" ascii
    // Strong indicator alone fires; weak indicators must co-occur with a
    // strong one to count.
    condition:
        $a1 or $a3 or (($a2 or $a4) and ($a1 or $a3))
}
