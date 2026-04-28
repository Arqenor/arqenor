/*
   Havoc C2 framework (HavocFramework / Demon agent).

   Source / inspiration:
   - https://github.com/HavocFramework/Havoc
   - Zscaler ThreatLabz writeup on Havoc
*/

rule ARQENOR_Havoc_Demon
{
    meta:
        author      = "arqenor"
        description = "Havoc Demon agent residual strings"
        family      = "Havoc"
        attack_id   = "T1071"
        severity    = "Critical"
        reference   = "https://github.com/HavocFramework/Havoc"
    strings:
        $s1 = "HavocFramework" ascii
        $s2 = "DemonInit" ascii
        $s3 = "DemonRoutine" ascii
        $s4 = "Demon.x64.dll" ascii nocase
        $s5 = "DemonGate" ascii
        $s6 = "CommandDispatcher" ascii
        $s7 = "PackageDispatcher" ascii
    condition:
        2 of them
}
