/*
   Sliver C2 framework — implant indicators.

   Source / inspiration:
   - https://github.com/BishopFox/sliver
   - SentinelOne writeups on Sliver implants
*/

rule ARQENOR_Sliver_Implant
{
    meta:
        author      = "arqenor"
        description = "Sliver implant residual strings"
        family      = "Sliver"
        attack_id   = "T1071"
        severity    = "Critical"
        reference   = "https://github.com/BishopFox/sliver"
    strings:
        $s1 = "github.com/bishopfox/sliver" ascii
        $s2 = "sliverpb" ascii
        $s3 = "implant.exe" ascii nocase
        $s4 = "*sliverpb.Envelope" ascii
        $s5 = "BeaconRegister" ascii
        $s6 = "*sliverpb.Register" ascii
        $s7 = "rpcpb.SliverRPC" ascii
    condition:
        2 of them
}

rule ARQENOR_Sliver_Shellcode_DLL
{
    meta:
        author      = "arqenor"
        description = "Sliver shellcode/DLL stager metadata"
        family      = "Sliver"
        attack_id   = "T1055.001"
        severity    = "High"
        reference   = "https://www.sentinelone.com/labs/sliver-c2-leveraged-by-many-threat-actors/"
    strings:
        $a1 = "ReflectiveLoader" ascii
        $a2 = "donut" ascii
        $a3 = "sgn.exe" ascii nocase
        $a4 = "sliverShellcode" ascii nocase
    condition:
        2 of them
}
