/*
   Brute Ratel C4 — commercial post-exploitation framework abused by APTs.

   Source / inspiration:
   - Palo Alto Unit 42 "When Pentest Tools Go Brutal" (Jul 2022)
   - Mandiant: "Brute Ratel C4 in the Wild"
*/

rule ARQENOR_BruteRatel_Badger
{
    meta:
        author      = "arqenor"
        description = "Brute Ratel Badger implant strings"
        family      = "BruteRatel"
        attack_id   = "T1071.001"
        severity    = "Critical"
        reference   = "https://unit42.paloaltonetworks.com/brute-ratel-c4-tool"
    strings:
        $s1 = "BadgerInstance" ascii wide
        $s2 = "BrcDecryptKey" ascii
        $s3 = "BadgerExportApi" ascii
        $s4 = "Mango_Mango" ascii
        $s5 = "badger.dll" ascii wide nocase
        $s6 = "BadgerDispatch" ascii
    condition:
        2 of them
}
