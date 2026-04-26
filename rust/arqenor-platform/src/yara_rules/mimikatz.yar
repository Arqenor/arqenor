/*
   Mimikatz / pypykatz — credential-dumping toolkit.

   Source / inspiration:
   - https://github.com/gentilkiwi/mimikatz (canonical strings)
   - Florian Roth signature-base (apt_mimikatz.yar)
*/

rule ARQENOR_Mimikatz_Strings
{
    meta:
        author      = "arqenor"
        description = "Mimikatz binary strings in process memory"
        family      = "Mimikatz"
        attack_id   = "T1003.001"
        severity    = "Critical"
        reference   = "https://github.com/gentilkiwi/mimikatz"
    strings:
        $a1 = "sekurlsa::logonpasswords" ascii wide nocase
        $a2 = "sekurlsa::pth" ascii wide nocase
        $a3 = "kerberos::list" ascii wide nocase
        $a4 = "lsadump::sam" ascii wide nocase
        $a5 = "privilege::debug" ascii wide nocase
        $a6 = "Mimikatz" ascii wide
        $a7 = "gentilkiwi" ascii
        $a8 = "Benjamin DELPY" ascii
    condition:
        2 of them
}

rule ARQENOR_Mimikatz_Modules
{
    meta:
        author      = "arqenor"
        description = "Mimikatz internal command strings"
        family      = "Mimikatz"
        attack_id   = "T1003"
        severity    = "Critical"
        reference   = "https://github.com/Neo23x0/signature-base/blob/master/yara/apt_mimikatz.yar"
    strings:
        $m1 = "n.e. (KIWI_MSV1_0_CREDENTIALS KO)" ascii
        $m2 = "* Username : %wZ" ascii
        $m3 = "* NTLM     :" ascii
        $m4 = "* Password :" ascii
        $m5 = "wdigest!l_LogSessList" ascii
    condition:
        2 of them
}
