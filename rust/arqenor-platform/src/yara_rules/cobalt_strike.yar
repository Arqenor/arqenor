/*
   Cobalt Strike beacon — in-memory indicators.

   Source / inspiration:
   - Elastic public detection rules https://github.com/elastic/protections-artifacts
   - Florian Roth signatures (Neo23x0/signature-base)
   - JPCERT memory analysis notes on CS beacon configuration block

   These are intentionally lightweight (string-based) so they fire on residual
   strings inside extracted process memory rather than on packed/encoded
   payloads.  Encoded payloads should be caught by the BYOVD / memory-anomaly
   layer, not by YARA alone.
*/

rule ARQENOR_CobaltStrike_Beacon_Strings
{
    meta:
        author      = "arqenor"
        description = "Cobalt Strike beacon residual strings in process memory"
        family      = "CobaltStrike"
        attack_id   = "T1055"
        severity    = "Critical"
        reference   = "https://www.cobaltstrike.com/help-beacon"
    strings:
        $a1 = "%%IMPORT%%" ascii wide
        $a2 = "beacon.dll" ascii wide nocase
        $a3 = "beacon.x64.dll" ascii wide nocase
        $a4 = "ReflectiveLoader" ascii
        $b1 = "%c%c%c%c%c%c%cMSSE-%d-server" ascii
        $b2 = "(admin) checkin" ascii
        $b3 = "%s as %s\\%s: %d" ascii
    condition:
        2 of ($a*) or 1 of ($b*)
}

rule ARQENOR_CobaltStrike_Beacon_Config
{
    meta:
        author      = "arqenor"
        description = "Cobalt Strike beacon configuration block magic"
        family      = "CobaltStrike"
        attack_id   = "T1071.001"
        severity    = "Critical"
        reference   = "Sentinel One: Inside the Cobalt Strike Beacon"
    strings:
        // Encoded config block prefix used by CS 4.x (single byte XOR 0x2E).
        // 16 ASCII dots in a row also occurs in benign documents/URLs, so we
        // require it to co-locate with the decoded plaintext marker below to
        // keep the FP rate low on user workstations.
        $cfg_xor = { 2E 2E 2E 2E 2E 2E 2E 2E 2E 2E 2E 2E 2E 2E 2E 2E }
        // Plaintext config marker once decoded.
        $cfg_plain = { 00 01 00 01 00 02 ?? ?? }
    condition:
        all of them
}
