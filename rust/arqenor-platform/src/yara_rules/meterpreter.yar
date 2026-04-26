/*
   Metasploit Meterpreter — in-memory indicators.

   Source / inspiration:
   - Metasploit Framework source (rapid7/metasploit-framework)
   - Florian Roth signature-base (apt_apt29_grizzly_steppe.yar)
*/

rule ARQENOR_Meterpreter_Strings
{
    meta:
        author      = "arqenor"
        description = "Meterpreter residual strings in process memory"
        family      = "Meterpreter"
        attack_id   = "T1055"
        severity    = "Critical"
        reference   = "https://github.com/rapid7/metasploit-framework"
    strings:
        $s1 = "metsrv.dll" ascii wide nocase
        $s2 = "metsrv.x64.dll" ascii wide nocase
        $s3 = "stdapi_sys_process_get_processes" ascii
        $s4 = "core_channel_open" ascii
        $s5 = "ReflectiveLoader" ascii
        $s6 = "stdapi_railgun_api" ascii
        $s7 = "stdapi_fs_ls" ascii
    condition:
        2 of them
}

rule ARQENOR_Meterpreter_HTTP_Stager
{
    meta:
        author      = "arqenor"
        description = "Meterpreter HTTP/S reverse-stager URI patterns"
        family      = "Meterpreter"
        attack_id   = "T1071.001"
        severity    = "High"
        reference   = "https://www.rapid7.com/db/modules/payload/windows/meterpreter/reverse_http/"
    strings:
        // Default Metasploit reverse_http URI is /<4 base64 chars>; very common
        // server responses contain these stager headers.
        $h1 = "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)" ascii
        $h2 = "GET / HTTP/1.1" ascii
        $h3 = "ResponseLength" ascii
        $h4 = "TransportInit" ascii
    condition:
        3 of them
}
