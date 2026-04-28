/*
   Generic shellcode patterns — common stager prologues / API hashing.

   Sources / inspiration:
   - Didier Stevens — shellcode detection heuristics
   - ANSSI dfir-orc rule packs
   - Florian Roth — generic_shellcode.yar
*/

rule ARQENOR_Shellcode_Common_Prologue
{
    meta:
        author      = "arqenor"
        description = "Common shellcode entry-point prologues (PEB walk)"
        family      = "GenericShellcode"
        attack_id   = "T1055"
        severity    = "Medium"
        reference   = "https://github.com/Neo23x0/signature-base/blob/master/yara/gen_generic_shellcode.yar"
    strings:
        // 64-bit PEB walk: mov rax, gs:[60h]
        $a1 = { 65 48 8B 04 25 60 00 00 00 }
        // 32-bit PEB walk: mov eax, fs:[30h]
        $a2 = { 64 A1 30 00 00 00 }
        // 32-bit PEB walk variant: mov eax, fs:[0x30]
        $a3 = { 64 8B 0D 30 00 00 00 }
        // syscall stub used by direct-syscall payloads
        $a4 = { 4C 8B D1 B8 ?? ?? 00 00 0F 05 }
    // PEB walk + direct-syscall stubs are individually emitted by ntdll, the
    // .NET runtime, and the Windows loader. Requiring 2 distinct prologues
    // co-located in the same memory region narrows to suspicious payloads.
    condition:
        2 of them
}

rule ARQENOR_Shellcode_API_Hashing
{
    meta:
        author      = "arqenor"
        description = "API hashing constants used by Metasploit/CS shellcode"
        family      = "GenericShellcode"
        attack_id   = "T1027"
        severity    = "Medium"
    strings:
        // ROR-13 hash for "kernel32.dll" — used by Metasploit, CS, many others.
        $h1 = { 6A 30 59 64 8B 31 8B 76 0C }
        // Constant 0xEDB88320 (CRC32 polynomial) — common in API hashing.
        $h2 = { 20 83 B8 ED }
    condition:
        any of them
}
