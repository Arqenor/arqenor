# Phase 5 — Memory Forensics + Anti-Injection
> Target: Q1 2027 | Priority: MEDIUM | Effort: High

## What Memory Forensics Adds

Phases 1-4 detect malicious **behavior** (what a process does).
Memory forensics detects malicious **state** (what lives in process memory).

This matters because:
- Fileless malware leaves no disk artifact — memory is the only evidence
- Process hollowing, reflective DLL injection, and shellcode execution
  are invisible to file-based scanners
- AMSI patching and hook removal modify process memory without touching disk

---

## 5.1 — VAD Tree Walk (Anonymous Executable Memory)

### The Technique

Windows tracks all process memory allocations in a Virtual Address Descriptor (VAD) tree.
Each node describes a memory region: base address, size, protection, and — critically —
**whether it's backed by a file on disk**.

Malicious indicators:
1. **Anonymous RWX memory** — executable memory NOT backed by a file = shellcode
2. **Private executable memory** — PE loaded via `VirtualAllocEx` + `WriteProcessMemory`
   (as opposed to normal `LoadLibrary`) = process injection
3. **Executable heap pages** — heap regions marked executable = JIT or shellcode

```rust
// arqenor-platform/src/windows/memory_scan.rs

pub struct MemoryRegion {
    pub base:         usize,
    pub size:         usize,
    pub protect:      u32,          // PAGE_EXECUTE_READ, etc.
    pub type_:        u32,          // MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE
    pub state:        u32,          // MEM_COMMIT, MEM_RESERVE, MEM_FREE
    pub mapped_file:  Option<String>, // None = anonymous (suspicious if executable)
}

pub fn scan_process_memory(pid: u32) -> Vec<MemoryAnoaly> {
    // VirtualQueryEx(process_handle, ...) loop through entire address space
    // Flag regions where:
    //   - type == MEM_PRIVATE (not file-backed)
    //   AND protect has EXECUTE bit
    //   AND state == MEM_COMMIT (actually allocated)
    // These are candidate shellcode/injection regions
}
```

### Process Hollowing Detection (T1055.012)

Process hollowing:
1. Start a legitimate process suspended (`CreateProcess` with `CREATE_SUSPENDED`)
2. `NtUnmapViewOfSection` to unmap the original code
3. `VirtualAllocEx` to write malicious PE
4. `SetThreadContext` to redirect to new entry point
5. `ResumeThread`

Detection: compare the in-memory PE header bytes of a running process against
the on-disk image at the same path.

```rust
pub fn detect_hollow_process(pid: u32) -> Option<Alert> {
    let process = open_process(pid)?;
    let image_path = get_process_image_path(pid)?;
    
    // Read PE header from running process memory (first 0x1000 bytes at ImageBase)
    let memory_pe_header = read_process_memory(process, image_base, 0x1000)?;
    
    // Read the same file from disk
    let disk_pe_header = read_file_header(&image_path, 0x1000)?;
    
    // Compare: if different → process was hollowed
    // Note: some differences are expected (relocations, patches) — compare key fields:
    // - OptionalHeader.AddressOfEntryPoint
    // - OptionalHeader.ImageBase  
    // - FileHeader.Characteristics
    if significant_difference(&memory_pe_header, &disk_pe_header) {
        Some(Alert { severity: Critical, attack_id: "T1055.012", ... })
    } else {
        None
    }
}
```

---

## 5.2 — NTDLL Hook Detection

### Why This Matters

Commercial EDR hooks NTDLL (the lowest-level Windows DLL before the kernel) to
monitor API calls. Attackers know this and routinely un-hook NTDLL by:
1. Loading a fresh copy of `ntdll.dll` from disk
2. Comparing hooked bytes with clean bytes
3. Restoring clean bytes over the hooked ones

The result: the EDR's hooks are removed. No more visibility into injection APIs.

ARQENOR can detect this attack by checking NTDLL integrity:

```rust
pub fn check_ntdll_hooks() -> Vec<Alert> {
    let mut alerts = Vec::new();
    
    // Load clean copy of ntdll.dll from disk
    let disk_ntdll = load_file_bytes("C:\\Windows\\System32\\ntdll.dll")?;
    
    // Get base address of ntdll.dll in current process (or target process)
    let loaded_ntdll_base = get_module_base("ntdll.dll")?;
    
    // Critical functions to check (injection primitives):
    let functions = [
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory", 
        "NtCreateThreadEx",
        "NtQueueApcThread",
        "LdrLoadDll",
    ];
    
    for func in &functions {
        let disk_bytes   = get_function_bytes_from_file(&disk_ntdll, func)?;
        let loaded_bytes = get_function_bytes_in_memory(loaded_ntdll_base, func)?;
        
        if &disk_bytes[..5] != &loaded_bytes[..5] {
            alerts.push(Alert {
                severity:  Critical,
                attack_id: "T1562.001",
                message:   format!("NTDLL hook removed on {func} — possible EDR bypass"),
            });
        }
    }
    alerts
}
```

---

## 5.3 — YARA Scanning in Memory

YARA rules are the industry-standard format for pattern matching in files AND memory.
Running YARA rules against process memory catches:
- Known malware families (Cobalt Strike, Metasploit, Sliver)
- Common shellcode stubs
- Credential dumping tools (Mimikatz)

```rust
// Use yara-x crate (pure Rust YARA engine)

pub struct MemoryScanner {
    rules: yara_x::Rules,
}

impl MemoryScanner {
    pub fn scan_process(&self, pid: u32) -> Vec<YaraMatch> {
        let regions = get_executable_regions(pid);
        let mut matches = Vec::new();
        
        for region in regions {
            let bytes = read_process_memory_region(pid, &region)?;
            if let Ok(hits) = self.rules.scan_mem(&bytes) {
                matches.extend(hits.into_iter().map(|h| YaraMatch {
                    rule_name: h.identifier().to_string(),
                    region:    region.base,
                    pid,
                }));
            }
        }
        matches
    }
}
```

**YARA rule sources:**
- `https://github.com/Neo23x0/signature-base` — Florian Roth's massive ruleset
- `https://github.com/elastic/protections-artifacts` — Elastic's public rules
- `https://github.com/mandiant/red_team_tool_countermeasures` — Mandiant C2 tool rules

---

## 5.4 — BYOVD Detection (T1068)

Bring Your Own Vulnerable Driver attacks use signed but vulnerable kernel drivers
to achieve ring-0 execution. Detection:

```rust
pub async fn check_loaded_drivers() -> Vec<Alert> {
    // 1. Enumerate loaded kernel drivers
    //    Windows: EnumDeviceDrivers() or NtQuerySystemInformation(SystemModuleInformation)
    // 2. Hash each driver
    // 3. Check against LOLDrivers.io blocklist (vulnerable driver database)
    //    Download: https://www.loldrivers.io/api/drivers.json
    // 4. Flag any driver that matches a known-vulnerable entry
    // 5. Also flag: drivers loaded from user-writable paths (Downloads, TEMP)
    
    let loaded_drivers = enumerate_kernel_drivers().await?;
    let blocklist = load_loldrivers_blocklist().await?;
    
    loaded_drivers.into_iter()
        .filter_map(|drv| {
            let hash = sha256_file(&drv.path)?;
            if blocklist.contains(&hash) {
                Some(Alert {
                    severity: Critical,
                    attack_id: "T1068",
                    message: format!("Vulnerable driver loaded: {} (known BYOVD tool)", drv.name),
                })
            } else if is_user_writable_path(&drv.path) {
                Some(Alert {
                    severity: High,
                    attack_id: "T1068",
                    message: format!("Driver loaded from suspicious path: {}", drv.path),
                })
            } else {
                None
            }
        })
        .collect()
}
```

---

## 5.5 — Credential Guard Status Check

Quick win: check if Windows Credential Guard is enabled.
If disabled on a machine that should have it → policy violation alert.

```rust
pub fn check_credential_guard() -> SecurityPosture {
    // HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity
    // HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags
    //
    // Value 2 = Strict mode (UEFI lock — can't be disabled without UEFI access)
    // Value 1 = Enabled without lock
    // Value 0 = Disabled → LSASS is vulnerable to credential dumping
}

pub fn check_lsa_protection() -> SecurityPosture {
    // HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL
    // Value 1 = LSA runs as Protected Process Light
    // If 0 → Mimikatz can dump credentials directly
}
```

---

## Coverage After Phase 5

+15 techniques:
- T1055.012 — Process Hollowing
- T1055.001 — DLL Injection (VAD anonymous executable memory)
- T1055 — Generic Process Injection (shellcode detection)
- T1562.001 — NTDLL hook removal (impair defenses)
- T1068 — BYOVD privilege escalation
- T1003.001 — LSASS memory read (enhanced: direct memory comparison)

---

## Hardening notes (2026-04-27 security audit pass)

- **PPL-protected processes.** `windows/memory_scan.rs` now falls back to `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` when `PROCESS_VM_READ` is denied. The new `MemoryScanResult::vm_read_denied` flag lets the pipeline distinguish "not enumerated" from "process clean", restoring partial telemetry on the most-targeted processes (LSASS, MsMpEng, …).
- **Streaming SHA-256.** BYOVD (`byovd.rs`), NTDLL check (`ntdll_check.rs`) and memory scan (`memory_scan.rs`) all switched to `arqenor-platform/src/hash.rs` (default 512 MiB cap) — closes the OOM vector previously caused by hashing arbitrarily-large drivers / DLLs in a single `fs::read`.
