# Phase 2 — Kernel Telemetry (ETW + eBPF)
> Target: Q3 2026 | Priority: HIGH | Effort: Very High

## Why This Is the Biggest Gap

The #1 detection gap between ARQENOR and CrowdStrike/ArqenorOne is the
**Microsoft-Windows-Threat-Intelligence ETW provider** (a.k.a. "ETW-TI").

This kernel-level channel delivers callbacks on every call to:
- `VirtualAllocEx`, `VirtualProtect` — memory allocation with RWX permissions
- `WriteProcessMemory` — classic injection primitive
- `SetThreadContext` — process hollowing/thread hijacking
- `QueueUserAPC` — APC injection
- `MapViewOfFile2` — section-based injection

**Critically, it includes the full call stack.** This lets CrowdStrike detect:
- Direct syscalls (shellcode bypasses user-mode hooks)
- ROP gadgets in call chains  
- Shellcode execution (anonymous executable memory)
- Cross-process operations

Access requires the consuming process to run as PPL (Protected Process Light),
which requires a **Microsoft-signed kernel driver**. This is the only reason
commercial EDRs have an advantage here.

---

## 2.1 — Windows: ETW Consumer

### Short-Term (No Driver Required)

While a signed driver is being developed, we can consume ETW channels that
don't require PPL using the standard Windows ETW API:

**Accessible ETW providers (no PPL needed):**
```
Microsoft-Windows-Kernel-Process      — process/thread/image-load events
Microsoft-Windows-Kernel-File         — file I/O operations  
Microsoft-Windows-Kernel-Registry     — registry operations
Microsoft-Windows-Kernel-Network      — network connections per-process
Microsoft-Windows-Security-Auditing   — security audit events (with admin rights)
Microsoft-Windows-PowerShell          — PowerShell script execution, AMSI
Microsoft-Windows-WMI-Activity        — WMI activity and event subscriptions
Microsoft-Windows-TaskScheduler       — scheduled task creation/modification
Microsoft-Windows-DNS-Client          — DNS queries per-process
```

These alone provide **massive** detection coverage without any kernel driver.

```rust
// arqenor-platform/src/windows/etw_consumer.rs
// Use windows-rs with Win32_System_Diagnostics_Etw feature

use windows::Win32::System::Diagnostics::Etw::*;

pub struct EtwConsumer {
    session_handle: u64,
}

impl EtwConsumer {
    pub fn start(providers: &[Guid], tx: Sender<EtwEvent>) -> Result<Self> {
        // StartTrace → EnableTraceEx2 for each provider → OpenTrace → ProcessTrace
    }
}

pub struct EtwEvent {
    pub provider:   String,
    pub event_id:   u16,
    pub pid:        u32,
    pub timestamp:  DateTime<Utc>,
    pub properties: HashMap<String, String>,
}
```

### ETW Events to Capture

| Provider | Event ID | What it gives |
|----------|----------|---------------|
| Microsoft-Windows-Kernel-Process | 1 | Process create (image, cmdline, parent PID) |
| Microsoft-Windows-Kernel-Process | 2 | Process terminate |
| Microsoft-Windows-Kernel-Process | 5 | Image/DLL load (path, hash) |
| Microsoft-Windows-Kernel-Network | 12 | TCP connect (PID → dest IP:port) |
| Microsoft-Windows-Kernel-Network | 15 | UDP send |
| Microsoft-Windows-Kernel-File | 12 | File create |
| Microsoft-Windows-PowerShell | 4104 | Script block logging (full PS content!) |
| Microsoft-Windows-WMI-Activity | 5861 | WMI event consumer creation |
| Microsoft-Windows-TaskScheduler | 106 | Task registered |
| Microsoft-Windows-Security-Auditing | 4688 | Process creation with full cmdline |
| Microsoft-Windows-Security-Auditing | 4698 | Scheduled task created |
| Microsoft-Windows-Security-Auditing | 4702 | Scheduled task modified |
| Microsoft-Windows-Security-Auditing | 4720 | User account created |
| Microsoft-Windows-Security-Auditing | 4732 | User added to local group |
| Microsoft-Windows-DNS-Client | 3006 | DNS query (domain → PID) |

### Why This Is Transformative

With ETW event ID 4104 (PowerShell script block logging), ARQENOR sees
the **full decoded PowerShell content** even after obfuscation — the payload
is decoded in memory before execution, and ETW captures it at that point.

This single provider catches:
- Invoke-Mimikatz variants
- Cobalt Strike PowerShell stagers
- Empire/Metasploit PowerShell payloads
- Any PowerShell-based infostealer

---

## 2.2 — Windows: Kernel Driver (Long-Term, PPL)

### Roadmap Toward PPL + ETW-TI

Getting a Microsoft-signed PPL driver is a multi-step process:

1. **Write the driver** (Rust via `windows-drivers-rs` crate — Microsoft's official Rust WDK support)
2. **Test sign** — for development and testing
3. **WHQL Certification** — submit to Windows Hardware Quality Labs
4. **EV Code Signing** — Extended Validation certificate required
5. **Microsoft Attestation Signing** — final step, Microsoft signs the driver
   (required for Windows 11 with Secure Boot)

Timeline: 6-9 months minimum from decision to production.

### Alternative: Minifilter Driver (File/Registry)

A minifilter driver doesn't require PPL but gives kernel-level FIM and
registry monitoring with much lower latency than polling:

```rust
// arqenor-driver/ (new crate)
// Built with windows-drivers-rs (Microsoft's official Rust WDK bindings)

// IRP_MJ_CREATE filter → intercept file opens on protected paths
// IRP_MJ_WRITE filter  → detect writes to critical system files
// Registry callbacks   → CmRegisterCallback for all registry modifications
```

### Driver Architecture

```
User space:   arqenor-agent (Rust service)
                    │ DeviceIoControl (IOCTL)
                    ▼
Kernel space: arqenor.sys (minifilter driver)
              ├── FltRegisterFilter()    — file system events
              ├── CmRegisterCallback()   — registry events  
              ├── PsSetCreateProcessNotifyRoutineEx() — process events
              ├── PsSetLoadImageNotifyRoutine()        — DLL load events
              └── ObRegisterCallbacks()  — handle-level access control
                  (protect ARQENOR agent process from termination)
```

The `ObRegisterCallbacks` hook is especially valuable — it lets ARQENOR
protect its own process handle from being opened with `PROCESS_TERMINATE`
rights by non-privileged processes. This is how commercial EDRs survive
"EDR killer" attacks.

---

## 2.3 — Linux: eBPF Agent

### eBPF vs. Auditd

| | auditd | eBPF (libbpf) |
|-|--------|---------------|
| Overhead | High (blocking) | Low (in-kernel filtering) |
| Latency | Seconds | Microseconds |
| io_uring coverage | None | Partial (growing) |
| Kernel version | All | 5.8+ recommended |
| Evasion risk | High (auditd can be killed) | Harder (eBPF programs survive process death) |

### Syscalls to Trace

```c
// arqenor-ebpf/src/probes.bpf.c

// Process execution
tracepoint/syscalls/sys_enter_execve    → capture: filename, argv
tracepoint/syscalls/sys_enter_execveat  → capture: dirfd, filename

// Memory injection  
kprobe/do_mmap    → flag: PROT_EXEC | PROT_WRITE combined (T1055)
kprobe/ptrace     → any ptrace attach to another process (T1055.008)

// Persistence
tracepoint/syscalls/sys_enter_openat → path matches /etc/cron.d/, /etc/systemd/
tracepoint/syscalls/sys_enter_write  → writing to /etc/ld.so.preload

// Privilege escalation
kprobe/commit_creds    → uid/gid change (su/sudo, SUID exploit)
kprobe/prepare_kernel_cred → setuid(0) from non-root process

// Network
tracepoint/syscalls/sys_enter_connect → capture: pid, dest IP/port
tracepoint/syscalls/sys_enter_bind    → new listening ports

// Module loading (rootkit detection)
kprobe/do_init_module → kernel module loaded; capture: module name + hash
```

### eBPF → Rust Pipeline

```
eBPF programs (C) compiled with clang/LLVM
       │ BPF ring buffer
       ▼
arqenor-ebpf-agent (Rust, using libbpf-rs)
       │ tokio channel
       ▼  
arqenor-core detection rules
       │
       ▼
Alert → TUI / Desktop UI
```

### eBPF Rootkit Self-Defense

A known weakness: if a rootkit intercepts the eBPF ring buffer export path,
it can suppress events. Counter-measures:

1. Monitor `bpf()` syscall itself — if another process loads eBPF programs, alert
2. Verify integrity of ARQENOR's own loaded eBPF programs via `/sys/fs/bpf/`
3. Cross-check process tree from eBPF vs `/proc` — discrepancy = rootkit hiding processes

---

## 2.4 — macOS: Endpoint Security Framework (ESF)

Apple's ESF is the supported API for macOS security tools (replaced deprecated
kext-based approach). Requires `com.apple.developer.endpoint-security.client`
entitlement — only granted to apps distributed on the Mac App Store or via
notarization with a special Apple entitlement.

```swift
// arqenor-mac-agent/Sources/ESAgent.swift
// (Swift module, called from Rust via FFI)

import EndpointSecurity

func startMonitoring() {
    es_new_client(&client, { client, message in
        switch message.pointee.event_type {
        case ES_EVENT_TYPE_NOTIFY_EXEC:     // process execution
        case ES_EVENT_TYPE_NOTIFY_CREATE:   // file creation
        case ES_EVENT_TYPE_NOTIFY_OPEN:     // file open (for FIM)
        case ES_EVENT_TYPE_AUTH_EXEC:       // can BLOCK execution
        case ES_EVENT_TYPE_NOTIFY_KEXTLOAD: // kernel extension loaded
        }
    })
    
    es_subscribe(client, [
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_CREATE,
        ES_EVENT_TYPE_AUTH_EXEC,    // AUTH events allow blocking
        ES_EVENT_TYPE_NOTIFY_KEXTLOAD,
    ])
}
```

The `AUTH_EXEC` event type lets ARQENOR **block** process execution — not just
observe — on macOS. This is the equivalent of real-time prevention mode.

---

## Crates Required

| Crate | Purpose |
|-------|---------|
| `arqenor-etw` (new) | Windows ETW consumer, event parsing |
| `arqenor-driver` (new) | Windows kernel driver (Phase 2b, long-term) |
| `arqenor-ebpf` (new) | Linux eBPF programs + Rust loader |
| `libbpf-rs` | Rust bindings for libbpf (eBPF loader) |
| `windows-drivers-rs` | Microsoft's Rust WDK bindings (driver dev) |

## Coverage After Phase 2

+30 techniques, including the hardest to detect:
- T1055.* — Process Injection (ETW call-stack detection)
- T1059.001 — PowerShell (Event 4104 full content)
- T1546.003 — WMI Event Subscription (ETW real-time)
- T1053.005 — Scheduled Tasks (ETW real-time, not polling)
- T1003.001 — LSASS credential dumping (handle monitoring)
- T1014 — Rootkit (eBPF + kernel module monitoring)
