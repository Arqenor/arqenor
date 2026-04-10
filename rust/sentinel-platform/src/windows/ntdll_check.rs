//! NTDLL hook detection (T1562.001).
//!
//! Detects when critical NTDLL functions have been modified in memory -- either
//! by malware removing EDR hooks, or by rootkits patching syscall stubs to
//! intercept calls.
//!
//! Algorithm:
//! 1. Read a fresh copy of ntdll.dll from disk (NOT via LoadLibrary).
//! 2. Parse the PE export table to find each function's RVA.
//! 3. Get the in-memory base of the already-loaded ntdll.dll.
//! 4. Compare the first 16 bytes of each function: disk vs memory.
//! 5. Classify any differences by hook type.

use sentinel_core::error::SentinelError;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::*;
use windows::core::w;

/// Number of bytes to compare at the start of each function.
const COMPARE_BYTES: usize = 16;

/// Critical ntdll functions -- injection/evasion primitives.
const CRITICAL_FUNCTIONS: &[&str] = &[
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtCreateThreadEx",
    "NtQueueApcThread",
    "NtMapViewOfSection",
    "NtProtectVirtualMemory",
    "NtCreateSection",
    "LdrLoadDll",
    "NtResumeThread",
    "NtSetContextThread",
];

// ── Public types ────────────────────────────────────────────────────────────

/// Result of checking one NTDLL function for hooks.
#[derive(Debug, Clone)]
pub struct NtdllHookResult {
    pub function_name: String,
    pub is_hooked:     bool,
    pub disk_bytes:    Vec<u8>,
    pub memory_bytes:  Vec<u8>,
    pub hook_type:     Option<HookType>,
}

/// Classification of the detected hook.
#[derive(Debug, Clone)]
pub enum HookType {
    /// JMP rel32 or JMP [addr] at function start (inline hook).
    InlineJmp,
    /// MOV RAX, addr; JMP RAX (trampoline).
    Trampoline,
    /// INT3 breakpoint (debugger or software hook).
    Breakpoint,
    /// Modification that does not match a known pattern.
    Unknown,
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Check NTDLL integrity for the current process.
///
/// Reads ntdll.dll from disk and compares critical function prologues with
/// the in-memory copy loaded in this process.
pub fn check_ntdll_hooks() -> Vec<NtdllHookResult> {
    let disk_ntdll = match std::fs::read(r"C:\Windows\System32\ntdll.dll") {
        Ok(data) => data,
        Err(_) => return Vec::new(),
    };

    // SAFETY: GetModuleHandleW returns the base address of the already-loaded
    // ntdll.dll in our process. ntdll is always loaded first and never unloaded.
    let mem_base = unsafe {
        match GetModuleHandleW(w!("ntdll.dll")) {
            Ok(h) => h.0 as usize,
            Err(_) => return Vec::new(),
        }
    };

    let exports = match parse_exports(&disk_ntdll) {
        Some(e) => e,
        None => return Vec::new(),
    };

    let mut results = Vec::new();

    for &func_name in CRITICAL_FUNCTIONS {
        let rva = match exports.iter().find(|(name, _)| name == func_name) {
            Some((_, rva)) => *rva,
            None => continue,
        };

        // Disk bytes at the function's RVA (converted from RVA to file offset).
        let file_offset = match rva_to_file_offset(&disk_ntdll, rva) {
            Some(off) => off,
            None => continue,
        };

        if file_offset + COMPARE_BYTES > disk_ntdll.len() {
            continue;
        }
        let disk_bytes = disk_ntdll[file_offset..file_offset + COMPARE_BYTES].to_vec();

        // Memory bytes at mem_base + RVA.
        let mem_addr = mem_base + rva as usize;
        let memory_bytes = unsafe {
            // SAFETY: We are reading from our own process's address space.
            // ntdll is always mapped and the RVA is within its image.
            let ptr = mem_addr as *const u8;
            std::slice::from_raw_parts(ptr, COMPARE_BYTES).to_vec()
        };

        let is_hooked = disk_bytes != memory_bytes;
        let hook_type = if is_hooked {
            Some(classify_hook(&memory_bytes))
        } else {
            None
        };

        results.push(NtdllHookResult {
            function_name: func_name.to_string(),
            is_hooked,
            disk_bytes,
            memory_bytes,
            hook_type,
        });
    }

    results
}

/// Check NTDLL integrity for a remote process.
///
/// Opens the target process with VM_READ access and compares ntdll function
/// prologues against the on-disk copy.
pub fn check_ntdll_hooks_remote(pid: u32) -> Result<Vec<NtdllHookResult>, SentinelError> {
    let disk_ntdll = std::fs::read(r"C:\Windows\System32\ntdll.dll")
        .map_err(|e| SentinelError::Platform(format!("read ntdll.dll from disk: {e}")))?;

    // We need to find ntdll's base in the remote process. We use the same
    // base as our own process -- ntdll is mapped at the same address in all
    // processes on the same boot session (ASLR is per-boot, not per-process
    // for ntdll).
    // SAFETY: GetModuleHandleW for ntdll in our own process.
    let mem_base = unsafe {
        GetModuleHandleW(w!("ntdll.dll"))
            .map_err(|e| SentinelError::Platform(format!("GetModuleHandleW: {e}")))?
            .0 as usize
    };

    // SAFETY: OpenProcess with valid pid; result checked.
    let handle = unsafe {
        OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)
            .map_err(|e| SentinelError::Platform(format!("OpenProcess({pid}): {e}")))?
    };

    let exports = parse_exports(&disk_ntdll)
        .ok_or_else(|| SentinelError::Platform("failed to parse ntdll exports".into()))?;

    let mut results = Vec::new();

    for &func_name in CRITICAL_FUNCTIONS {
        let rva = match exports.iter().find(|(name, _)| name == func_name) {
            Some((_, rva)) => *rva,
            None => continue,
        };

        let file_offset = match rva_to_file_offset(&disk_ntdll, rva) {
            Some(off) => off,
            None => continue,
        };

        if file_offset + COMPARE_BYTES > disk_ntdll.len() {
            continue;
        }
        let disk_bytes = disk_ntdll[file_offset..file_offset + COMPARE_BYTES].to_vec();

        // Read from remote process memory.
        let mem_addr = mem_base + rva as usize;
        let mut memory_bytes = vec![0u8; COMPARE_BYTES];
        let mut bytes_read: usize = 0;

        // SAFETY: ReadProcessMemory reads from the target process. Handle is
        // valid, mem_addr points within ntdll's image in the target process.
        let ok = unsafe {
            ReadProcessMemory(
                handle,
                mem_addr as *const _,
                memory_bytes.as_mut_ptr() as *mut _,
                COMPARE_BYTES,
                Some(&mut bytes_read),
            )
        };

        if ok.is_err() || bytes_read < COMPARE_BYTES {
            continue; // ERROR_PARTIAL_COPY or access denied.
        }

        let is_hooked = disk_bytes != memory_bytes;
        let hook_type = if is_hooked {
            Some(classify_hook(&memory_bytes))
        } else {
            None
        };

        results.push(NtdllHookResult {
            function_name: func_name.to_string(),
            is_hooked,
            disk_bytes,
            memory_bytes,
            hook_type,
        });
    }

    // SAFETY: Closing a valid handle we opened above.
    unsafe { let _ = CloseHandle(handle); }

    Ok(results)
}

// ── PE export table parsing ─────────────────────────────────────────────────

/// Exported function: (name, RVA).
type ExportEntry = (String, u32);

/// Parse the PE export directory from a raw PE file and return (name, rva) pairs.
fn parse_exports(pe: &[u8]) -> Option<Vec<ExportEntry>> {
    if pe.len() < 0x40 {
        return None;
    }

    // DOS header: e_lfanew at offset 0x3C.
    let pe_off = read_u32(pe, 0x3C) as usize;
    if pe_off + 0x88 > pe.len() {
        return None;
    }

    // Validate PE signature.
    if pe[pe_off..pe_off + 4] != [0x50, 0x45, 0x00, 0x00] {
        return None;
    }

    // Optional header starts at pe_off + 24.
    let opt_off = pe_off + 24;
    let magic = read_u16(pe, opt_off);

    // Export directory RVA and size are in DataDirectory[0].
    // For PE32+: DataDirectory starts at optional header + 112.
    // For PE32:  DataDirectory starts at optional header + 96.
    let dd_off = opt_off + if magic == 0x20B { 112 } else { 96 };
    let export_rva = read_u32(pe, dd_off) as usize;
    let export_size = read_u32(pe, dd_off + 4) as usize;

    if export_rva == 0 || export_size == 0 {
        return None;
    }

    let export_file_off = rva_to_file_offset_raw(pe, pe_off, export_rva as u32)? as usize;

    if export_file_off + 40 > pe.len() {
        return None;
    }

    let num_names = read_u32(pe, export_file_off + 24) as usize;
    let addr_of_functions_rva = read_u32(pe, export_file_off + 28);
    let addr_of_names_rva = read_u32(pe, export_file_off + 32);
    let addr_of_ordinals_rva = read_u32(pe, export_file_off + 36);

    let fn_table = rva_to_file_offset_raw(pe, pe_off, addr_of_functions_rva)? as usize;
    let name_table = rva_to_file_offset_raw(pe, pe_off, addr_of_names_rva)? as usize;
    let ord_table = rva_to_file_offset_raw(pe, pe_off, addr_of_ordinals_rva)? as usize;

    let mut exports = Vec::with_capacity(num_names);

    for i in 0..num_names {
        // Name pointer (RVA).
        let name_rva_off = name_table + i * 4;
        if name_rva_off + 4 > pe.len() {
            break;
        }
        let name_rva = read_u32(pe, name_rva_off);
        let name_file_off = match rva_to_file_offset_raw(pe, pe_off, name_rva) {
            Some(o) => o as usize,
            None => continue,
        };

        // Read null-terminated ASCII name.
        let name = read_cstring(pe, name_file_off);
        if name.is_empty() {
            continue;
        }

        // Ordinal.
        let ord_off = ord_table + i * 2;
        if ord_off + 2 > pe.len() {
            break;
        }
        let ordinal = read_u16(pe, ord_off) as usize;

        // Function RVA.
        let fn_off = fn_table + ordinal * 4;
        if fn_off + 4 > pe.len() {
            break;
        }
        let func_rva = read_u32(pe, fn_off);

        // Skip forwarder RVAs (they point inside the export directory).
        let func_rva_usize = func_rva as usize;
        if func_rva_usize >= export_rva && func_rva_usize < export_rva + export_size {
            continue;
        }

        exports.push((name, func_rva));
    }

    Some(exports)
}

/// Convert an RVA to a file offset using the PE section headers.
fn rva_to_file_offset(pe: &[u8], rva: u32) -> Option<usize> {
    let pe_off = read_u32(pe, 0x3C) as usize;
    rva_to_file_offset_raw(pe, pe_off, rva)
}

fn rva_to_file_offset_raw(pe: &[u8], pe_off: usize, rva: u32) -> Option<usize> {
    let num_sections = read_u16(pe, pe_off + 6) as usize;
    let opt_header_size = read_u16(pe, pe_off + 20) as usize;
    let sections_off = pe_off + 24 + opt_header_size;

    for i in 0..num_sections {
        let sec = sections_off + i * 40;
        if sec + 40 > pe.len() {
            break;
        }
        let virt_addr = read_u32(pe, sec + 12);
        let virt_size = read_u32(pe, sec + 8);
        let raw_data = read_u32(pe, sec + 20);

        if rva >= virt_addr && rva < virt_addr + virt_size {
            return Some((rva - virt_addr + raw_data) as usize);
        }
    }

    None
}

// ── Hook classification ─────────────────────────────────────────────────────

fn classify_hook(bytes: &[u8]) -> HookType {
    if bytes.is_empty() {
        return HookType::Unknown;
    }

    // INT3 breakpoint.
    if bytes[0] == 0xCC {
        return HookType::Breakpoint;
    }

    // JMP rel32 (E9 xx xx xx xx).
    if bytes[0] == 0xE9 {
        return HookType::InlineJmp;
    }

    // JMP [rip+disp32] (FF 25 xx xx xx xx).
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0x25 {
        return HookType::InlineJmp;
    }

    // MOV RAX, imm64; JMP RAX (48 B8 xx*8 FF E0).
    if bytes.len() >= 12 && bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0xFF && bytes[11] == 0xE0 {
        return HookType::Trampoline;
    }

    // PUSH imm32; RET (68 xx xx xx xx C3) -- 32-bit trampoline.
    if bytes.len() >= 6 && bytes[0] == 0x68 && bytes[5] == 0xC3 {
        return HookType::Trampoline;
    }

    HookType::Unknown
}

// ── Utility readers ─────────────────────────────────────────────────────────

fn read_u16(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(buf[offset..offset + 2].try_into().unwrap_or([0; 2]))
}

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap_or([0; 4]))
}

fn read_cstring(buf: &[u8], offset: usize) -> String {
    let end = buf[offset..]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(256)
        .min(256);
    String::from_utf8_lossy(&buf[offset..offset + end]).to_string()
}
