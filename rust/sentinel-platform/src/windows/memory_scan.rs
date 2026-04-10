//! VAD tree walk + process hollowing detection (T1055, T1055.012).
//!
//! Uses `VirtualQueryEx` to enumerate all committed memory regions in a target
//! process and flags suspicious patterns:
//! - Anonymous executable memory (RWX/RX without file backing) -- shellcode injection
//! - Process hollowing: in-memory PE header differs from on-disk image
//! - Heap memory marked executable (unusual outside JIT compilers)

use sentinel_core::error::SentinelError;
use std::mem::{size_of, zeroed};
use sysinfo::{ProcessRefreshKind, RefreshKind, System};
use windows::Win32::Foundation::{CloseHandle, HANDLE, MAX_PATH};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::*;
use windows::Win32::System::ProcessStatus::GetMappedFileNameW;
use windows::Win32::System::Threading::*;

/// Maximum number of regions to enumerate per process (safety limit).
const MAX_REGIONS: usize = 50_000;

/// Bytes to read for PE header comparison.
const PE_HEADER_SIZE: usize = 0x1000;

// -- Public types -------------------------------------------------------------

/// A memory region with analysis metadata.
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base:        usize,
    pub size:        usize,
    pub protect:     u32,
    pub mem_type:    u32,
    pub state:       u32,
    pub mapped_file: Option<String>,
}

/// Result of scanning a process's memory.
#[derive(Debug, Clone)]
pub struct MemoryScanResult {
    pub pid:           u32,
    pub image_path:    String,
    pub total_regions: usize,
    pub suspicious:    Vec<MemoryAnomaly>,
}

/// Detected memory anomaly.
#[derive(Debug, Clone)]
pub enum MemoryAnomaly {
    /// Anonymous executable memory -- no file backing + EXECUTE permission.
    /// Strong indicator of shellcode injection.
    AnonymousExecutable {
        base:    usize,
        size:    usize,
        protect: u32,
    },
    /// PE header in memory differs from PE on disk -- process hollowing.
    ProcessHollowing {
        base:      usize,
        disk_path: String,
        mismatch:  String,
    },
    /// Heap memory marked as executable -- suspicious unless JIT compiler.
    ExecutableHeap {
        base: usize,
        size: usize,
    },
}

// -- Public API ---------------------------------------------------------------

/// Scan a single process for memory anomalies.
///
/// Requires `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` access on the target.
pub fn scan_process(pid: u32) -> Result<MemoryScanResult, SentinelError> {
    let image_path = process_image_path(pid).unwrap_or_default();

    // SAFETY: OpenProcess is safe when given a valid PID; we check the result.
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid,
        )
        .map_err(|e| SentinelError::Platform(format!("OpenProcess({pid}): {e}")))?
    };

    let regions = enumerate_regions(handle);
    let total_regions = regions.len();
    let mut suspicious = Vec::new();

    for region in &regions {
        // Skip non-committed regions.
        if region.state != MEM_COMMIT.0 {
            continue;
        }

        let is_executable = is_exec_protect(region.protect);

        // 1. Anonymous executable memory (MEM_PRIVATE + exec + no mapped file).
        if is_executable
            && region.mem_type == MEM_PRIVATE.0
            && region.mapped_file.is_none()
        {
            suspicious.push(MemoryAnomaly::AnonymousExecutable {
                base:    region.base,
                size:    region.size,
                protect: region.protect,
            });
        }

        // 2. Executable heap -- MEM_PRIVATE + exec + large region (>= 64 KB).
        //    Heuristic: heap allocations are typically MEM_PRIVATE and large.
        if is_executable
            && region.mem_type == MEM_PRIVATE.0
            && region.size >= 0x10000
            && region.mapped_file.is_none()
        {
            suspicious.push(MemoryAnomaly::ExecutableHeap {
                base: region.base,
                size: region.size,
            });
        }
    }

    // 3. Process hollowing: compare first MEM_IMAGE region against on-disk PE.
    if !image_path.is_empty() {
        if let Some(first_image) = regions.iter().find(|r| r.mem_type == MEM_IMAGE.0) {
            if let Some(anomaly) = check_hollowing(handle, &image_path, first_image.base) {
                suspicious.push(anomaly);
            }
        }
    }

    // SAFETY: Closing a valid handle we opened above.
    unsafe { let _ = CloseHandle(handle); }

    Ok(MemoryScanResult {
        pid,
        image_path,
        total_regions,
        suspicious,
    })
}

/// Scan all running processes and return anomalies.
/// Skips system processes (PID 0, PID 4) and processes we cannot open.
pub fn scan_all_processes() -> Vec<MemoryScanResult> {
    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::new()),
    );
    sys.refresh_all();

    sys.processes()
        .keys()
        .filter_map(|&pid| {
            let pid_u32 = usize::from(pid) as u32;
            // Skip System Idle (0) and System (4) processes.
            if pid_u32 == 0 || pid_u32 == 4 {
                return None;
            }
            scan_process(pid_u32).ok()
        })
        .filter(|r| !r.suspicious.is_empty())
        .collect()
}

// -- Internal helpers ---------------------------------------------------------

/// Enumerate all committed memory regions using `VirtualQueryEx`.
fn enumerate_regions(handle: HANDLE) -> Vec<MemoryRegion> {
    let mut regions = Vec::new();
    let mut addr: usize = 0;

    loop {
        if regions.len() >= MAX_REGIONS {
            break;
        }

        // SAFETY: VirtualQueryEx reads memory info into the provided struct.
        // The handle is valid (opened by us) and addr is within the process
        // address space or past the end (which returns 0).
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
        let ret = unsafe {
            VirtualQueryEx(
                handle,
                Some(addr as *const _),
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if ret == 0 {
            break;
        }

        let mapped_file = if mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED {
            get_mapped_filename(handle, mbi.BaseAddress as usize)
        } else {
            None
        };

        regions.push(MemoryRegion {
            base:     mbi.BaseAddress as usize,
            size:     mbi.RegionSize,
            protect:  mbi.Protect.0,
            mem_type: mbi.Type.0,
            state:    mbi.State.0,
            mapped_file,
        });

        // Advance past this region.
        addr = mbi.BaseAddress as usize + mbi.RegionSize;
        // Guard against overflow (top of address space).
        if addr <= mbi.BaseAddress as usize {
            break;
        }
    }

    regions
}

/// Check for process hollowing by comparing in-memory PE header with on-disk image.
fn check_hollowing(handle: HANDLE, image_path: &str, base: usize) -> Option<MemoryAnomaly> {
    // Read on-disk PE header.
    let disk_bytes = std::fs::read(image_path).ok()?;
    if disk_bytes.len() < PE_HEADER_SIZE {
        return None;
    }
    let disk_header = &disk_bytes[..PE_HEADER_SIZE];

    // Read in-memory PE header.
    let mut mem_header = vec![0u8; PE_HEADER_SIZE];
    let mut bytes_read: usize = 0;

    // SAFETY: ReadProcessMemory reads from the target process into our buffer.
    // handle is valid, base points to the image base, buffer is properly sized.
    let ok = unsafe {
        ReadProcessMemory(
            handle,
            base as *const _,
            mem_header.as_mut_ptr() as *mut _,
            PE_HEADER_SIZE,
            Some(&mut bytes_read),
        )
    };

    if ok.is_err() || bytes_read < 0x200 {
        return None; // Could not read enough -- ERROR_PARTIAL_COPY or access denied.
    }

    // Validate DOS signature ("MZ").
    if disk_header[0..2] != [0x4D, 0x5A] || mem_header[0..2] != [0x4D, 0x5A] {
        return None; // Not a PE -- skip.
    }

    // PE signature offset is at offset 0x3C (e_lfanew).
    let disk_pe_off = u32::from_le_bytes(disk_header[0x3C..0x40].try_into().ok()?) as usize;
    let mem_pe_off = u32::from_le_bytes(mem_header[0x3C..0x40].try_into().ok()?) as usize;

    if disk_pe_off + 0x80 > PE_HEADER_SIZE || mem_pe_off + 0x80 > PE_HEADER_SIZE {
        return None; // PE header extends past our read window.
    }

    // Validate PE signatures ("PE\0\0").
    if disk_header[disk_pe_off..disk_pe_off + 4] != [0x50, 0x45, 0x00, 0x00] {
        return None;
    }
    if mem_header[mem_pe_off..mem_pe_off + 4] != [0x50, 0x45, 0x00, 0x00] {
        return None;
    }

    let mut mismatches = Vec::new();

    // Optional header starts at PE offset + 24 (after COFF header).
    let disk_opt = disk_pe_off + 24;
    let mem_opt = mem_pe_off + 24;

    // Check if it is PE32+ (0x20B) or PE32 (0x10B).
    let disk_magic = u16::from_le_bytes(disk_header[disk_opt..disk_opt + 2].try_into().ok()?);
    let mem_magic = u16::from_le_bytes(mem_header[mem_opt..mem_opt + 2].try_into().ok()?);

    if disk_magic != mem_magic {
        mismatches.push("OptionalHeader.Magic");
    }

    // AddressOfEntryPoint: offset 16 from optional header start.
    let disk_ep = read_u32(disk_header, disk_opt + 16);
    let mem_ep = read_u32(&mem_header, mem_opt + 16);
    if disk_ep != mem_ep {
        mismatches.push("AddressOfEntryPoint");
    }

    // SizeOfImage: offset 56 from optional header start.
    let disk_soi = read_u32(disk_header, disk_opt + 56);
    let mem_soi = read_u32(&mem_header, mem_opt + 56);
    if disk_soi != mem_soi {
        mismatches.push("SizeOfImage");
    }

    // NumberOfSections: COFF header offset + 2 (relative to PE sig).
    let disk_sections = read_u16(disk_header, disk_pe_off + 6);
    let mem_sections = read_u16(&mem_header, mem_pe_off + 6);
    if disk_sections != mem_sections {
        mismatches.push("NumberOfSections");
    }

    // ImageBase: offset 24 from optional header for PE32+, 28 for PE32.
    let ib_offset = if disk_magic == 0x20B { 24 } else { 28 };
    let disk_ib = read_u64_or_u32(disk_header, disk_opt + ib_offset, disk_magic);
    let mem_ib = read_u64_or_u32(&mem_header, mem_opt + ib_offset, mem_magic);
    if disk_ib != mem_ib {
        mismatches.push("ImageBase");
    }

    if mismatches.is_empty() {
        None
    } else {
        Some(MemoryAnomaly::ProcessHollowing {
            base,
            disk_path: image_path.to_string(),
            mismatch: mismatches.join(", "),
        })
    }
}

/// Return true if the protection flags include any EXECUTE variant.
fn is_exec_protect(protect: u32) -> bool {
    const EXEC_FLAGS: u32 = PAGE_EXECUTE.0
        | PAGE_EXECUTE_READ.0
        | PAGE_EXECUTE_READWRITE.0
        | PAGE_EXECUTE_WRITECOPY.0;
    protect & EXEC_FLAGS != 0
}

/// Get the mapped file name for a memory region (if any).
fn get_mapped_filename(handle: HANDLE, base: usize) -> Option<String> {
    let mut buf = [0u16; MAX_PATH as usize];
    // SAFETY: GetMappedFileNameW writes into our buffer; handle and base are valid.
    let len = unsafe { GetMappedFileNameW(handle, base as *const _, &mut buf) };
    if len == 0 {
        None
    } else {
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }
}

/// Resolve a process's image path via `QueryFullProcessImageNameW`.
fn process_image_path(pid: u32) -> Option<String> {
    // SAFETY: OpenProcess + QueryFullProcessImageNameW are safe with valid pid.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 1024];
        let mut size = 1024u32;
        let ok = QueryFullProcessImageNameW(
            handle,
            Default::default(),
            windows::core::PWSTR(buf.as_mut_ptr()),
            &mut size,
        )
        .is_ok();
        let _ = CloseHandle(handle);
        if ok && size > 0 {
            Some(String::from_utf16_lossy(&buf[..size as usize]))
        } else {
            None
        }
    }
}

fn read_u16(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(buf[offset..offset + 2].try_into().unwrap_or([0; 2]))
}

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap_or([0; 4]))
}

fn read_u64_or_u32(buf: &[u8], offset: usize, magic: u16) -> u64 {
    if magic == 0x20B {
        // PE32+ -- 8-byte ImageBase
        u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap_or([0; 8]))
    } else {
        // PE32 -- 4-byte ImageBase
        read_u32(buf, offset) as u64
    }
}
