//! YARA-based process memory scanner (T1055, T1059, T1003).
//!
//! Scans committed executable memory regions of running processes against
//! compiled YARA rules using the pure-Rust [`yara_x`] engine.  Works on top
//! of the same `VirtualQueryEx` enumeration pattern used by [`super::memory_scan`].
//!
//! # Usage
//!
//! ```rust,ignore
//! use arqenor_platform::windows::yara_scan::YaraScanner;
//! use arqenor_platform::windows::yara_rules::EMBEDDED_RULES;
//!
//! let scanner = YaraScanner::from_source(EMBEDDED_RULES)?;
//! let result  = scanner.scan_process(1234)?;
//! for m in &result.matches {
//!     println!("{}: {} @ 0x{:x}", m.pid, m.rule_name, m.region_base);
//! }
//! ```

use std::mem::{size_of, zeroed};
use std::path::Path;

use sysinfo::{ProcessRefreshKind, RefreshKind, System};
use tracing::{debug, warn};
use windows::Win32::Foundation::{CloseHandle, HANDLE, MAX_PATH};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::*;
use windows::Win32::System::Threading::*;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A YARA match found in process memory.
#[derive(Debug, Clone)]
pub struct YaraMatch {
    /// Name of the matched YARA rule.
    pub rule_name: String,
    /// Tags attached to the rule (may be empty).
    pub rule_tags: Vec<String>,
    /// Target process ID.
    pub pid: u32,
    /// Base address of the memory region that matched.
    pub region_base: usize,
    /// Size (bytes) of the region that was scanned.
    pub region_size: usize,
    /// `description` metadata field from the rule, if present.
    pub description: Option<String>,
    /// `severity` metadata field from the rule, if present.
    pub severity: Option<String>,
    /// `attack_id` (MITRE ATT&CK) metadata field from the rule, if present.
    pub attack_id: Option<String>,
}

/// Aggregate result of scanning a single process.
#[derive(Debug, Clone)]
pub struct YaraScanResult {
    /// Target process ID.
    pub pid: u32,
    /// Full image path of the process (empty if unavailable).
    pub image_path: String,
    /// All YARA matches found across the process's memory regions.
    pub matches: Vec<YaraMatch>,
    /// Number of memory regions scanned.
    pub regions_scanned: usize,
    /// Total bytes read and scanned.
    pub bytes_scanned: usize,
}

/// Errors that can occur during YARA scanning.
#[derive(Debug)]
pub enum YaraScanError {
    /// YARA rule compilation failed.
    CompileError(String),
    /// Could not open the target process.
    ProcessOpenFailed(u32),
    /// `ReadProcessMemory` failed for a region (pid, base).
    ReadMemoryFailed(u32, usize),
    /// Generic I/O error (e.g. reading rule files from disk).
    IoError(std::io::Error),
}

impl std::fmt::Display for YaraScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CompileError(msg) => write!(f, "YARA compile error: {msg}"),
            Self::ProcessOpenFailed(pid) => write!(f, "cannot open process {pid}"),
            Self::ReadMemoryFailed(pid, base) => {
                write!(f, "ReadProcessMemory failed: pid={pid} base=0x{base:x}")
            }
            Self::IoError(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for YaraScanError {}

impl From<std::io::Error> for YaraScanError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of regions to enumerate per process (safety limit).
const MAX_REGIONS: usize = 50_000;

/// Skip regions larger than 100 MB to avoid scanning oversized JIT heaps.
const MAX_REGION_SIZE: usize = 100 * 1024 * 1024;

/// Protection flags that indicate executable memory.
const EXEC_FLAGS: u32 = PAGE_EXECUTE.0
    | PAGE_EXECUTE_READ.0
    | PAGE_EXECUTE_READWRITE.0
    | PAGE_EXECUTE_WRITECOPY.0;

// ---------------------------------------------------------------------------
// YaraScanner
// ---------------------------------------------------------------------------

/// Holds compiled YARA rules and exposes process-scanning methods.
pub struct YaraScanner {
    rules: yara_x::Rules,
}

impl YaraScanner {
    /// Compile rules from every `.yar` / `.yara` file in `dir`.
    ///
    /// Invalid individual rule files are skipped with a warning rather than
    /// aborting the entire compilation so that one bad rule does not prevent
    /// scanning.
    pub fn from_rules_dir(dir: &Path) -> Result<Self, YaraScanError> {
        let mut compiler = yara_x::Compiler::new();
        let mut loaded = 0u32;

        for entry in walkdir::WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            match path.extension().and_then(|e| e.to_str()) {
                Some("yar" | "yara") => {}
                _ => continue,
            }

            let source = match std::fs::read_to_string(path) {
                Ok(s) => s,
                Err(e) => {
                    warn!("skipping unreadable rule file {}: {e}", path.display());
                    continue;
                }
            };

            if let Err(e) = compiler.add_source(source.as_str()) {
                warn!(
                    "skipping rule file {} (compile error): {e}",
                    path.display()
                );
                continue;
            }

            loaded += 1;
        }

        if loaded == 0 {
            return Err(YaraScanError::CompileError(format!(
                "no valid YARA rule files found in {}",
                dir.display()
            )));
        }

        debug!("compiled {loaded} YARA rule files from {}", dir.display());
        let rules = compiler.build();
        Ok(Self { rules })
    }

    /// Compile rules from a single source string (e.g. embedded rules).
    pub fn from_source(source: &str) -> Result<Self, YaraScanError> {
        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source(source)
            .map_err(|e| YaraScanError::CompileError(e.to_string()))?;
        let rules = compiler.build();
        Ok(Self { rules })
    }

    /// Scan a single process's executable memory regions.
    ///
    /// Opens the process with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`,
    /// enumerates committed executable regions via `VirtualQueryEx`, reads each
    /// region with `ReadProcessMemory`, and runs the YARA ruleset against the
    /// bytes.
    pub fn scan_process(&self, pid: u32) -> Result<YaraScanResult, YaraScanError> {
        let image_path = process_image_path(pid).unwrap_or_default();

        // SAFETY: OpenProcess with valid PID; result is checked.
        let handle = unsafe {
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
                .map_err(|_| YaraScanError::ProcessOpenFailed(pid))?
        };

        let result = self.scan_with_handle(pid, &image_path, handle);

        // SAFETY: closing a handle we successfully opened.
        unsafe {
            let _ = CloseHandle(handle);
        }

        result
    }

    /// Scan all running processes.
    ///
    /// Skips PID 0 (System Idle), PID 4 (System), and the current process.
    /// Processes that cannot be opened (access denied) are silently skipped.
    pub fn scan_all(&self) -> Vec<YaraScanResult> {
        let mut sys =
            System::new_with_specifics(RefreshKind::new().with_processes(ProcessRefreshKind::new()));
        sys.refresh_all();

        let self_pid = std::process::id();

        sys.processes()
            .keys()
            .filter_map(|&pid| {
                let pid_u32 = usize::from(pid) as u32;
                if pid_u32 == 0 || pid_u32 == 4 || pid_u32 == self_pid {
                    return None;
                }
                match self.scan_process(pid_u32) {
                    Ok(r) if !r.matches.is_empty() => Some(r),
                    Ok(_) => None, // no matches -- omit from results
                    Err(e) => {
                        debug!("skipping pid {pid_u32}: {e}");
                        None
                    }
                }
            })
            .collect()
    }

    // -- private helpers ----------------------------------------------------

    /// Core scanning logic operating on an already-opened process handle.
    fn scan_with_handle(
        &self,
        pid: u32,
        image_path: &str,
        handle: HANDLE,
    ) -> Result<YaraScanResult, YaraScanError> {
        let mut all_matches = Vec::new();
        let mut regions_scanned: usize = 0;
        let mut bytes_scanned: usize = 0;
        let mut addr: usize = 0;
        let mut region_count: usize = 0;

        loop {
            if region_count >= MAX_REGIONS {
                break;
            }

            // SAFETY: VirtualQueryEx reads memory info; handle is valid.
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

            region_count += 1;

            // Advance past this region (do this early to avoid infinite loops).
            let next_addr = mbi.BaseAddress as usize + mbi.RegionSize;
            // Guard against address-space overflow at the top of the range.
            if next_addr <= addr {
                break;
            }
            addr = next_addr;

            // Only scan committed regions with an EXECUTE protection bit.
            if mbi.State != MEM_COMMIT {
                continue;
            }
            if mbi.Protect.0 & EXEC_FLAGS == 0 {
                continue;
            }

            let region_base = mbi.BaseAddress as usize;
            let region_size = mbi.RegionSize;

            // Skip oversized regions (large JIT heaps, GPU-mapped buffers).
            if region_size > MAX_REGION_SIZE {
                debug!(
                    "pid {pid}: skipping oversized region 0x{region_base:x} ({} MB)",
                    region_size / (1024 * 1024)
                );
                continue;
            }

            // Read the region's bytes into a local buffer.
            let buf = match read_region(handle, region_base, region_size) {
                Ok(b) => b,
                Err(_) => {
                    // ERROR_PARTIAL_COPY or access denied -- skip this region.
                    debug!("pid {pid}: ReadProcessMemory failed for 0x{region_base:x}");
                    continue;
                }
            };

            if buf.is_empty() {
                continue;
            }

            regions_scanned += 1;
            bytes_scanned += buf.len();

            // Run YARA rules against the buffer.
            let mut scanner = yara_x::Scanner::new(&self.rules);
            let scan_results = match scanner.scan(&buf) {
                Ok(r) => r,
                Err(e) => {
                    warn!("pid {pid}: YARA scan error on region 0x{region_base:x}: {e}");
                    continue;
                }
            };

            for rule in scan_results.matching_rules() {
                let mut description: Option<String> = None;
                let mut severity: Option<String> = None;
                let mut attack_id: Option<String> = None;

                for (key, value) in rule.metadata() {
                    let val_str = format!("{value:?}");
                    match key {
                        "description" => description = Some(val_str),
                        "severity" => severity = Some(val_str),
                        "attack_id" => attack_id = Some(val_str),
                        _ => {}
                    }
                }

                all_matches.push(YaraMatch {
                    rule_name: rule.identifier().to_string(),
                    rule_tags: rule
                        .tags()
                        .map(|t| t.identifier().to_string())
                        .collect(),
                    pid,
                    region_base,
                    region_size: buf.len(),
                    description,
                    severity,
                    attack_id,
                });
            }
        }

        Ok(YaraScanResult {
            pid,
            image_path: image_path.to_string(),
            matches: all_matches,
            regions_scanned,
            bytes_scanned,
        })
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Read the contents of a memory region.  If `ReadProcessMemory` returns a
/// partial read (ERROR_PARTIAL_COPY), we return whatever bytes were read
/// rather than failing -- the region may be partially accessible.
fn read_region(
    handle: HANDLE,
    base: usize,
    size: usize,
) -> Result<Vec<u8>, YaraScanError> {
    let mut buf = vec![0u8; size];
    let mut bytes_read: usize = 0;

    // SAFETY: handle is valid, base is within the target's address space,
    // and buf is properly sized.
    let result = unsafe {
        ReadProcessMemory(
            handle,
            base as *const _,
            buf.as_mut_ptr() as *mut _,
            size,
            Some(&mut bytes_read),
        )
    };

    if result.is_ok() {
        buf.truncate(bytes_read);
        Ok(buf)
    } else if bytes_read > 0 {
        // Partial read (ERROR_PARTIAL_COPY) -- scan what we got.
        debug!(
            "partial read at 0x{base:x}: got {bytes_read}/{size} bytes"
        );
        buf.truncate(bytes_read);
        Ok(buf)
    } else {
        Err(YaraScanError::ReadMemoryFailed(
            std::process::id(),
            base,
        ))
    }
}

/// Resolve a process's full image path via `QueryFullProcessImageNameW`.
fn process_image_path(pid: u32) -> Option<String> {
    // SAFETY: OpenProcess + QueryFullProcessImageNameW with valid pid.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; MAX_PATH as usize];
        let mut size = buf.len() as u32;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows::yara_rules::EMBEDDED_RULES;

    #[test]
    fn embedded_rules_compile() {
        // Verify that the embedded rule set compiles without errors.
        let scanner = YaraScanner::from_source(EMBEDDED_RULES);
        assert!(
            scanner.is_ok(),
            "embedded rules failed to compile: {:?}",
            scanner.err()
        );
    }

    #[test]
    fn scan_self_does_not_panic() {
        // Scanning our own process should succeed (no matches expected).
        let scanner = YaraScanner::from_source(EMBEDDED_RULES).expect("compile");
        let result = scanner.scan_process(std::process::id());
        // We may or may not be able to open ourselves depending on
        // privilege level, but this must not panic.
        if let Ok(r) = result {
            assert_eq!(r.pid, std::process::id());
        }
    }

    #[test]
    fn from_source_bad_rule_returns_error() {
        let bad = "rule broken { condition: foo_undefined }";
        let result = YaraScanner::from_source(bad);
        assert!(result.is_err());
    }
}
