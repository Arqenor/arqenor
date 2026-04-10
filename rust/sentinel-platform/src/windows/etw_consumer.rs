//! Phase 2 — Windows ETW (Event Tracing for Windows) real-time consumer.
//!
//! Opens a single named session (`SENTINEL-ETW-v1`) and enables high-value
//! providers for threat-detection signals:
//!
//! | Provider                             | GUID data1  | Key events              |
//! |--------------------------------------|-------------|-------------------------|
//! | Microsoft-Windows-Kernel-Process     | 22FB2CD6    | 1=start, 2=stop, 5=load |
//! | Microsoft-Windows-PowerShell         | A0C1853B    | 4104=script-block       |
//! | Microsoft-Windows-Security-Auditing  | 54849625    | 4688=new proc, 4698=task|
//! | Microsoft-Windows-DNS-Client         | 1C95126E    | 3006=dns query          |
//! | Microsoft-Windows-WMI-Activity       | 1418EF04    | 5861=wmi query          |
//! | Microsoft-Windows-TaskScheduler      | DE7B24EA    | 106=task launch         |
//! | Microsoft-Windows-Kernel-Network     | 7DD42A49    | 12=TCP connect, 15=UDP  |
//! | Microsoft-Windows-Kernel-File        | EDD08927    | 12=create, 14=write     |
//! | Microsoft-Windows-Kernel-Registry    | 70EB4F03    | 1=key create, 3=val set |
//!
//! Architecture:
//!   StartTrace → EnableTraceEx2 × N → OpenTrace → ProcessTrace (dedicated thread)
//!
//! In windows-rs 0.52:
//!   - `CONTROLTRACE_HANDLE` — session control (StartTrace, EnableTraceEx2, ControlTrace)
//!   - `PROCESSTRACE_HANDLE` — trace consumption (OpenTrace, ProcessTrace, CloseTrace)
//!   - All ETW functions return `windows::core::Result<()>`
//!   - `ProcessTrace` takes `&[PROCESSTRACE_HANDLE]` (count inferred from slice)

use std::{
    mem,
    sync::{
        mpsc::{sync_channel, Receiver, SyncSender},
        OnceLock,
    },
    thread,
};

use windows::{
    core::{GUID, PCWSTR, PWSTR},
    Win32::{
        Foundation::ERROR_ALREADY_EXISTS,
        System::Diagnostics::Etw::{
            CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
            CONTROLTRACE_HANDLE, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW,
            EVENT_TRACE_PROPERTIES, PROCESSTRACE_HANDLE,
        },
    },
};

use sentinel_core::error::SentinelError;

// ── ETW flags (raw values to avoid feature-gate ambiguities) ──────────────────

const SESSION_NAME: &str = "SENTINEL-ETW-v1";

const WNODE_FLAG_TRACED_GUID: u32          = 0x0002_0000;
const EVENT_TRACE_REAL_TIME_MODE: u32        = 0x0000_0100;
const PROCESS_TRACE_MODE_REAL_TIME: u32      = 0x0000_0100;
const PROCESS_TRACE_MODE_EVENT_RECORD: u32   = 0x1000_0000;
const ENABLE_CODE: u32  = 1; // EVENT_CONTROL_CODE_ENABLE_PROVIDER
const TRACE_LEVEL_ALL: u8 = 5; // TRACE_LEVEL_VERBOSE

// ── Provider GUIDs ────────────────────────────────────────────────────────────

const PROVIDER_KERNEL_PROCESS: GUID = GUID {
    data1: 0x22FB2CD6, data2: 0x0E7B, data3: 0x422B,
    data4: [0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16],
};
const PROVIDER_POWERSHELL: GUID = GUID {
    data1: 0xA0C1853B, data2: 0x5C40, data3: 0x4B15,
    data4: [0x87, 0x66, 0x3C, 0xF1, 0xC5, 0x8F, 0x98, 0x5A],
};
const PROVIDER_SECURITY: GUID = GUID {
    data1: 0x54849625, data2: 0x5478, data3: 0x4994,
    data4: [0xA5, 0xBA, 0x3E, 0x3B, 0x03, 0x28, 0xC3, 0x0D],
};
const PROVIDER_DNS: GUID = GUID {
    data1: 0x1C95126E, data2: 0x7EEA, data3: 0x49A9,
    data4: [0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D],
};
const PROVIDER_WMI: GUID = GUID {
    data1: 0x1418EF04, data2: 0xB0B4, data3: 0x4623,
    data4: [0xBF, 0x7E, 0xD7, 0x4A, 0xB4, 0x7B, 0xBD, 0xAA],
};
const PROVIDER_TASKSCHEDULER: GUID = GUID {
    data1: 0xDE7B24EA, data2: 0x73C8, data3: 0x4A09,
    data4: [0x98, 0x5D, 0x5B, 0xDA, 0xDC, 0xFA, 0x90, 0x17],
};
const PROVIDER_KERNEL_NETWORK: GUID = GUID {
    data1: 0x7DD42A49, data2: 0x5329, data3: 0x4832,
    data4: [0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88],
};
const PROVIDER_KERNEL_FILE: GUID = GUID {
    data1: 0xEDD08927, data2: 0x9CC4, data3: 0x4E65,
    data4: [0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89],
};
const PROVIDER_KERNEL_REGISTRY: GUID = GUID {
    data1: 0x70EB4F03, data2: 0xC1DE, data3: 0x4F73,
    data4: [0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x54, 0x13, 0xBD],
};

const PROVIDERS: &[GUID] = &[
    PROVIDER_KERNEL_PROCESS,
    PROVIDER_POWERSHELL,
    PROVIDER_SECURITY,
    PROVIDER_DNS,
    PROVIDER_WMI,
    PROVIDER_TASKSCHEDULER,
    PROVIDER_KERNEL_NETWORK,
    PROVIDER_KERNEL_FILE,
    PROVIDER_KERNEL_REGISTRY,
];

// ── Global sender for the ETW callback thread ─────────────────────────────────

/// Written once at `EtwConsumer::start()`.  `SyncSender` is `Sync + Send`.
static ETW_TX: OnceLock<SyncSender<EtwEvent>> = OnceLock::new();

// ── Public event type ─────────────────────────────────────────────────────────

/// A raw ETW event forwarded from the real-time session callback.
///
/// The `user_data` payload is the raw provider-specific byte slice.
/// Higher-level consumers can use TDH (`TdhGetEventInformation`) to decode it.
#[derive(Debug, Clone)]
pub struct EtwEvent {
    /// Provider GUID as `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
    pub provider_guid: String,
    /// ETW event ID (e.g. `4104` for PowerShell script-block).
    pub event_id: u16,
    /// Process that emitted the event.
    pub pid: u32,
    /// Thread that emitted the event.
    pub tid: u32,
    /// Windows FILETIME (100-ns intervals since 1601-01-01 UTC).
    pub timestamp: i64,
    pub level:   u8,
    pub opcode:  u8,
    pub task:    u16,
    pub keyword: u64,
    /// Raw user-data bytes; schema depends on (provider, event_id).
    pub user_data: Vec<u8>,
    /// Static ATT&CK-tagged label derived from (provider, event_id).
    pub description: &'static str,
}

/// Map `(data1_hex_upper, event_id)` → description.
/// We only match on the first 8 chars of the GUID string (data1) — unique
/// across our provider set.
fn describe_event(guid_str: &str, event_id: u16) -> &'static str {
    // guid_str format: `{22FB2CD6-…}` → data1 occupies chars [1..9]
    let tag = guid_str.get(1..9).unwrap_or("");
    match (tag, event_id) {
        ("22FB2CD6", 1)    => "Kernel: process start",
        ("22FB2CD6", 2)    => "Kernel: process stop",
        ("22FB2CD6", 5)    => "Kernel: image load",
        ("A0C1853B", 4104) => "PowerShell: script-block execution [T1059.001]",
        ("54849625", 4688) => "Security: new process created [T1059]",
        ("54849625", 4698) => "Security: scheduled task created [T1053.005]",
        ("1C95126E", 3006) => "DNS: query sent [T1071.004]",
        ("1418EF04", 5861) => "WMI: activity/query [T1047]",
        ("DE7B24EA", 106)  => "TaskScheduler: task launched [T1053.005]",
        ("7DD42A49", 12)   => "Kernel-Network: TCP connect [T1071]",
        ("7DD42A49", 15)   => "Kernel-Network: UDP send [T1071]",
        ("EDD08927", 12)   => "Kernel-File: file create [T1005]",
        ("EDD08927", 14)   => "Kernel-File: file write [T1565]",
        ("70EB4F03", 1)    => "Kernel-Registry: key create [T1112]",
        ("70EB4F03", 3)    => "Kernel-Registry: value set [T1112]",
        _                  => "ETW event",
    }
}

// ── ETW callback (called from the ProcessTrace thread) ────────────────────────

unsafe extern "system" fn event_record_callback(record: *mut EVENT_RECORD) {
    let Some(tx) = ETW_TX.get() else { return };

    // SAFETY: `record` is valid for the duration of this callback invocation;
    // it is a pointer owned by the ETW runtime.
    let r = unsafe { &*record };

    let g = &r.EventHeader.ProviderId;
    let provider_guid = format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        g.data1, g.data2, g.data3,
        g.data4[0], g.data4[1],
        g.data4[2], g.data4[3], g.data4[4],
        g.data4[5], g.data4[6], g.data4[7],
    );

    let user_data = if r.UserDataLength > 0 && !r.UserData.is_null() {
        // SAFETY: ETW guarantees UserData points to UserDataLength valid bytes.
        unsafe {
            std::slice::from_raw_parts(
                r.UserData.cast::<u8>(),
                r.UserDataLength as usize,
            )
            .to_vec()
        }
    } else {
        Vec::new()
    };

    let event_id    = r.EventHeader.EventDescriptor.Id;
    let description = describe_event(&provider_guid, event_id);

    let ev = EtwEvent {
        provider_guid,
        event_id,
        pid:       r.EventHeader.ProcessId,
        tid:       r.EventHeader.ThreadId,
        timestamp: r.EventHeader.TimeStamp,
        level:     r.EventHeader.EventDescriptor.Level,
        opcode:    r.EventHeader.EventDescriptor.Opcode,
        task:      r.EventHeader.EventDescriptor.Task,
        keyword:   r.EventHeader.EventDescriptor.Keyword,
        user_data,
        description,
    };

    // Non-blocking: drop the event if the consumer is lagging rather than
    // stalling the ETW dispatch thread.
    let _ = tx.try_send(ev);
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0u16]).collect()
}

/// Allocate a buffer large enough for `EVENT_TRACE_PROPERTIES` followed by the
/// null-terminated `session_name_w`, with required fields pre-populated.
///
/// The trailing string allows `StartTraceW` to name the session and
/// `ControlTraceW` to find it by name when the handle is 0.
fn make_props(session_name_w: &[u16]) -> Vec<u8> {
    let struct_size = mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let name_bytes  = session_name_w.len() * mem::size_of::<u16>();
    let total       = struct_size + name_bytes;

    let mut buf = vec![0u8; total];

    // SAFETY: `buf` provides at least `total` bytes; `EVENT_TRACE_PROPERTIES`
    // is repr(C) with 4-byte alignment, which Vec<u8> guarantees on Windows.
    unsafe {
        let p = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        (*p).Wnode.BufferSize = total as u32;
        (*p).Wnode.Flags      = WNODE_FLAG_TRACED_GUID;
        (*p).LogFileMode      = EVENT_TRACE_REAL_TIME_MODE;
        (*p).LoggerNameOffset = struct_size as u32;

        std::ptr::copy_nonoverlapping(
            session_name_w.as_ptr().cast::<u8>(),
            (p as *mut u8).add(struct_size),
            name_bytes,
        );
    }

    buf
}

// ── EtwConsumer ───────────────────────────────────────────────────────────────

/// Windows ETW real-time session controller.
///
/// # Requirements
/// Administrator privileges or `SeSystemProfilePrivilege` (most providers).
/// `Security-Auditing` additionally requires `SeTcbPrivilege` on Server SKUs.
///
/// # Usage
/// ```rust,ignore
/// let (mut consumer, rx) = EtwConsumer::start()?;
/// // spawn a thread/task to drain rx …
/// consumer.stop(); // explicit stop; Drop will also stop on drop
/// ```
pub struct EtwConsumer {
    session_handle: CONTROLTRACE_HANDLE,
    trace_handle:   Option<PROCESSTRACE_HANDLE>,
    session_name_w: Vec<u16>,
}

impl EtwConsumer {
    /// Start the ETW session and return `(Self, Receiver<EtwEvent>)`.
    ///
    /// The `ProcessTrace` loop runs on a background thread named `etw-processor`
    /// and is unblocked by [`stop`] or `Drop`.
    pub fn start() -> Result<(Self, Receiver<EtwEvent>), SentinelError> {
        // Register the global sender before any event can arrive.
        let (tx, rx) = sync_channel::<EtwEvent>(2048);
        ETW_TX
            .set(tx)
            .map_err(|_| SentinelError::Platform("ETW consumer already running".into()))?;

        let session_name_w = to_wide(SESSION_NAME);

        // ── Step 1: StartTrace ─────────────────────────────────────────────────
        let mut session_handle = CONTROLTRACE_HANDLE { Value: 0 };
        let mut props = make_props(&session_name_w);

        let start_result = unsafe {
            StartTraceW(
                &mut session_handle,
                PCWSTR(session_name_w.as_ptr()),
                props.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
            )
        };

        if let Err(e) = start_result {
            if e.code() == ERROR_ALREADY_EXISTS.to_hresult() {
                // A stale session from a previous crash — stop it and retry.
                tracing::debug!("ETW session '{SESSION_NAME}' already exists; stopping stale session");
                let mut stop_props = make_props(&session_name_w);
                let _ = unsafe {
                    ControlTraceW(
                        CONTROLTRACE_HANDLE { Value: 0 },
                        PCWSTR(session_name_w.as_ptr()),
                        stop_props.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
                        EVENT_TRACE_CONTROL_STOP,
                    )
                };

                session_handle = CONTROLTRACE_HANDLE { Value: 0 };
                props = make_props(&session_name_w);
                unsafe {
                    StartTraceW(
                        &mut session_handle,
                        PCWSTR(session_name_w.as_ptr()),
                        props.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
                    )
                }
                .map_err(|e2| SentinelError::Platform(format!("StartTrace (retry): {e2}")))?;
            } else {
                return Err(SentinelError::Platform(format!("StartTrace: {e}")));
            }
        }

        // ── Step 2: EnableTraceEx2 for each provider ───────────────────────────
        for guid in PROVIDERS {
            if let Err(e) = unsafe {
                EnableTraceEx2(
                    session_handle,
                    guid,
                    ENABLE_CODE,
                    TRACE_LEVEL_ALL,
                    0xFFFF_FFFF_FFFF_FFFF, // all keywords
                    0,                     // MatchAllKeyword = none required
                    0,                     // synchronous (wait for enable to complete)
                    None,
                )
            } {
                // Warn but continue — some providers (e.g. Security-Auditing)
                // require elevated privileges that may not always be present.
                tracing::warn!(
                    "EnableTraceEx2 failed for provider {:08X}: {e}",
                    guid.data1,
                );
            }
        }

        // ── Step 3: OpenTrace ──────────────────────────────────────────────────
        // `logfile` only needs to outlive the `OpenTraceW` call; the returned
        // handle is what drives the lifetime of the session.
        let trace_handle = {
            let mut name_buf = session_name_w.clone();
            let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { mem::zeroed() };
            logfile.LoggerName = PWSTR(name_buf.as_mut_ptr());
            logfile.Anonymous1.ProcessTraceMode =
                PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);

            let h = unsafe { OpenTraceW(&mut logfile) };
            if h.Value == u64::MAX {
                return Err(SentinelError::Platform(
                    "OpenTraceW returned INVALID_PROCESSTRACE_HANDLE — check session name".into(),
                ));
            }
            h
        };

        // ── Step 4: ProcessTrace on a dedicated thread (call blocks) ───────────
        // `PROCESSTRACE_HANDLE` is `Copy` (transparent u64), safe to move.
        let th = trace_handle;
        thread::Builder::new()
            .name("etw-processor".into())
            .spawn(move || {
                // SAFETY: `th` is a valid open trace handle obtained from OpenTraceW.
                // ProcessTrace blocks until CloseTrace(th) is called.
                if let Err(e) = unsafe { ProcessTrace(&[th], None, None) } {
                    tracing::debug!("ProcessTrace exited: {e}");
                }
                tracing::debug!("etw-processor thread exiting");
            })
            .map_err(|e| SentinelError::Platform(format!("spawn etw-processor: {e}")))?;

        tracing::info!(
            "ETW session '{}' started — {} providers enabled",
            SESSION_NAME,
            PROVIDERS.len(),
        );

        Ok((
            Self {
                session_handle,
                trace_handle: Some(trace_handle),
                session_name_w,
            },
            rx,
        ))
    }

    /// Stop the ETW session and unblock the `etw-processor` thread.
    ///
    /// Idempotent — subsequent calls are no-ops.
    pub fn stop(&mut self) {
        if let Some(th) = self.trace_handle.take() {
            unsafe {
                // CloseTrace unblocks ProcessTrace so the spawned thread can exit.
                let _ = CloseTrace(th);

                // Stop the controller session to release kernel resources.
                let mut buf = make_props(&self.session_name_w);
                let _ = ControlTraceW(
                    self.session_handle,
                    PCWSTR(std::ptr::null()),
                    buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            tracing::info!("ETW session '{}' stopped", SESSION_NAME);
        }
    }
}

impl Drop for EtwConsumer {
    fn drop(&mut self) {
        self.stop();
    }
}
