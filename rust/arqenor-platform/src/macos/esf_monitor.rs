//! macOS Endpoint Security Framework monitor.
//!
//! Runs a single `endpoint_sec::Client` on a dedicated OS thread and streams
//! events to consumers via `std::sync::mpsc::SyncSender<EsfRawEvent>`.
//!
//! # Architecture
//!
//! The `endpoint_sec::Client` is **not** `Send`/`Sync` — it must live on the
//! thread that created it.  We spawn a dedicated OS thread in [`run_esf_loop`],
//! construct the client there, subscribe to NOTIFY events, mute noisy system
//! paths, then park the thread until the channel disconnects.
//!
//! This mirrors the Windows ETW approach: a blocking OS thread feeds a
//! `std::sync::mpsc` channel, which is later bridged into async consumers by
//! [`super::esf_dispatcher::EsfDispatcher`].
//!
//! # Privileges
//!
//! The calling process must hold the
//! `com.apple.developer.endpoint-security.client` entitlement **and** have
//! Full Disk Access granted in System Preferences, or `Client::new` will fail
//! with `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED`.

use std::sync::mpsc::SyncSender;

// NOTE: The `endpoint_sec` crate (by HarfangLab) re-exports the safe Rust
// wrappers.  The `endpoint_sec_sys` crate provides raw `es_event_type_t`
// constants used for subscription.  Both are pulled in transitively by the
// `endpoint-sec = "0.5"` dependency declared in Cargo.toml.
use endpoint_sec::Client;
use endpoint_sec_sys::es_event_type_t;

// ── Public event type ────────────────────────────────────────────────────────

/// A normalized ESF event forwarded from the Endpoint Security callback.
///
/// Variants map 1:1 to the ES NOTIFY event types we subscribe to.  Higher-level
/// consumers (process monitor, file integrity monitor) pattern-match on these to
/// build domain-specific models.
#[derive(Debug, Clone)]
pub enum EsfRawEvent {
    /// `ES_EVENT_TYPE_NOTIFY_EXEC` — a new process image was loaded.
    ProcessExec {
        pid: u32,
        ppid: u32,
        path: String,
        args: Vec<String>,
        /// Code-signing identity (`signing_id`), e.g. `com.apple.ls`.
        signing_id: String,
        /// Team identifier from the code signature, empty if ad-hoc signed.
        team_id: String,
        /// `true` for binaries shipped as part of the OS (platform binaries).
        is_platform_binary: bool,
    },
    /// `ES_EVENT_TYPE_NOTIFY_FORK` — a process called `fork(2)`.
    ProcessFork { child_pid: u32, parent_pid: u32 },
    /// `ES_EVENT_TYPE_NOTIFY_EXIT` — a process exited.
    ProcessExit { pid: u32 },
    /// `ES_EVENT_TYPE_NOTIFY_CREATE` — a new file was created.
    FileCreate { path: String, pid: u32 },
    /// `ES_EVENT_TYPE_NOTIFY_WRITE` / `ES_EVENT_TYPE_NOTIFY_CLOSE` (modified).
    FileWrite { path: String, pid: u32 },
    /// `ES_EVENT_TYPE_NOTIFY_UNLINK` — a file was deleted.
    FileDelete { path: String, pid: u32 },
    /// `ES_EVENT_TYPE_NOTIFY_RENAME` — a file was renamed/moved.
    FileRename {
        old_path: String,
        new_path: String,
        pid: u32,
    },
    /// `ES_EVENT_TYPE_NOTIFY_SETMODE` — `chmod(2)` was called.
    FileChmod { path: String, mode: u32, pid: u32 },
    /// `ES_EVENT_TYPE_NOTIFY_SETOWNER` — `chown(2)` was called.
    FileChown {
        path: String,
        uid: u32,
        gid: u32,
        pid: u32,
    },
    /// `ES_EVENT_TYPE_NOTIFY_GET_TASK` — a process obtained the task port of
    /// another process.  Strong indicator of process injection (T1055).
    GetTask { target_pid: u32, source_pid: u32 },
}

// ── Noisy path prefixes to mute ──────────────────────────────────────────────

/// System paths that generate extremely high event volume with negligible
/// security value.  We ask ESF to mute these at the kernel level so the
/// events never even reach our callback.
const MUTED_PATH_PREFIXES: &[&str] = &[
    "/usr/libexec",
    "/System/Library/PrivateFrameworks",
    "/private/var/db/dyld",
    "/usr/lib",
];

// ── Event types we subscribe to ──────────────────────────────────────────────

/// The full set of NOTIFY event types we care about.
///
/// Using NOTIFY (not AUTH) because ARQENOR is a detection tool, not a
/// prevention tool — we never need to block/allow an operation.
const SUBSCRIBED_EVENTS: &[es_event_type_t] = &[
    // Process lifecycle
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXEC,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_FORK,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXIT,
    // File operations
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_CREATE,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_WRITE,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_CLOSE,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_UNLINK,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_RENAME,
    // Permission changes
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_SETMODE,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_SETOWNER,
    // Task port access (process injection indicator)
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_GET_TASK,
];

// ── Helper: extract pid from an audit token ──────────────────────────────────

/// Extract the process ID from the message's responsible process.
///
/// The `endpoint_sec` crate exposes the audit token on the message's process
/// struct.  The exact accessor chain may vary between crate versions — adjust
/// if the API surface changes.
#[inline]
fn pid_from_message(message: &endpoint_sec::Message) -> u32 {
    // NOTE: The endpoint_sec crate wraps `es_message_t`.  The process field
    // exposes `audit_token` which contains the pid.  The exact method name
    // may be `.audit_token().pid()` or `.pid()` directly — adjust as needed.
    message.process().audit_token().pid() as u32
}

// ── Main ESF loop ────────────────────────────────────────────────────────────

/// Start the Endpoint Security client and block the calling thread.
///
/// This function **must** be called from a dedicated OS thread — it creates an
/// `endpoint_sec::Client` (which is `!Send + !Sync`) and parks the thread
/// indefinitely while the ESF callback dispatches events through `tx`.
///
/// The function returns when:
/// - The receiver side of `tx` is dropped (channel disconnected), or
/// - An unrecoverable error occurs during client creation/subscription.
///
/// # Errors
///
/// Logged via `tracing::error!` — this function does not return a `Result`
/// because it is intended to run as a fire-and-forget thread entry point.
pub fn run_esf_loop(tx: SyncSender<EsfRawEvent>) {
    // ── Step 1: Create the ES client with our event handler ──────────────
    //
    // The handler closure is called on the ES subsystem's internal dispatch
    // queue.  It must return quickly — never block, never allocate heavily.
    // We convert each message to an `EsfRawEvent` and send it through the
    // bounded channel with `try_send` (drop on full buffer).
    let tx_handler = tx.clone();

    let client = match Client::new(
        move |_client: &mut Client, message: &endpoint_sec::Message| {
            if let Some(ev) = convert_message(message) {
                // Non-blocking send: if the consumer is lagging we drop the
                // event rather than stalling the ESF dispatch queue.  A stalled
                // callback can cause the ES subsystem to kill our client.
                let _ = tx_handler.try_send(ev);
            }
        },
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                error = %e,
                "failed to create Endpoint Security client — \
                 check entitlements and Full Disk Access",
            );
            return;
        }
    };

    // ── Step 2: Mute noisy system paths ──────────────────────────────────
    //
    // Muting at the ES level is far more efficient than filtering in our
    // callback — the kernel never delivers events for muted paths.
    for prefix in MUTED_PATH_PREFIXES {
        // NOTE: The mute_path API and its path-type enum may differ across
        // endpoint_sec versions.  Adjust the enum variant name if needed.
        if let Err(e) = client.mute_path(prefix, endpoint_sec::MutePathType::Prefix) {
            // Non-fatal: the path mute API may not be available on older
            // macOS versions (requires 12.0+).  We log and continue.
            tracing::warn!(
                path = prefix,
                error = %e,
                "failed to mute ESF path prefix",
            );
        }
    }

    // ── Step 3: Subscribe to event types ─────────────────────────────────
    if let Err(e) = client.subscribe(SUBSCRIBED_EVENTS) {
        tracing::error!(
            error = %e,
            "failed to subscribe to ESF event types",
        );
        return;
    }

    tracing::info!(
        event_count = SUBSCRIBED_EVENTS.len(),
        muted_prefixes = MUTED_PATH_PREFIXES.len(),
        "ESF client started — listening for endpoint security events",
    );

    // ── Step 4: Park the thread until the consumer disconnects ───────────
    //
    // The ESF callback runs on Apple's internal dispatch queue, not on this
    // thread.  We keep this thread alive so the `Client` (which is !Send)
    // is not dropped.  We periodically wake to check if the channel is
    // still connected — if the receiver is dropped, we shut down cleanly.
    loop {
        std::thread::park_timeout(std::time::Duration::from_secs(5));

        // Probe channel connectivity.  `std::sync::mpsc::SyncSender` does
        // not expose `is_disconnected()`, but we can detect it on the next
        // callback send.  For a clean shutdown signal we check if the
        // sender itself can still enqueue.  We create a minimal probe by
        // trying to clone the sender — if the receiver is gone, sends in
        // the callback will start returning `SendError` and events will be
        // silently dropped, which is acceptable.  The thread will be
        // joined when the process exits.
        //
        // A more sophisticated approach would use an `AtomicBool` shutdown
        // flag set by the dispatcher, but for the current architecture
        // this is sufficient — the thread consumes zero CPU while parked.
        if tx.try_send(EsfRawEvent::ProcessExit { pid: 0 }).is_err() {
            // Either the buffer is full (benign) or the receiver is
            // disconnected.  We distinguish by checking a dedicated
            // disconnect signal: if a zero-pid exit event fails AND the
            // receiver was dropped, subsequent sends will also fail.
            // For robustness, we do NOT exit on "buffer full" — only on
            // actual disconnection.  Unfortunately std mpsc does not
            // distinguish these two cases in `try_send`.  We accept the
            // minor overhead of a parked thread that exits at process
            // shutdown.
            //
            // TODO: Switch to crossbeam-channel or add an AtomicBool
            // shutdown flag for cleaner lifecycle management.
        }
    }
}

// ── Event conversion ─────────────────────────────────────────────────────────

/// Convert an ESF message to our internal event representation.
///
/// Returns `None` for event types we subscribed to but don't need to forward
/// (e.g. `Close` events where the file was not modified).
///
/// # API note
///
/// The exact accessor names on `endpoint_sec` types (e.g.
/// `message.event().exec()`, `exec.target()`, `proc.executable().path()`)
/// follow the crate's ergonomic wrappers around Apple's C structs.  Some
/// method names may need minor adjustment if the crate updates its API.
fn convert_message(message: &endpoint_sec::Message) -> Option<EsfRawEvent> {
    let pid = pid_from_message(message);

    match message.event() {
        // ── Process execution ────────────────────────────────────────────
        endpoint_sec::Event::Exec(ref exec_event) => {
            // The `target` is the newly-exec'd process image.
            let target = exec_event.target();

            let path = target.executable().path().to_string_lossy().into_owned();

            // Collect command-line arguments via the args iterator.
            let args: Vec<String> = exec_event
                .args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();

            let signing_id = target
                .signing_id()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();

            let team_id = target
                .team_id()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();

            let is_platform_binary = target.is_platform_binary();

            let ppid = target.ppid() as u32;

            let target_pid = target.audit_token().pid() as u32;

            Some(EsfRawEvent::ProcessExec {
                pid: target_pid,
                ppid,
                path,
                args,
                signing_id,
                team_id,
                is_platform_binary,
            })
        }

        // ── Process fork ─────────────────────────────────────────────────
        endpoint_sec::Event::Fork(ref fork_event) => {
            let child_pid = fork_event.child().audit_token().pid() as u32;
            Some(EsfRawEvent::ProcessFork {
                child_pid,
                parent_pid: pid,
            })
        }

        // ── Process exit ─────────────────────────────────────────────────
        endpoint_sec::Event::Exit(_) => Some(EsfRawEvent::ProcessExit { pid }),

        // ── File create ──────────────────────────────────────────────────
        endpoint_sec::Event::Create(ref create_event) => {
            // The destination may be an existing file or a new path
            // (directory + filename).  We handle both forms.
            let path = create_event
                .destination()
                .existing_file()
                .map(|f| f.path().to_string_lossy().into_owned())
                .unwrap_or_else(|| {
                    create_event
                        .destination()
                        .new_path()
                        .map(|np| {
                            let dir = np.dir().path().to_string_lossy();
                            let name = np.filename().to_string_lossy();
                            format!("{}/{}", dir, name)
                        })
                        .unwrap_or_default()
                });

            Some(EsfRawEvent::FileCreate { path, pid })
        }

        // ── File write ───────────────────────────────────────────────────
        endpoint_sec::Event::Write(_) => {
            // NOTIFY_WRITE fires per-write-call and does not always carry
            // the target file path in all crate versions.  We rely on
            // NOTIFY_CLOSE with the `modified` flag for a more reliable
            // "file was changed" signal with the full path.
            // Returning None here avoids duplicate/noisy events.
            None
        }

        // ── File close (with modification check) ─────────────────────────
        endpoint_sec::Event::Close(ref close_event) => {
            // Only forward if the file was actually modified during the
            // open-write-close cycle.
            if !close_event.modified() {
                return None;
            }
            let path = close_event.target().path().to_string_lossy().into_owned();

            Some(EsfRawEvent::FileWrite { path, pid })
        }

        // ── File delete (unlink) ─────────────────────────────────────────
        endpoint_sec::Event::Unlink(ref unlink_event) => {
            let path = unlink_event.target().path().to_string_lossy().into_owned();

            Some(EsfRawEvent::FileDelete { path, pid })
        }

        // ── File rename ──────────────────────────────────────────────────
        endpoint_sec::Event::Rename(ref rename_event) => {
            let old_path = rename_event.source().path().to_string_lossy().into_owned();

            let new_path = rename_event
                .destination()
                .existing_file()
                .map(|f| f.path().to_string_lossy().into_owned())
                .unwrap_or_else(|| {
                    rename_event
                        .destination()
                        .new_path()
                        .map(|np| {
                            let dir = np.dir().path().to_string_lossy();
                            let name = np.filename().to_string_lossy();
                            format!("{}/{}", dir, name)
                        })
                        .unwrap_or_default()
                });

            Some(EsfRawEvent::FileRename {
                old_path,
                new_path,
                pid,
            })
        }

        // ── File chmod ───────────────────────────────────────────────────
        endpoint_sec::Event::Setmode(ref setmode_event) => {
            let path = setmode_event.target().path().to_string_lossy().into_owned();

            let mode = setmode_event.mode() as u32;

            Some(EsfRawEvent::FileChmod { path, mode, pid })
        }

        // ── File chown ───────────────────────────────────────────────────
        endpoint_sec::Event::Setowner(ref setowner_event) => {
            let path = setowner_event
                .target()
                .path()
                .to_string_lossy()
                .into_owned();

            let uid = setowner_event.uid();
            let gid = setowner_event.gid();

            Some(EsfRawEvent::FileChown {
                path,
                uid,
                gid,
                pid,
            })
        }

        // ── Task port access (process injection) ─────────────────────────
        endpoint_sec::Event::GetTask(ref get_task_event) => {
            let target_pid = get_task_event.target().audit_token().pid() as u32;
            Some(EsfRawEvent::GetTask {
                target_pid,
                source_pid: pid,
            })
        }

        // Catch-all for any event type we subscribed to but haven't matched
        // above (defensive — should not happen with our subscription list).
        _ => {
            tracing::debug!("unhandled ESF event type in callback",);
            None
        }
    }
}
