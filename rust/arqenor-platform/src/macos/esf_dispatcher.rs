//! Shared ESF event dispatcher.
//!
//! Starts a single ESF monitor and fans out events to registered consumers.
//! This avoids the macOS limit on concurrent ES clients (Apple enforces a
//! per-process cap, typically 3-4 clients).
//!
//! # Architecture
//!
//! ```text
//!   ┌──────────────────┐
//!   │  ESF OS thread   │  endpoint_sec::Client callback
//!   │  (esf_monitor)   │──► std::sync::mpsc::SyncSender<EsfRawEvent>
//!   └──────────────────┘           │
//!                                  ▼
//!   ┌──────────────────┐   std::sync::mpsc::Receiver
//!   │  Bridge thread   │──► classify + fan-out
//!   └──────────────────┘     │              │
//!                            ▼              ▼
//!                   tokio Sender       tokio Sender
//!                   (process_tx)       (file_tx)
//! ```
//!
//! The bridge thread runs a blocking `recv()` loop on the `std::sync::mpsc`
//! channel and dispatches each event to the appropriate tokio consumer(s)
//! using non-blocking `try_send()`.

use super::esf_monitor::{self, EsfRawEvent};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::mpsc::Sender;

// ── Singleton accessor ───────────────────────────────────────────────────────

/// Global singleton storage for the dispatcher.
///
/// We use `OnceLock` so the `Arc<Mutex<EsfDispatcher>>` is initialized exactly
/// once, regardless of how many callers invoke `EsfDispatcher::global()`.
static DISPATCHER: OnceLock<Arc<Mutex<EsfDispatcher>>> = OnceLock::new();

/// Tracks whether the ESF monitor + bridge threads have been spawned.
///
/// `std::sync::Once` guarantees the spawn logic runs at most once, even if
/// both the process watcher and file watcher call `start()` concurrently.
static START_ONCE: std::sync::Once = std::sync::Once::new();

// ── EsfDispatcher ────────────────────────────────────────────────────────────

/// Shared dispatcher that owns the tokio senders for process and file consumers.
///
/// Register your consumer sender with [`set_process_sender`] or
/// [`set_file_sender`], then call [`start`] to spawn the ESF monitor.
/// Calling `start()` multiple times is safe — the monitor is spawned exactly
/// once via `std::sync::Once`.
pub struct EsfDispatcher {
    /// Sender for process-related events (Exec, Fork, Exit, GetTask).
    process_tx: Option<Sender<EsfRawEvent>>,
    /// Sender for file-related events (Create, Write, Delete, Rename, Chmod, Chown).
    file_tx: Option<Sender<EsfRawEvent>>,
}

impl EsfDispatcher {
    /// Obtain the global singleton dispatcher.
    ///
    /// The first call initializes the `Arc<Mutex<EsfDispatcher>>`.  Subsequent
    /// calls return a clone of the same `Arc`.
    pub fn global() -> Arc<Mutex<EsfDispatcher>> {
        DISPATCHER
            .get_or_init(|| {
                Arc::new(Mutex::new(EsfDispatcher {
                    process_tx: None,
                    file_tx: None,
                }))
            })
            .clone()
    }

    /// Register the tokio sender for process-lifecycle events.
    ///
    /// Must be called **before** [`start`] for events to be delivered from the
    /// beginning.  If called after `start`, events that arrived before
    /// registration are silently dropped.
    pub fn set_process_sender(&mut self, tx: Sender<EsfRawEvent>) {
        self.process_tx = Some(tx);
    }

    /// Register the tokio sender for file-system events.
    ///
    /// Must be called **before** [`start`] for events to be delivered from the
    /// beginning.  If called after `start`, events that arrived before
    /// registration are silently dropped.
    pub fn set_file_sender(&mut self, tx: Sender<EsfRawEvent>) {
        self.file_tx = Some(tx);
    }

    /// Spawn the ESF monitor thread and the bridge/dispatch thread.
    ///
    /// This method is idempotent — calling it multiple times (e.g. once from
    /// the process watcher and once from the file watcher) is safe.  The
    /// underlying threads are spawned exactly once via `std::sync::Once`.
    ///
    /// # Thread layout
    ///
    /// 1. **`esf-client`** — OS thread running `esf_monitor::run_esf_loop`.
    ///    Owns the `endpoint_sec::Client` and feeds a bounded `std::sync::mpsc`
    ///    channel.
    /// 2. **`esf-bridge`** — OS thread that drains the `std::sync::mpsc`
    ///    receiver and fans out events to the registered tokio senders.
    pub fn start(&self) {
        // Clone the senders so the bridge thread owns them independently.
        let process_tx = self.process_tx.clone();
        let file_tx = self.file_tx.clone();

        START_ONCE.call_once(move || {
            // Bounded channel between the ESF callback thread and our bridge.
            // 4096 slots gives ~160 KB overhead and absorbs short bursts.
            let (sync_tx, sync_rx) = std::sync::mpsc::sync_channel::<EsfRawEvent>(4096);

            // ── Thread 1: ESF client (must own the Client on this thread) ──
            if let Err(e) = std::thread::Builder::new()
                .name("esf-client".into())
                .spawn(move || {
                    esf_monitor::run_esf_loop(sync_tx);
                    tracing::info!("esf-client thread exiting");
                })
            {
                tracing::error!(error = %e, "failed to spawn esf-client thread");
                return;
            }

            // ── Thread 2: Bridge / fan-out ─────────────────────────────────
            if let Err(e) = std::thread::Builder::new()
                .name("esf-bridge".into())
                .spawn(move || {
                    run_bridge(sync_rx, process_tx, file_tx);
                    tracing::info!("esf-bridge thread exiting");
                })
            {
                tracing::error!(error = %e, "failed to spawn esf-bridge thread");
                return;
            }

            tracing::info!("ESF dispatcher started (esf-client + esf-bridge threads)");
        });
    }
}

// ── Bridge loop ──────────────────────────────────────────────────────────────

/// Blocking loop that receives events from the `std::sync::mpsc` channel and
/// dispatches them to the appropriate tokio sender(s).
///
/// Exits when the `sync_rx` channel is disconnected (i.e. the ESF monitor
/// thread dropped its sender) **or** when both consumer senders are `None` /
/// closed.
fn run_bridge(
    sync_rx: std::sync::mpsc::Receiver<EsfRawEvent>,
    process_tx: Option<Sender<EsfRawEvent>>,
    file_tx: Option<Sender<EsfRawEvent>>,
) {
    // If neither consumer is registered, there is nothing to dispatch.
    if process_tx.is_none() && file_tx.is_none() {
        tracing::warn!("ESF bridge started with no registered consumers — exiting");
        return;
    }

    // Track whether each sender is still connected so we can exit early
    // if both consumers have dropped their receivers.
    let mut process_alive = process_tx.is_some();
    let mut file_alive = file_tx.is_some();

    for event in sync_rx.iter() {
        // Early exit if both consumers are gone.
        if !process_alive && !file_alive {
            tracing::info!("both ESF consumers disconnected — bridge exiting");
            break;
        }

        match &event {
            // ── Process-related events → process_tx ──────────────────────
            EsfRawEvent::ProcessExec { .. }
            | EsfRawEvent::ProcessFork { .. }
            | EsfRawEvent::ProcessExit { .. }
            | EsfRawEvent::GetTask { .. } => {
                if let Some(ref tx) = process_tx {
                    if process_alive {
                        match tx.try_send(event) {
                            Ok(()) => {}
                            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                tracing::debug!("process consumer lagging — event dropped");
                            }
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                tracing::warn!("process consumer closed — disabling dispatch");
                                process_alive = false;
                            }
                        }
                    }
                }
            }

            // ── File-related events → file_tx ───────────────────────────
            EsfRawEvent::FileCreate { .. }
            | EsfRawEvent::FileWrite { .. }
            | EsfRawEvent::FileDelete { .. }
            | EsfRawEvent::FileRename { .. }
            | EsfRawEvent::FileChmod { .. }
            | EsfRawEvent::FileChown { .. } => {
                if let Some(ref tx) = file_tx {
                    if file_alive {
                        match tx.try_send(event) {
                            Ok(()) => {}
                            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                tracing::debug!("file consumer lagging — event dropped");
                            }
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                tracing::warn!("file consumer closed — disabling dispatch");
                                file_alive = false;
                            }
                        }
                    }
                }
            }
        }
    }

    tracing::info!("ESF bridge: sync channel closed — exiting dispatch loop");
}
