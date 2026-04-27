use crate::{
    common,
    host::{
        host_analyzer_server::HostAnalyzer, FileEvent as ProtoFileEvent, HealthResponse,
        PersistenceEntry as ProtoPersistenceEntry, PersistenceResponse,
        ProcessEvent as ProtoProcessEvent, ProcessInfo as ProtoProcessInfo, ScanRequest,
        SnapshotResponse,
    },
    limits::{resolve_max_size_bytes, sanitize_meta_value, AllowedRoots},
};
use arqenor_core::traits::connection_monitor::spawn_polling_watch;
use arqenor_core::{
    ioc::{
        feeds,
        persistence::{load_from_store, IocPersistence},
        IocDatabase,
    },
    models::alert::Severity as CoreSeverity,
    pipeline::{DetectionPipeline, PipelineConfig},
    rules::sigma,
};
use arqenor_platform::{
    new_connection_monitor, new_fs_scanner, new_persistence_detector, new_process_monitor,
};
use arqenor_store::IocSqliteStore;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// Default connection polling interval in milliseconds (5 seconds).
const CONN_POLL_INTERVAL_MS: u64 = 5_000;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

/// Shared state initialised once at service startup.
struct SharedDetectionState {
    ioc_db: Arc<RwLock<IocDatabase>>,
    sigma_rules: Vec<sigma::SigmaRule>,
    /// Filesystem-scan allowlist used to gate `ScanFilesystem` requests.
    /// See finding GRPC-PATH.
    allowed_roots: AllowedRoots,
}

pub struct HostAnalyzerService {
    shared: Arc<SharedDetectionState>,
}

impl HostAnalyzerService {
    /// Construct the service with an explicit filesystem-scan allowlist.
    ///
    /// The allowlist is canonicalized at construction time and consulted on
    /// every incoming `ScanFilesystem` request. Pass an empty list to refuse
    /// every scan request — useful for deployments where filesystem scanning
    /// is not in scope.
    pub fn new(allowed_roots: AllowedRoots) -> Self {
        let ioc_db = Arc::new(RwLock::new(IocDatabase::new()));

        // Best-effort initial feed load (blocking in constructor is acceptable
        // because the gRPC server hasn't started accepting yet). Persist to
        // SQLite when possible so feeds survive restarts and benefit from
        // HTTP conditional-GET delta refresh.
        let db_clone = Arc::clone(&ioc_db);
        tokio::spawn(async move {
            let data_dir = std::env::var("ARQENOR_DATA_DIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| std::path::PathBuf::from("."));

            let store: Option<Arc<dyn IocPersistence>> = match std::fs::create_dir_all(&data_dir) {
                Err(e) => {
                    tracing::warn!(%e, path = %data_dir.display(),
                            "create data_dir failed, IOC persistence disabled");
                    None
                }
                Ok(()) => match IocSqliteStore::open(&data_dir.join("ioc.db")) {
                    Ok(s) => Some(Arc::new(s)),
                    Err(e) => {
                        tracing::warn!(%e, "open IOC store failed, falling back to in-memory");
                        None
                    }
                },
            };

            {
                let mut guard = db_clone.write().await;
                if let Some(ref s) = store {
                    if let Err(e) = load_from_store(s.as_ref(), &mut guard) {
                        tracing::warn!(%e, "load IOC from store failed");
                    }
                }
                feeds::refresh_all_feeds_with_persist(&mut guard, store.as_deref()).await;
            }

            // Refresh every 4 hours.
            let interval = std::time::Duration::from_secs(4 * 3600);
            match store {
                Some(s) => feeds::spawn_feed_refresh_loop_with_persist(db_clone, s, interval),
                None => feeds::spawn_feed_refresh_loop(db_clone, interval),
            };
        });

        // Load SIGMA rules from a well-known path if present.
        let sigma_rules = if std::path::Path::new("sigma-rules").exists() {
            sigma::load_sigma_rules_from_dir(std::path::Path::new("sigma-rules"))
        } else {
            Vec::new()
        };

        Self {
            shared: Arc::new(SharedDetectionState {
                ioc_db,
                sigma_rules,
                allowed_roots,
            }),
        }
    }
}

// ── Platform-specific FIM default path ───────────────────────────────────────

fn default_fim_path() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    {
        std::path::PathBuf::from(r"C:\Windows\System32")
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::path::PathBuf::from("/etc")
    }
}

// ── Alert conversion ──────────────────────────────────────────────────────────

/// Sanitize every value of an `Alert.metadata` map before it crosses the
/// gRPC boundary. See finding GRPC-METADATA in the 2026-04 audit.
fn sanitize_metadata(meta: HashMap<String, String>) -> HashMap<String, String> {
    meta.into_iter()
        .map(|(k, v)| (k, sanitize_meta_value(&v)))
        .collect()
}

fn core_alert_to_proto(a: arqenor_core::models::alert::Alert) -> common::Alert {
    let sev = match a.severity {
        CoreSeverity::Info => common::Severity::Info as i32,
        CoreSeverity::Low => common::Severity::Low as i32,
        CoreSeverity::Medium => common::Severity::Medium as i32,
        CoreSeverity::High => common::Severity::High as i32,
        CoreSeverity::Critical => common::Severity::Critical as i32,
    };
    let occurred_at = Some(prost_types::Timestamp {
        seconds: a.occurred_at.timestamp(),
        nanos: a.occurred_at.timestamp_subsec_nanos() as i32,
    });
    common::Alert {
        id: a.id.to_string(),
        severity: sev,
        kind: a.kind,
        message: sanitize_meta_value(&a.message),
        occurred_at,
        metadata: sanitize_metadata(a.metadata),
        rule_id: a.rule_id.unwrap_or_default(),
        attack_id: a.attack_id.unwrap_or_default(),
    }
}

// ── Core → proto event conversion ────────────────────────────────────────────

fn chrono_to_proto_ts(t: chrono::DateTime<chrono::Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: t.timestamp(),
        nanos: t.timestamp_subsec_nanos() as i32,
    }
}

fn core_process_info_to_proto(p: arqenor_core::models::process::ProcessInfo) -> ProtoProcessInfo {
    ProtoProcessInfo {
        pid: p.pid,
        ppid: p.ppid,
        name: p.name,
        exe_path: p.exe_path.unwrap_or_default(),
        cmdline: p.cmdline.unwrap_or_default(),
        user: p.user.unwrap_or_default(),
        sha256: p.sha256.unwrap_or_default(),
        started_at: p.started_at.map(chrono_to_proto_ts),
        loaded_modules: p.loaded_modules,
    }
}

fn core_process_event_to_proto(
    e: arqenor_core::models::process::ProcessEvent,
) -> ProtoProcessEvent {
    use arqenor_core::models::process::ProcessEventKind;
    let kind = match e.kind {
        ProcessEventKind::Created => crate::host::process_event::Kind::Created as i32,
        ProcessEventKind::Terminated => crate::host::process_event::Kind::Terminated as i32,
        ProcessEventKind::Modified => crate::host::process_event::Kind::Modified as i32,
    };
    ProtoProcessEvent {
        kind,
        process: Some(core_process_info_to_proto(e.process)),
        event_time: Some(chrono_to_proto_ts(e.event_time)),
    }
}

fn core_file_event_to_proto(e: arqenor_core::models::file_event::FileEvent) -> ProtoFileEvent {
    use arqenor_core::models::file_event::FileEventKind;
    let kind = match e.kind {
        FileEventKind::Created => crate::host::file_event::Kind::Created as i32,
        FileEventKind::Modified => crate::host::file_event::Kind::Modified as i32,
        FileEventKind::Deleted => crate::host::file_event::Kind::Deleted as i32,
        FileEventKind::Renamed => crate::host::file_event::Kind::Renamed as i32,
    };
    ProtoFileEvent {
        kind,
        path: e.path,
        sha256: e.sha256.unwrap_or_default(),
        size: e.size.unwrap_or(0),
        event_time: Some(chrono_to_proto_ts(e.event_time)),
    }
}

// ── HostAnalyzer implementation ───────────────────────────────────────────────

#[tonic::async_trait]
impl HostAnalyzer for HostAnalyzerService {
    type WatchProcessesStream = ReceiverStream<Result<ProtoProcessEvent, Status>>;
    type ScanFilesystemStream = ReceiverStream<Result<ProtoFileEvent, Status>>;
    type WatchFilesystemStream = ReceiverStream<Result<ProtoFileEvent, Status>>;
    type WatchAlertsStream = ReceiverStream<Result<common::Alert, Status>>;

    async fn get_process_snapshot(
        &self,
        _req: Request<()>,
    ) -> Result<Response<SnapshotResponse>, Status> {
        let monitor = new_process_monitor();
        let procs = monitor
            .snapshot()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let proto_procs = procs
            .into_iter()
            .map(|p| ProtoProcessInfo {
                pid: p.pid,
                ppid: p.ppid,
                name: p.name,
                exe_path: p.exe_path.unwrap_or_default(),
                cmdline: p.cmdline.unwrap_or_default(),
                user: p.user.unwrap_or_default(),
                sha256: p.sha256.unwrap_or_default(),
                started_at: None,
                loaded_modules: p.loaded_modules,
            })
            .collect();

        Ok(Response::new(SnapshotResponse {
            processes: proto_procs,
            captured_at: None,
        }))
    }

    async fn watch_processes(
        &self,
        _req: Request<()>,
    ) -> Result<Response<Self::WatchProcessesStream>, Status> {
        // Bridge core ProcessEvent stream (from the platform provider) onto the
        // gRPC response stream.
        let (core_tx, mut core_rx) =
            mpsc::channel::<arqenor_core::models::process::ProcessEvent>(256);
        let (stream_tx, stream_rx) = mpsc::channel::<Result<ProtoProcessEvent, Status>>(256);

        let monitor = new_process_monitor();
        monitor.watch(core_tx).await.map_err(|e| {
            tracing::error!("watch_processes: failed to start process monitor: {e}");
            Status::internal(format!("failed to start process monitor: {e}"))
        })?;

        tokio::spawn(async move {
            while let Some(evt) = core_rx.recv().await {
                let proto = core_process_event_to_proto(evt);
                if stream_tx.send(Ok(proto)).await.is_err() {
                    // Client disconnected.
                    break;
                }
            }
            tracing::debug!("watch_processes: core event stream closed");
        });

        Ok(Response::new(ReceiverStream::new(stream_rx)))
    }

    async fn scan_filesystem(
        &self,
        req: Request<ScanRequest>,
    ) -> Result<Response<Self::ScanFilesystemStream>, Status> {
        let r = req.into_inner();

        // Validate caller-supplied root_path against the canonical allowlist
        // (finding GRPC-PATH). Any path outside one of the allowed roots, or
        // any path that fails to canonicalize, is rejected with a precise
        // gRPC status code so clients can distinguish input errors from
        // policy denials.
        let canonical_root = self.shared.allowed_roots.validate(&r.root_path)?;

        // Cap caller-supplied max_size_bytes to a server-side maximum
        // (finding GRPC-MAXSIZE). `0` is treated as "use server default"
        // rather than "unbounded".
        let max_size_bytes = resolve_max_size_bytes(r.max_size_bytes)?;

        let scanner = new_fs_scanner();
        let config = arqenor_core::models::file_event::ScanConfig {
            recursive: r.recursive,
            include_extensions: r.include_exts,
            max_size_bytes: Some(max_size_bytes),
            compute_hash: true,
        };

        let events = scanner
            .scan_path(&canonical_root, &config)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let (tx, rx) = mpsc::channel(128);
        tokio::spawn(async move {
            for e in events {
                let proto = ProtoFileEvent {
                    kind: e.kind as i32,
                    path: e.path,
                    sha256: e.sha256.unwrap_or_default(),
                    size: e.size.unwrap_or(0),
                    event_time: None,
                };
                if tx.send(Ok(proto)).await.is_err() {
                    break;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn watch_filesystem(
        &self,
        req: Request<ScanRequest>,
    ) -> Result<Response<Self::WatchFilesystemStream>, Status> {
        let r = req.into_inner();

        // Fall back to the platform-specific default FIM path if the caller did
        // not specify one — matches the behaviour of `watch_alerts` and keeps
        // the RPC useful with an empty request.
        let root = if r.root_path.trim().is_empty() {
            default_fim_path()
        } else {
            // When a caller supplies a path, gate it through the same
            // allowlist used by `scan_filesystem` (finding GRPC-PATH).
            self.shared.allowed_roots.validate(&r.root_path)?
        };

        let (core_tx, mut core_rx) =
            mpsc::channel::<arqenor_core::models::file_event::FileEvent>(256);
        let (stream_tx, stream_rx) = mpsc::channel::<Result<ProtoFileEvent, Status>>(256);

        let scanner = new_fs_scanner();
        scanner.watch_path(&root, core_tx).await.map_err(|e| {
            tracing::error!(
                "watch_filesystem: failed to start fs watcher on {}: {e}",
                root.display()
            );
            Status::internal(format!(
                "failed to start fs watcher on {}: {e}",
                root.display()
            ))
        })?;

        tokio::spawn(async move {
            while let Some(evt) = core_rx.recv().await {
                let proto = core_file_event_to_proto(evt);
                if stream_tx.send(Ok(proto)).await.is_err() {
                    // Client disconnected.
                    break;
                }
            }
            tracing::debug!("watch_filesystem: core event stream closed");
        });

        Ok(Response::new(ReceiverStream::new(stream_rx)))
    }

    async fn get_persistence(
        &self,
        _req: Request<()>,
    ) -> Result<Response<PersistenceResponse>, Status> {
        let detector = new_persistence_detector();
        let entries = detector
            .detect()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let proto_entries = entries
            .into_iter()
            .map(|e| ProtoPersistenceEntry {
                kind: format!("{:?}", e.kind),
                name: e.name,
                command: e.command,
                location: e.location,
                is_new: e.is_new,
            })
            .collect();

        Ok(Response::new(PersistenceResponse {
            entries: proto_entries,
        }))
    }

    async fn health(&self, _req: Request<()>) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: "ok".into(),
            platform: std::env::consts::OS.into(),
            version: env!("CARGO_PKG_VERSION").into(),
        }))
    }

    /// Stream real-time detection alerts to the caller.
    ///
    /// On each connection:
    ///   1. Starts process, filesystem, and connection watchers (non-fatal).
    ///   2. Runs the `DetectionPipeline` with all event streams including
    ///      network connection monitoring for C2 beaconing detection.
    ///   3. Streams resulting `Alert`s until the client disconnects.
    async fn watch_alerts(
        &self,
        _req: Request<()>,
    ) -> Result<Response<Self::WatchAlertsStream>, Status> {
        let (proc_tx, proc_rx) = mpsc::channel(512);
        let (fim_tx, fim_rx) = mpsc::channel(512);
        let (conn_tx, conn_rx) =
            mpsc::channel::<arqenor_core::models::connection::ConnectionInfo>(512);
        let (core_tx, mut core_rx) = mpsc::channel::<arqenor_core::models::alert::Alert>(256);

        // Start watchers — ignore errors (platform may not support them).
        let _ = new_process_monitor().watch(proc_tx).await;
        let _ = new_fs_scanner()
            .watch_path(&default_fim_path(), fim_tx)
            .await;

        // Start connection monitor with fallback to polling.
        let conn_monitor = new_connection_monitor();
        match conn_monitor
            .watch(conn_tx.clone(), CONN_POLL_INTERVAL_MS)
            .await
        {
            Ok(()) => {}
            Err(arqenor_core::error::ArqenorError::NotSupported) => {
                let fallback = new_connection_monitor();
                spawn_polling_watch(fallback, conn_tx, CONN_POLL_INTERVAL_MS);
            }
            Err(_) => {
                // Connection monitoring unavailable — pipeline will use an
                // inert conn_rx (sender side dropped).
            }
        }

        // Run the detection pipeline with SIGMA + IOC + correlation + connections.
        let config = PipelineConfig {
            sigma_rules: self.shared.sigma_rules.clone(),
            ioc_db: Some(Arc::clone(&self.shared.ioc_db)),
            ..PipelineConfig::default()
        };
        let pipeline =
            DetectionPipeline::with_connections(config, proc_rx, fim_rx, conn_rx, core_tx);
        tokio::spawn(pipeline.run());

        // Bridge core Alert → proto Alert on the stream channel.
        let (stream_tx, stream_rx) = mpsc::channel::<Result<common::Alert, Status>>(256);
        tokio::spawn(async move {
            while let Some(alert) = core_rx.recv().await {
                if stream_tx
                    .send(Ok(core_alert_to_proto(alert)))
                    .await
                    .is_err()
                {
                    break; // client disconnected
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(stream_rx)))
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use arqenor_core::models::{
        alert::{Alert as CoreAlert, Severity as CoreAlertSeverity},
        file_event::{FileEvent as CoreFileEvent, FileEventKind},
        process::{
            ProcessEvent as CoreProcessEvent, ProcessEventKind, ProcessInfo as CoreProcessInfo,
        },
    };
    use chrono::Utc;
    use uuid::Uuid;

    fn sample_process_info() -> CoreProcessInfo {
        CoreProcessInfo {
            pid: 42,
            ppid: 1,
            name: "bash".into(),
            exe_path: Some("/bin/bash".into()),
            cmdline: Some("bash -c 'echo'".into()),
            user: Some("root".into()),
            sha256: Some("deadbeef".into()),
            started_at: Some(Utc::now()),
            loaded_modules: vec!["libc.so".into()],
        }
    }

    #[test]
    fn converts_process_event_kinds() {
        let base = CoreProcessEvent {
            id: Uuid::new_v4(),
            kind: ProcessEventKind::Created,
            process: sample_process_info(),
            event_time: Utc::now(),
        };
        let proto_created = core_process_event_to_proto(base.clone());
        assert_eq!(
            proto_created.kind,
            crate::host::process_event::Kind::Created as i32,
        );
        assert!(proto_created.process.is_some());
        let process = proto_created.process.unwrap();
        assert_eq!(process.pid, 42);
        assert_eq!(process.name, "bash");
        assert_eq!(process.exe_path, "/bin/bash");
        assert_eq!(process.loaded_modules, vec!["libc.so".to_string()]);

        let mut terminated = base.clone();
        terminated.kind = ProcessEventKind::Terminated;
        assert_eq!(
            core_process_event_to_proto(terminated).kind,
            crate::host::process_event::Kind::Terminated as i32,
        );

        let mut modified = base;
        modified.kind = ProcessEventKind::Modified;
        assert_eq!(
            core_process_event_to_proto(modified).kind,
            crate::host::process_event::Kind::Modified as i32,
        );
    }

    #[test]
    fn converts_file_event_kinds() {
        let base = CoreFileEvent {
            id: Uuid::new_v4(),
            kind: FileEventKind::Created,
            path: "/tmp/x".into(),
            sha256: Some("cafebabe".into()),
            size: Some(1_024),
            event_time: Utc::now(),
        };
        let proto = core_file_event_to_proto(base.clone());
        assert_eq!(proto.path, "/tmp/x");
        assert_eq!(proto.sha256, "cafebabe");
        assert_eq!(proto.size, 1_024);
        assert_eq!(proto.kind, crate::host::file_event::Kind::Created as i32);

        for (core_kind, expected) in [
            (
                FileEventKind::Modified,
                crate::host::file_event::Kind::Modified,
            ),
            (
                FileEventKind::Deleted,
                crate::host::file_event::Kind::Deleted,
            ),
            (
                FileEventKind::Renamed,
                crate::host::file_event::Kind::Renamed,
            ),
        ] {
            let mut e = base.clone();
            e.kind = core_kind;
            assert_eq!(core_file_event_to_proto(e).kind, expected as i32);
        }
    }

    #[test]
    fn handles_missing_optional_fields() {
        let proto = core_file_event_to_proto(CoreFileEvent {
            id: Uuid::new_v4(),
            kind: FileEventKind::Deleted,
            path: "/gone".into(),
            sha256: None,
            size: None,
            event_time: Utc::now(),
        });
        assert_eq!(proto.sha256, "");
        assert_eq!(proto.size, 0);
    }

    /// Exercising the GRPC-METADATA fix: control characters in metadata
    /// values (and in `message`) must be stripped before crossing the
    /// gRPC boundary.
    #[test]
    fn alert_to_proto_sanitizes_metadata_and_message() {
        let mut metadata = HashMap::new();
        metadata.insert(
            "cmdline".to_string(),
            "powershell\n[ALERT]\nSEVERITY=critical".to_string(),
        );
        metadata.insert("clean".to_string(), "C:\\Users\\bob".to_string());

        let alert = CoreAlert {
            id: Uuid::new_v4(),
            severity: CoreAlertSeverity::High,
            kind: "test".into(),
            message: "first\r\nsecond".into(),
            occurred_at: Utc::now(),
            metadata,
            rule_id: None,
            attack_id: None,
        };
        let proto = core_alert_to_proto(alert);

        let cmdline = proto.metadata.get("cmdline").expect("cmdline key");
        assert!(!cmdline.contains('\n'));
        assert!(!cmdline.contains('\r'));

        // Printable ASCII / valid Unicode is preserved verbatim.
        assert_eq!(proto.metadata.get("clean").unwrap(), "C:\\Users\\bob");

        // The `message` field is also sanitized at the boundary.
        assert!(!proto.message.contains('\n'));
        assert!(!proto.message.contains('\r'));
    }

    /// Smoke test: `watch_filesystem` returns a live gRPC stream on a valid
    /// temporary directory.  We don't assert that any event is produced
    /// (platform watchers may batch or suppress changes during test runs),
    /// only that the RPC wires through without error and yields a stream
    /// that stays open long enough to attempt a `recv`.
    ///
    /// Ignored by default: on Linux, `LinuxFsScanner::watch_path` spawns a
    /// `tokio::task::spawn_blocking` thread that loops on
    /// `inotify::Inotify::read_events_blocking`. Tokio cannot abort blocking
    /// threads at runtime drop, so the test binary stays alive after this
    /// test returns and `cargo test` hangs until the CI runner timeout.
    /// Run explicitly with `cargo test -- --ignored` once the FIM watcher
    /// migrates to `inotify::EventStream` (async, cancel-on-drop).
    #[tokio::test]
    #[ignore = "hangs on Linux: LinuxFsScanner uses spawn_blocking + read_events_blocking; switch to async EventStream"]
    async fn watch_filesystem_smoke() {
        use std::time::Duration;
        use tokio_stream::StreamExt;

        let dir = tempfile::tempdir().expect("tempdir");
        // Allow the tempdir explicitly so the path passes the GRPC-PATH gate.
        let allowed = AllowedRoots::new([dir.path()]);
        let svc = HostAnalyzerService::new(allowed);

        let req = Request::new(crate::host::ScanRequest {
            root_path: dir.path().to_string_lossy().into_owned(),
            recursive: false,
            include_exts: vec![],
            max_size_bytes: 0,
        });

        // If the platform watcher cannot start on a transient tempdir (some CI
        // sandboxes block inotify / ReadDirectoryChangesW), accept the error
        // as a non-failure — the wiring is what we're testing.
        let Ok(resp) = svc.watch_filesystem(req).await else {
            return;
        };
        let mut stream = resp.into_inner();

        // Trigger a couple of filesystem events; ignore propagation races.
        let target = dir.path().join("smoke.txt");
        let _ = tokio::fs::write(&target, b"hello").await;

        // Poll with a short timeout; we accept either an event or timeout.
        let _ = tokio::time::timeout(Duration::from_millis(250), stream.next()).await;
    }
}
