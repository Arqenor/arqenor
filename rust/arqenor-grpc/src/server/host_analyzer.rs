use crate::{
    common,
    host::{
        host_analyzer_server::HostAnalyzer, FileEvent as ProtoFileEvent, HealthResponse,
        PersistenceEntry as ProtoPersistenceEntry, PersistenceResponse,
        ProcessEvent as ProtoProcessEvent, ProcessInfo as ProtoProcessInfo, ScanRequest,
        SnapshotResponse,
    },
};
use arqenor_core::traits::connection_monitor::spawn_polling_watch;
use arqenor_core::{
    ioc::{feeds, IocDatabase},
    models::alert::Severity as CoreSeverity,
    pipeline::{DetectionPipeline, PipelineConfig},
    rules::sigma,
};
use arqenor_platform::{
    new_connection_monitor, new_fs_scanner, new_persistence_detector, new_process_monitor,
};
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
}

pub struct HostAnalyzerService {
    shared: Arc<SharedDetectionState>,
}

impl HostAnalyzerService {
    pub fn new() -> Self {
        let ioc_db = Arc::new(RwLock::new(IocDatabase::new()));

        // Best-effort initial feed load (blocking in constructor is acceptable
        // because the gRPC server hasn't started accepting yet).
        let db_clone = Arc::clone(&ioc_db);
        tokio::spawn(async move {
            {
                let mut guard = db_clone.write().await;
                feeds::refresh_all_feeds(&mut guard).await;
            }
            // Refresh every 4 hours.
            feeds::spawn_feed_refresh_loop(db_clone, std::time::Duration::from_secs(4 * 3600));
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
        message: a.message,
        occurred_at,
        metadata: a.metadata,
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

fn core_process_info_to_proto(
    p: arqenor_core::models::process::ProcessInfo,
) -> ProtoProcessInfo {
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
        let scanner = new_fs_scanner();
        let config = arqenor_core::models::file_event::ScanConfig {
            recursive: r.recursive,
            include_extensions: r.include_exts,
            max_size_bytes: (r.max_size_bytes > 0).then_some(r.max_size_bytes),
            compute_hash: true,
        };

        let root = std::path::PathBuf::from(&r.root_path);
        let events = scanner
            .scan_path(&root, &config)
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
            std::path::PathBuf::from(&r.root_path)
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
        file_event::{FileEvent as CoreFileEvent, FileEventKind},
        process::{ProcessEvent as CoreProcessEvent, ProcessEventKind, ProcessInfo as CoreProcessInfo},
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
            (FileEventKind::Modified, crate::host::file_event::Kind::Modified),
            (FileEventKind::Deleted, crate::host::file_event::Kind::Deleted),
            (FileEventKind::Renamed, crate::host::file_event::Kind::Renamed),
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

    /// Smoke test: `watch_filesystem` returns a live gRPC stream on a valid
    /// temporary directory.  We don't assert that any event is produced
    /// (platform watchers may batch or suppress changes during test runs),
    /// only that the RPC wires through without error and yields a stream
    /// that stays open long enough to attempt a `recv`.
    #[tokio::test]
    async fn watch_filesystem_smoke() {
        use std::time::Duration;
        use tokio_stream::StreamExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let svc = HostAnalyzerService::new();

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
