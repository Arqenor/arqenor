use crate::{
    common,
    host::{
        host_analyzer_server::HostAnalyzer,
        FileEvent as ProtoFileEvent,
        HealthResponse,
        PersistenceEntry as ProtoPersistenceEntry,
        PersistenceResponse,
        ProcessInfo as ProtoProcessInfo,
        ScanRequest,
        SnapshotResponse,
        ProcessEvent as ProtoProcessEvent,
    },
};
use sentinel_core::{
    models::alert::Severity as CoreSeverity,
    pipeline::{DetectionPipeline, PipelineConfig},
};
use sentinel_platform::{new_fs_scanner, new_persistence_detector, new_process_monitor};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

pub struct HostAnalyzerService;

impl HostAnalyzerService {
    pub fn new() -> Self {
        Self
    }
}

// ── Platform-specific FIM default path ───────────────────────────────────────

fn default_fim_path() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    { std::path::PathBuf::from(r"C:\Windows\System32") }
    #[cfg(not(target_os = "windows"))]
    { std::path::PathBuf::from("/etc") }
}

// ── Alert conversion ──────────────────────────────────────────────────────────

fn core_alert_to_proto(a: sentinel_core::models::alert::Alert) -> common::Alert {
    let sev = match a.severity {
        CoreSeverity::Info     => common::Severity::Info as i32,
        CoreSeverity::Low      => common::Severity::Low as i32,
        CoreSeverity::Medium   => common::Severity::Medium as i32,
        CoreSeverity::High     => common::Severity::High as i32,
        CoreSeverity::Critical => common::Severity::Critical as i32,
    };
    let occurred_at = Some(prost_types::Timestamp {
        seconds: a.occurred_at.timestamp(),
        nanos:   a.occurred_at.timestamp_subsec_nanos() as i32,
    });
    common::Alert {
        id:          a.id.to_string(),
        severity:    sev,
        kind:        a.kind,
        message:     a.message,
        occurred_at,
        metadata:    a.metadata,
        rule_id:     a.rule_id.unwrap_or_default(),
        attack_id:   a.attack_id.unwrap_or_default(),
    }
}

// ── HostAnalyzer implementation ───────────────────────────────────────────────

#[tonic::async_trait]
impl HostAnalyzer for HostAnalyzerService {
    type WatchProcessesStream  = ReceiverStream<Result<ProtoProcessEvent, Status>>;
    type ScanFilesystemStream  = ReceiverStream<Result<ProtoFileEvent, Status>>;
    type WatchFilesystemStream = ReceiverStream<Result<ProtoFileEvent, Status>>;
    type WatchAlertsStream     = ReceiverStream<Result<common::Alert, Status>>;

    async fn get_process_snapshot(
        &self,
        _req: Request<()>,
    ) -> Result<Response<SnapshotResponse>, Status> {
        let monitor = new_process_monitor();
        let procs   = monitor
            .snapshot()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let proto_procs = procs
            .into_iter()
            .map(|p| ProtoProcessInfo {
                pid:            p.pid,
                ppid:           p.ppid,
                name:           p.name,
                exe_path:       p.exe_path.unwrap_or_default(),
                cmdline:        p.cmdline.unwrap_or_default(),
                user:           p.user.unwrap_or_default(),
                sha256:         p.sha256.unwrap_or_default(),
                started_at:     None,
                loaded_modules: p.loaded_modules,
            })
            .collect();

        Ok(Response::new(SnapshotResponse {
            processes:   proto_procs,
            captured_at: None,
        }))
    }

    async fn watch_processes(
        &self,
        _req: Request<()>,
    ) -> Result<Response<Self::WatchProcessesStream>, Status> {
        Err(Status::unimplemented("watch_processes: ETW/eBPF coming in Phase 2"))
    }

    async fn scan_filesystem(
        &self,
        req: Request<ScanRequest>,
    ) -> Result<Response<Self::ScanFilesystemStream>, Status> {
        let r       = req.into_inner();
        let scanner = new_fs_scanner();
        let config  = sentinel_core::models::file_event::ScanConfig {
            recursive:          r.recursive,
            include_extensions: r.include_exts,
            max_size_bytes:     (r.max_size_bytes > 0).then_some(r.max_size_bytes),
            compute_hash:       true,
        };

        let root   = std::path::PathBuf::from(&r.root_path);
        let events = scanner
            .scan_path(&root, &config)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let (tx, rx) = mpsc::channel(128);
        tokio::spawn(async move {
            for e in events {
                let proto = ProtoFileEvent {
                    kind:       e.kind as i32,
                    path:       e.path,
                    sha256:     e.sha256.unwrap_or_default(),
                    size:       e.size.unwrap_or(0),
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
        _req: Request<ScanRequest>,
    ) -> Result<Response<Self::WatchFilesystemStream>, Status> {
        Err(Status::unimplemented("watch_filesystem: inotify/FSEvents coming in Phase 2"))
    }

    async fn get_persistence(
        &self,
        _req: Request<()>,
    ) -> Result<Response<PersistenceResponse>, Status> {
        let detector = new_persistence_detector();
        let entries  = detector
            .detect()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let proto_entries = entries
            .into_iter()
            .map(|e| ProtoPersistenceEntry {
                kind:     format!("{:?}", e.kind),
                name:     e.name,
                command:  e.command,
                location: e.location,
                is_new:   e.is_new,
            })
            .collect();

        Ok(Response::new(PersistenceResponse { entries: proto_entries }))
    }

    async fn health(
        &self,
        _req: Request<()>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status:   "ok".into(),
            platform: std::env::consts::OS.into(),
            version:  env!("CARGO_PKG_VERSION").into(),
        }))
    }

    /// Stream real-time detection alerts to the caller.
    ///
    /// On each connection:
    ///   1. Starts process and filesystem watchers (non-fatal if unsupported).
    ///   2. Runs the `DetectionPipeline` (LOLBin + sensitive-path rules).
    ///   3. Streams resulting `Alert`s until the client disconnects.
    async fn watch_alerts(
        &self,
        _req: Request<()>,
    ) -> Result<Response<Self::WatchAlertsStream>, Status> {
        let (proc_tx, proc_rx) = mpsc::channel(512);
        let (fim_tx,  fim_rx)  = mpsc::channel(512);
        let (core_tx, mut core_rx) =
            mpsc::channel::<sentinel_core::models::alert::Alert>(256);

        // Start watchers — ignore errors (platform may not support them).
        let _ = new_process_monitor().watch(proc_tx).await;
        let _ = new_fs_scanner().watch_path(&default_fim_path(), fim_tx).await;

        // Run the detection pipeline in a background task.
        let pipeline = DetectionPipeline::new(PipelineConfig::default(), proc_rx, fim_rx, core_tx);
        tokio::spawn(pipeline.run());

        // Bridge core Alert → proto Alert on the stream channel.
        let (stream_tx, stream_rx) = mpsc::channel::<Result<common::Alert, Status>>(256);
        tokio::spawn(async move {
            while let Some(alert) = core_rx.recv().await {
                if stream_tx.send(Ok(core_alert_to_proto(alert))).await.is_err() {
                    break; // client disconnected
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(stream_rx)))
    }
}
