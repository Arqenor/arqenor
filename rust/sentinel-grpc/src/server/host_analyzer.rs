use crate::host::{
    host_analyzer_server::HostAnalyzer,
    FileEvent as ProtoFileEvent,
    HealthResponse,
    PersistenceEntry as ProtoPersistenceEntry,
    PersistenceResponse,
    ProcessInfo as ProtoProcessInfo,
    ScanRequest,
    SnapshotResponse,
    ProcessEvent as ProtoProcessEvent,
};
use sentinel_platform::{new_fs_scanner, new_persistence_detector, new_process_monitor};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

pub struct HostAnalyzerService;

impl HostAnalyzerService {
    pub fn new() -> Self {
        Self
    }
}

#[tonic::async_trait]
impl HostAnalyzer for HostAnalyzerService {
    type WatchProcessesStream  = ReceiverStream<Result<ProtoProcessEvent, Status>>;
    type ScanFilesystemStream  = ReceiverStream<Result<ProtoFileEvent, Status>>;
    type WatchFilesystemStream = ReceiverStream<Result<ProtoFileEvent, Status>>;

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

        let (tx, rx) = tokio::sync::mpsc::channel(128);
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
}
