use async_trait::async_trait;
use sentinel_core::{
    error::SentinelError,
    models::persistence::{PersistenceEntry, PersistenceKind},
    traits::persistence::PersistenceDetector,
};
use std::{fs, path::Path};

pub struct LinuxPersistenceDetector;

impl LinuxPersistenceDetector {
    pub fn new() -> Self {
        Self
    }
}

const SYSTEMD_DIRS: &[&str] = &[
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/run/systemd/system",
];

const CRON_DIRS: &[&str] = &[
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
];

#[async_trait]
impl PersistenceDetector for LinuxPersistenceDetector {
    async fn detect(&self) -> Result<Vec<PersistenceEntry>, SentinelError> {
        let mut entries = Vec::new();

        // systemd units
        for dir in SYSTEMD_DIRS {
            let path = Path::new(dir);
            if !path.exists() {
                continue;
            }
            if let Ok(rd) = fs::read_dir(path) {
                for entry in rd.filter_map(|e| e.ok()) {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if name.ends_with(".service") || name.ends_with(".timer") {
                        entries.push(PersistenceEntry {
                            kind:     PersistenceKind::SystemdUnit,
                            name:     name.clone(),
                            command:  String::new(), // TODO: parse ExecStart from unit file
                            location: entry.path().to_string_lossy().into_owned(),
                            is_new:   false,
                        });
                    }
                }
            }
        }

        // cron
        for dir in CRON_DIRS {
            let path = Path::new(dir);
            if !path.exists() {
                continue;
            }
            if let Ok(rd) = fs::read_dir(path) {
                for entry in rd.filter_map(|e| e.ok()) {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    entries.push(PersistenceEntry {
                        kind:     PersistenceKind::Cron,
                        name,
                        command:  String::new(),
                        location: entry.path().to_string_lossy().into_owned(),
                        is_new:   false,
                    });
                }
            }
        }

        // LD_PRELOAD
        if let Ok(val) = std::env::var("LD_PRELOAD") {
            if !val.is_empty() {
                entries.push(PersistenceEntry {
                    kind:     PersistenceKind::LdPreload,
                    name:     "LD_PRELOAD".into(),
                    command:  val.clone(),
                    location: "environment".into(),
                    is_new:   false,
                });
            }
        }

        Ok(entries)
    }

    async fn diff_baseline(
        &self,
        baseline: &[PersistenceEntry],
    ) -> Result<Vec<PersistenceEntry>, SentinelError> {
        let current = self.detect().await?;
        Ok(current
            .into_iter()
            .filter(|e| !baseline.iter().any(|b| b.name == e.name && b.location == e.location))
            .map(|mut e| { e.is_new = true; e })
            .collect())
    }
}
