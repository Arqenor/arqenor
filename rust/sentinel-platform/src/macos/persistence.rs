use async_trait::async_trait;
use sentinel_core::{
    error::SentinelError,
    models::persistence::{PersistenceEntry, PersistenceKind},
    traits::persistence::PersistenceDetector,
};
use std::{fs, path::Path};

pub struct MacosPersistenceDetector;

impl MacosPersistenceDetector {
    pub fn new() -> Self {
        Self
    }
}

const LAUNCH_DIRS: &[(&str, PersistenceKind)] = &[
    ("/Library/LaunchDaemons",       PersistenceKind::LaunchDaemon),
    ("/Library/LaunchAgents",        PersistenceKind::LaunchAgent),
    ("/System/Library/LaunchDaemons", PersistenceKind::LaunchDaemon),
    ("/System/Library/LaunchAgents",  PersistenceKind::LaunchAgent),
];

fn user_launch_dirs() -> Vec<(String, PersistenceKind)> {
    if let Some(home) = std::env::var("HOME").ok() {
        vec![(format!("{}/Library/LaunchAgents", home), PersistenceKind::LaunchAgent)]
    } else {
        vec![]
    }
}

#[async_trait]
impl PersistenceDetector for MacosPersistenceDetector {
    async fn detect(&self) -> Result<Vec<PersistenceEntry>, SentinelError> {
        let mut entries = Vec::new();

        let static_dirs: Vec<(&str, &PersistenceKind)> =
            LAUNCH_DIRS.iter().map(|(p, k)| (*p, k)).collect();

        let user_dirs = user_launch_dirs();
        let dynamic_dirs: Vec<(&str, &PersistenceKind)> =
            user_dirs.iter().map(|(p, k)| (p.as_str(), k)).collect();

        for (dir, kind) in static_dirs.into_iter().chain(dynamic_dirs) {
            let path = Path::new(dir);
            if !path.exists() { continue; }
            if let Ok(rd) = fs::read_dir(path) {
                for entry in rd.filter_map(|e| e.ok()) {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if !name.ends_with(".plist") { continue; }
                    // TODO Phase 2: parse plist to extract ProgramArguments
                    entries.push(PersistenceEntry {
                        kind:     kind.clone(),
                        name:     name.clone(),
                        command:  String::new(),
                        location: entry.path().to_string_lossy().into_owned(),
                        is_new:   false,
                    });
                }
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
