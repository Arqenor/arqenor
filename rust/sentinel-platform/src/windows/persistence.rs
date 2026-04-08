use async_trait::async_trait;
use sentinel_core::{
    error::SentinelError,
    models::persistence::{PersistenceEntry, PersistenceKind},
    traits::persistence::PersistenceDetector,
};

#[cfg(windows)]
use winreg::{
    enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE},
    RegKey,
};

pub struct WindowsPersistenceDetector;

impl WindowsPersistenceDetector {
    pub fn new() -> Self {
        Self
    }
}

const RUN_KEYS: &[(&str, &str)] = &[
    (
        "HKLM",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    ),
    (
        "HKLM",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    ),
    (
        "HKCU",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    ),
    (
        "HKCU",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    ),
];

#[async_trait]
impl PersistenceDetector for WindowsPersistenceDetector {
    async fn detect(&self) -> Result<Vec<PersistenceEntry>, SentinelError> {
        let mut entries = Vec::new();

        #[cfg(windows)]
        for (hive_name, subkey) in RUN_KEYS {
            let hive = match *hive_name {
                "HKLM" => RegKey::predef(HKEY_LOCAL_MACHINE),
                "HKCU" => RegKey::predef(HKEY_CURRENT_USER),
                _      => continue,
            };

            let key = match hive.open_subkey(subkey) {
                Ok(k)  => k,
                Err(_) => continue,
            };

            for (name, value) in key.enum_values().filter_map(|r| r.ok()) {
                entries.push(PersistenceEntry {
                    kind:     PersistenceKind::RegistryRun,
                    name:     name.clone(),
                    command:  value.to_string(),
                    location: format!("{}\\{}", hive_name, subkey),
                    is_new:   false,
                });
            }
        }

        // TODO Phase 2: enumerate Scheduled Tasks via ITaskService COM
        // TODO Phase 2: enumerate Windows Services via OpenSCManager

        Ok(entries)
    }

    async fn diff_baseline(
        &self,
        baseline: &[PersistenceEntry],
    ) -> Result<Vec<PersistenceEntry>, SentinelError> {
        let current = self.detect().await?;
        let new_entries = current
            .into_iter()
            .filter(|e| {
                !baseline
                    .iter()
                    .any(|b| b.name == e.name && b.location == e.location)
            })
            .map(|mut e| { e.is_new = true; e })
            .collect();
        Ok(new_entries)
    }
}
