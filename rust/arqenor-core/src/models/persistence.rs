use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PersistenceKind {
    // Windows
    RegistryRun,
    ScheduledTask,
    WindowsService,
    WmiSubscription,
    ComHijacking,
    DllSideloading,
    BitsJob,
    AppInitDll,
    IfeoHijack,
    AccessibilityHijack,
    PrintMonitor,
    LsaProvider,
    NetshHelper,
    ActiveSetup,
    // Linux
    SystemdUnit,
    Cron,
    RcLocal,
    LdPreload,
    KernelModule,
    SshAuthorizedKey,
    PamModule,
    ShellProfile,
    GitHook,
    // macOS
    LaunchDaemon,
    LaunchAgent,
    // Cross-platform
    StartupFolder,
    Unknown(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceEntry {
    pub kind: PersistenceKind,
    pub name: String,
    pub command: String,
    pub location: String,
    pub is_new: bool,
}
