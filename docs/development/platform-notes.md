# Platform-specific Notes

## Codebase platform dispatch

All platform-specific code lives in `rust/arqenor-platform/src/`:

```
arqenor-platform/src/
├── lib.rs           # Factory functions — the only public API
├── windows/
│   ├── process_monitor.rs
│   ├── persistence.rs
│   └── fs_scanner.rs
├── linux/
│   ├── process_monitor.rs
│   ├── persistence.rs
│   └── fs_scanner.rs
└── macos/
    ├── process_monitor.rs
    ├── persistence.rs
    └── fs_scanner.rs
```

`lib.rs` uses `cfg_if!` to select the right module at compile time:

```rust
use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(target_os = "windows")] {
        mod windows;
        pub use windows::process_monitor::WindowsProcessMonitor as PlatformProcessMonitor;
        // ...
    } else if #[cfg(target_os = "linux")] {
        mod linux;
        pub use linux::process_monitor::LinuxProcessMonitor as PlatformProcessMonitor;
        // ...
    } else if #[cfg(target_os = "macos")] {
        mod macos;
        pub use macos::process_monitor::MacosProcessMonitor as PlatformProcessMonitor;
        // ...
    }
}
```

**Rule:** never put `#[cfg(target_os = ...)]` outside of `arqenor-platform`. All other crates use the trait `ProcessMonitor` only.

### Cross-platform helpers

Two modules are now shared by all platform impls:

- `arqenor_platform::hash` — streaming SHA-256 (`sha256_file_streaming`, 64 KiB chunks, capped at `DEFAULT_MAX_HASH_SIZE = 512 MiB`). Replaces `fs::read + Sha256::digest` everywhere.
- `arqenor_platform::path_validate` — `ensure_no_reparse(path)` rejects symlinks and reparse points on every component; `ensure_no_reparse_strict(path)` (Linux only) additionally refuses world-writable parents outside `/tmp /var/tmp /dev/shm`. Called at the entry of `WindowsFsScanner::scan_path`, before `CreateFileW(FILE_FLAG_BACKUP_SEMANTICS)`, and before `inotify::add` on Linux.

---

## Windows

### Process monitoring

- **Current:** `sysinfo` crate — snapshot via `CreateToolhelp32Snapshot` internally
- **Phase 2:** ETW (Event Tracing for Windows) via the `windows` crate for real-time streaming events without polling

Privileges required:
- `SeDebugPrivilege` — needed to open handles to SYSTEM processes for full enumeration
- Without elevation: user-space processes are visible, SYSTEM processes may be partially hidden

### Persistence detection

| Mechanism | Registry path | Requires elevation |
|---|---|---|
| HKLM Run | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Yes |
| HKLM RunOnce | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` | Yes |
| HKCU Run | `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | No |
| HKCU RunOnce | `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` | No |
| Startup folder | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` | No |
| Scheduled Tasks | `C:\Windows\System32\Tasks\` | Yes (full tree) |
| Windows Services | SCM via `OpenSCManager` | Partial without elevation |

Implementation uses `winreg` for registry access and the `windows` crate for service enumeration.

### Filesystem

- `walkdir` for recursive scanning
- Inotify equivalent (ReadDirectoryChangesW) planned for Phase 2
- Paths use `\\` separators internally; convert with `Path::to_string_lossy()`

### Network capture (Phase 3)

Requires [Npcap](https://npcap.com/) installed in WinPcap compatibility mode. `gopacket` uses Npcap's `wpcap.dll`.

### ETW provider coverage

`windows::etw_consumer` enforces minimum coverage at session start. Providers are bucketed by `ProviderGroup` (Process, File, Network, Security). The session refuses to start unless at least one Process provider plus at least one File or Network provider attach successfully — this prevents silent "we attached zero providers but the session is up" failures. When `attached == 0`, an explicit `error!` is logged.

### Credential-store accessor and PID recycling

`windows::cred_guard` captures `ProcessIdentity { exe_path, creation_time }` at enumeration time via `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `QueryFullProcessImageNameW` + `GetProcessTimes`. Before emitting an alert, the current `creation_time` is re-read; if it has changed, the PID has been recycled and the alert is skipped with a `warn!`.

### Memory scan PPL fallback

`windows::memory_scan` falls back to `PROCESS_QUERY_LIMITED_INFORMATION` when `OpenProcess(PROCESS_VM_READ)` is denied (typically PPL-protected processes). The result struct exposes `vm_read_denied: bool`. Modules are still enumerated via Toolhelp; only hollowing detection is skipped in that mode.

### WMI (planned Phase 2)

The `wmi` crate allows rich process enrichment (parent process name, command line, signed binary check). Requires COM initialization — must be done on a dedicated thread (not Tokio task) due to COM apartment threading model.

---

## Linux

### Process monitoring

- `procfs` crate reads `/proc/<pid>/` entries directly — no polling, low overhead
- `inotify` (`inotify` crate) for filesystem watch without polling

Privileges:
- Root or `CAP_SYS_PTRACE` for reading other users' process cmdlines
- Without: `/proc/<pid>/cmdline` for processes owned by other users is inaccessible (read returns empty)

### Persistence detection

| Mechanism | Location |
|---|---|
| System cron | `/etc/cron*`, `/var/spool/cron/crontabs/` |
| User cron | `/var/spool/cron/crontabs/<user>` |
| Systemd system units | `/etc/systemd/system/`, `/lib/systemd/system/` |
| Systemd user units | `~/.config/systemd/user/` |
| LD_PRELOAD | `/etc/ld.so.preload`, `LD_PRELOAD` env in `/proc/*/environ` |
| rc.local | `/etc/rc.local` |

### inotify limits

Default `fs.inotify.max_user_watches` is 8192 on many distros — too low for watching large directories. Raise it:

```bash
echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### eBPF (Phase 2)

Planned: use `libbpf` bindings or `aya` (pure-Rust eBPF) for kernel-level process event streaming. Requires kernel 5.8+ for ring buffers. Falls back to `procfs` polling on older kernels.

---

## macOS

### Process monitoring

- `sysinfo` with macOS backend (uses `sysctl` and `proc_pidinfo`)
- Full process list requires no special entitlement in most cases

Privileges:
- System Integrity Protection (SIP) limits access to some Apple-signed daemons — expected, not a bug
- `taskport_for_pid` for memory introspection requires `com.apple.security.cs.debugger` entitlement

### Persistence detection

| Mechanism | Location |
|---|---|
| LaunchDaemons (system) | `/Library/LaunchDaemons/*.plist` |
| LaunchAgents (system) | `/Library/LaunchAgents/*.plist` |
| LaunchAgents (user) | `~/Library/LaunchAgents/*.plist` |

Plists are parsed with the `plist` crate. Each entry is parsed for `ProgramArguments`, `Program`, `RunAtLoad`, and `StartInterval` keys.

### ES Framework (Phase 2)

Apple's Endpoint Security framework (`libEndpointSecurity`) provides kernel-level event streaming. Requires:

- macOS 10.15+
- `com.apple.developer.endpoint-security.client` entitlement (requires Apple provisioning)
- System Extensions approval by user

The `macos/process_monitor.rs` placeholder will be replaced with ES framework bindings in Phase 2.

### Network capture (Phase 3)

Uses `libpcap` (available via Xcode command line tools). No additional installation needed on macOS.

---

## Adding a new platform

1. Create `rust/arqenor-platform/src/<platform>/`:
   - `process_monitor.rs` — implement `ProcessMonitor`
   - `persistence.rs` — implement `PersistenceDetector`
   - `fs_scanner.rs` — implement `FsScanner`

2. Add platform-specific deps in `arqenor-platform/Cargo.toml`:
   ```toml
   [target.'cfg(target_os = "yourplatform")'.dependencies]
   some-platform-crate = "1.0"
   ```

3. Register in `arqenor-platform/src/lib.rs` inside the `cfg_if!` block

4. Update this document with capability matrix and privilege notes
