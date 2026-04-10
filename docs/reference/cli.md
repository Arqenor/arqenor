# CLI Reference

Binary: `sentinel` (built from `sentinel-cli`)

```
sentinel [OPTIONS] <COMMAND>

Commands:
  scan    One-time scan snapshot
  watch   Continuous scan loop
  help    Print help

Options:
  --config <PATH>   Path to sentinel.toml [default: ./configs/sentinel.toml]
  --version         Print version
  -h, --help        Print help
```

---

## sentinel scan

```
sentinel scan [OPTIONS]

Options:
  --host             Scan running processes
  --persistence      Scan persistence mechanisms
  --json             Output JSON instead of formatted table
  -h, --help         Print help
```

At least one of `--host` or `--persistence` must be specified.

### Output: table mode (default)

```
Processes (42 running)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 PID    PPID   NAME              USER     RISK
 1      0      System            SYSTEM   Normal
 1234   800    chrome.exe        alice    Normal
 9012   1      unknown.exe       SYSTEM   HIGH

Persistence (3 entries)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 KIND          NAME          COMMAND                    NEW?
 RegistryRun   MyCoolApp     C:\Temp\evil.exe           YES
 Service       WinDefend     C:\ProgramData\...         no
```

### Output: JSON mode (`--json`)

```json
{
  "timestamp": 1712345678,
  "processes": [
    {
      "pid": 9012,
      "ppid": 1,
      "name": "unknown.exe",
      "exe_path": "C:\\Windows\\Temp\\unknown.exe",
      "cmdline": "unknown.exe --silent",
      "user": "SYSTEM",
      "sha256": "aabbccdd...",
      "loaded_modules": ["ntdll.dll", "kernel32.dll"],
      "risk": "HIGH"
    }
  ],
  "persistence": [
    {
      "kind": "RegistryRun",
      "name": "MyCoolApp",
      "command": "C:\\Temp\\evil.exe",
      "location": "HKCU\\...\\Run",
      "is_new": true
    }
  ]
}
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No anomalies at or above `min_severity` |
| `1` | One or more anomalies detected |
| `2` | Configuration error |
| `3` | Runtime / permission error |

---

## sentinel watch

```
sentinel watch [OPTIONS]

Options:
  --watch-path <PATH>   Directory to monitor for FIM [default: C:\Windows\System32 / /etc]
  --db <PATH>           SQLite database for alert persistence [default: sentinel.db]
  -h, --help            Print help
```

Watch mode starts a **real-time detection pipeline**:

1. **Process watcher** — Windows: EvtSubscribe (Security 4688/4689); Linux: /proc polling (500ms)
2. **FIM watcher** — Windows: ReadDirectoryChangesW; Linux: inotify
3. **Detection pipeline** — evaluates 15 LOLBin process rules + 9 file-path rules against live events
4. **Alert consumer** — prints alerts to stdout and persists to SQLite

```
$ sentinel watch --watch-path C:\Windows\System32
SENTINEL watch — 15 process rules, 9 file rules | FIM: C:\Windows\System32 | db: sentinel.db
Press Ctrl-C to stop.
────────────────────────────────────────────────────────────────────────

[HIGH] 14:32:05 | lolbin | PowerShell Encoded Command — PID 9012 (powershell.exe) | T1059.001
[CRIT] 14:32:10 | file_rule | Hosts File Modified — C:\Windows\System32\drivers\etc\hosts (modified) | T1565.001
[stats] proc:1247 file:83 alerts:2
```

Press `Ctrl+C` to stop. Session summary is printed on exit.

---

## sentinel-tui

```
sentinel-tui [OPTIONS]

Options:
  --config <PATH>    Path to sentinel.toml
  -h, --help         Print help
```

Launches the Ratatui dashboard. See [Usage Guide — Terminal UI](../guides/usage.md#terminal-ui-sentinel-tui) for keyboard controls.

---

## sentinel-grpc

```
sentinel-grpc [OPTIONS]

Options:
  --config <PATH>    Path to sentinel.toml [default: ./configs/sentinel.toml]
  --addr <ADDR>      Override gRPC listen address [default: 127.0.0.1:50051]
  -h, --help         Print help
```

Starts the Tonic gRPC server. Runs until `Ctrl+C`.

Logs to stdout in structured format:

```
2026-04-08T14:30:00Z  INFO sentinel_grpc: starting gRPC server addr=127.0.0.1:50051 platform=windows
2026-04-08T14:30:00Z  INFO sentinel_grpc: ready
```
