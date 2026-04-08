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
  --interval <SECS>   Seconds between scans [default: 30]
  -h, --help          Print help
```

Watch mode runs `scan --host --persistence` in a loop, printing only **changes** relative to the previous snapshot:

```
[2026-04-08 14:32:00] New process: unknown.exe (PID 9012, SYSTEM, RISK: HIGH)
[2026-04-08 14:32:00] New persistence: RegistryRun "MyCoolApp" → C:\Temp\evil.exe  [NEW]
[2026-04-08 14:32:30] Process terminated: unknown.exe (PID 9012)
```

Press `Ctrl+C` to stop.

### Suppress unchanged output

When nothing changes, watch mode prints nothing (silent by default). Use `--verbose` (planned) to always print the snapshot.

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
