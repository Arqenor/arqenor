# TODO — Phase 3 : Network Deep Analysis + C2 Detection

> Q3 2026 | ~20 ATT&CK techniques | Priorite : HAUTE
> Last updated: 2026-04-10

Legende : `[ ]` a faire · `[~]` en cours · `[x]` termine

---

## SECTION A — Windows Native Connections

> fichier : `rust/arqenor-platform/src/windows/connections.rs`

- [x] **A1** — Remplacer `netstat -ano` par `GetExtendedTcpTable` (IPv4 TCP)
  - Feature `Win32_NetworkManagement_IpHelper` active
  - Pattern two-pass : appel avec `None` pour la taille, puis allocation + second appel
  - Parse `MIB_TCPROW_OWNER_PID` : state, local/remote addr:port, PID

- [x] **A2** — Ajouter `GetExtendedUdpTable` (IPv4 UDP)
  - Parse `MIB_UDPROW_OWNER_PID` : local addr:port, PID

- [ ] **A3** — IPv6 support (TCP6 + UDP6)
  - `GetExtendedTcpTable` avec `AF_INET6`
  - Parse `MIB_TCP6ROW_OWNER_PID`

---

## SECTION B — Network Analysis Models

> fichier : `rust/arqenor-core/src/models/network.rs`

- [x] **B1** — `FlowKey` (src_ip, dst_ip, dst_port, proto)
- [x] **B2** — `FlowRecord` (timestamps, conn_count, first/last seen)
- [x] **B3** — `BeaconScore` (interval mean/stddev, CV, score 0.0-1.0)
- [x] **B4** — `DnsQuery` (domain, query_type, pid, timestamp)
- [x] **B5** — `DnsAnomalyScore` (tunneling_score, dga_score, entropy metrics)

---

## SECTION C — Network Detection Rules

> fichier : `rust/arqenor-core/src/rules/network.rs`

- [x] **C1** — C2 Beaconing `T1071`
  - `analyze_beaconing()` : coefficient of variation sur intervalles inter-connexion
  - CV < 0.1 = score 0.9, CV < 0.2 = 0.7, CV < 0.3 = 0.5
  - `beacon_alerts()` : seuil 0.7, severity High

- [x] **C2** — DNS Tunneling `T1071.004`
  - `analyze_dns_tunneling()` : groupe par domaine base, scoring sur :
    - longueur moyenne des sous-domaines (> 30 chars)
    - entropie Shannon (> 3.5 bits)
    - ratio unique subdomains (> 0.8)
    - volume (> 100 queries)
  - `dns_tunneling_alerts()` : severity Critical

- [x] **C3** — DGA Detection `T1568.002`
  - `score_dga()` : scoring leger base sur :
    - entropie des caracteres
    - ratio voyelles (< 20% = suspect)
    - ratio chiffres (> 40% = suspect)
    - longueur (12-20 chars = range DGA)
    - runs de consonnes consecutives > 4
  - `dga_alerts()` : severity Medium

- [x] **C4** — `shannon_entropy()` helper (bits par caractere)

---

## SECTION D — Pipeline Integration

> fichier : `rust/arqenor-core/src/pipeline.rs`

- [x] **D1** — Ajouter `conn_rx: Receiver<ConnectionInfo>` au `DetectionPipeline`
  - Constructeur `new()` cree un dummy channel (backwards compat)
  - `with_connections()` pour le vrai channel

- [x] **D2** — Flow table `HashMap<FlowKey, FlowRecord>` dans `run()`
  - Upsert sur chaque ConnectionInfo recue
  - Parse IP:port depuis les strings local_addr/remote_addr

- [x] **D3** — Analyse periodique (60s interval via `tokio::time::Interval`)
  - 4eme branche dans `tokio::select!`
  - Drain flow table, analyse beaconing, genere alertes

- [x] **D4** — `PipelineStats` += `conn_events: AtomicU64`

- [x] **D5** — Graceful multi-channel shutdown (process_open/file_open/conn_open flags)

---

## SECTION E — macOS ESF (complete dans cette session)

> fichiers : `rust/arqenor-platform/src/macos/`

- [x] **E1** — `esf_monitor.rs` : client ESF, 11 event types, muting, thread dedie
- [x] **E2** — `esf_dispatcher.rs` : singleton OnceLock, fan-out 1 ESF → N consumers
- [x] **E3** — `process_monitor.rs` : `watch()` branche sur ESF (EXEC/EXIT → ProcessEvent)
- [x] **E4** — `fs_scanner.rs` : `watch_path()` branche sur ESF (CREATE/WRITE/DELETE/RENAME → FileEvent)
- [x] **E5** — `persistence.rs` : plist parsing + Login Items, cron tabs, auth plugins, periodic, DYLD_INSERT_LIBRARIES
- [x] **E6** — `fim.rs` : `macos_critical_paths()` (hosts, sudoers, pam.d, LaunchDaemons, SecurityAgentPlugins)
- [x] **E7** — `Cargo.toml` : `endpoint-sec = "0.5"` dans deps macOS

---

## SECTION F — Remaining (Phase 3b)

- [x] **F1** — JA4 TLS fingerprinting
  - `tls_fingerprint.rs` : `compute_ja4()`, `parse_client_hello()`, `Ja4Blocklist::builtin()` (17 C2 fingerprints)
  - Cobalt Strike ×4, Sliver ×2, Metasploit ×2, Havoc, Brute Ratel ×2, PoshC2, Tor ×2, miners
  - `check_ja4_alerts()` → Alert with prefix + exact matching, 16 tests
- [ ] **F2** — Lateral movement patterns (SMB workstation-to-workstation)
- [ ] **F3** — Kerberoasting detection (TGS-REQ anomaly)
- [ ] **F4** — ARP cache poisoning / rogue gateway detection
- [x] **F5** — ConnectionMonitor::watch() polling impl (Win + Linux + macOS)
  - `spawn_polling_watch()` : polls `snapshot()` every 5s, dedup with HashSet, auto-stops on channel close
- [x] **F6** — Wire connection watch into CLI `arqenor watch` + gRPC `watch_alerts`
  - `conn_tx`/`conn_rx` channel, `DetectionPipeline::with_connections()`, fallback to polling if `NotSupported`
  - C2 beaconing + IOC IP checks now live in real-time

---

## Crates touchees

| Crate | Sections | Statut |
|-------|----------|--------|
| `arqenor-core` (models) | B1-B5 | ✅ |
| `arqenor-core` (rules) | C1-C4 | ✅ |
| `arqenor-core` (pipeline) | D1-D5 | ✅ |
| `arqenor-platform` (Windows) | A1-A2 | ✅ |
| `arqenor-platform` (macOS) | E1-E7 | ✅ |
| `arqenor-platform` (Windows) | A3 (IPv6) | ⏳ pending |
| `arqenor-core` (tls_fingerprint) | F1 | ✅ |
| `arqenor-core` (connection_monitor) | F5 | ✅ |
| `arqenor-cli` + `arqenor-grpc` | F6 | ✅ |
| Phase 3b | F2-F4 | ⏳ pending |
