# TODO — Phase 2 : Kernel Telemetry (ETW + eBPF)
> Q3 2026 | ~30 ATT&CK techniques | Priorité : HAUTE
> Last updated: 2026-04-10

Légende : `[ ]` à faire · `[~]` en cours · `[x]` terminé

---

## SECTION A — Windows ETW Consumer

> fichiers : `rust/sentinel-platform/src/windows/etw_consumer.rs` + `etw_monitor.rs`

- [x] **A1** — Session ETW temps-réel
  - `StartTrace → EnableTraceEx2 × N → OpenTrace → ProcessTrace` (thread dédié)
  - Handles : `CONTROLTRACE_HANDLE` (session) + `PROCESSTRACE_HANDLE` (trace)
  - Canal `std::sync::mpsc` borné (2048) → callback non-bloquant

- [x] **A2** — Providers activés (6 / phase 2.1)
  - `Microsoft-Windows-Kernel-Process`    `{22FB2CD6-…}` — start/stop/image-load
  - `Microsoft-Windows-PowerShell`        `{A0C1853B-…}` — script-block 4104
  - `Microsoft-Windows-Security-Auditing` `{54849625-…}` — 4688/4698/4702/4720/4732
  - `Microsoft-Windows-DNS-Client`        `{1C95126E-…}` — requêtes DNS 3006
  - `Microsoft-Windows-WMI-Activity`      `{1418EF04-…}` — 5861 event consumer
  - `Microsoft-Windows-TaskScheduler`     `{DE7B24EA-…}` — task launch 106

- [x] **A3** — ETW → Alert bridge (`etw_monitor.rs`)
  - 7 règles ETW (ETW-1001 → ETW-1007) : PS 4104, tasks 4698/4702/106, user 4720/4732, WMI 5861
  - `EtwMonitor::run_blocking()` → thread dédié `etw-monitor`
  - `new_etw_monitor()` factory dans `lib.rs`

- [x] **A4** — Providers supplémentaires `T1021.002 / T1005`
  - `Microsoft-Windows-Kernel-Network` `{7DD42A49-…}` — TCP connect (evt 12), UDP send (evt 15)
  - `Microsoft-Windows-Kernel-File`    `{EDD08927-…}` — file create (evt 12) pour FIM temps-réel
  - `Microsoft-Windows-Kernel-Registry` — opérations registre

- [ ] **A5** — TDH parsing des propriétés `UserData`
  - `TdhGetEventInformation` → décoder les bytes en champs typés (cmdline, filename, domain…)
  - Permet le filtrage sur contenu : PS 4104 + IOC regex, DNS 3006 + C2 domain list
  - Nécessite feature `Win32_System_Diagnostics_Etw` étendue + `TDH` linking

- [x] **A6** — UI : onglet « ETW Stream » dans `sentinel-desktop`
  - Liste temps-réel des événements ETW haute-valeur
  - Filtre par provider / event_id / PID
  - Badge compteur dans sidebar

---

## SECTION B — Linux eBPF Agent

> nouveau crate : `sentinel-ebpf/` (C probes + Rust loader libbpf-rs)

- [ ] **B1** — Créer le crate `sentinel-ebpf` (workspace member)
  - `sentinel-ebpf/src/probes/` — programmes eBPF en C (compilés avec clang)
  - `sentinel-ebpf/src/loader.rs` — loader Rust avec `libbpf-rs`
  - `sentinel-ebpf/src/events.rs` — struct `EbpfEvent` + ring buffer consumer

- [ ] **B2** — Probes exécution de processus `T1059`
  - `tracepoint/syscalls/sys_enter_execve` → capture filename + argv
  - `tracepoint/syscalls/sys_enter_execveat` → dirfd + filename

- [ ] **B3** — Probes injection mémoire `T1055`
  - `kprobe/do_mmap` → flag PROT_EXEC | PROT_WRITE combinés
  - `kprobe/ptrace` → attach à un autre process (T1055.008)

- [ ] **B4** — Probes persistence `T1574.006 / T1053`
  - `sys_enter_write` → écriture sur `/etc/ld.so.preload`
  - `sys_enter_openat` → ouverture de `/etc/cron.d/`, `/etc/systemd/system/`

- [ ] **B5** — Probes privilege escalation `T1068`
  - `kprobe/commit_creds` → changement uid/gid
  - `kprobe/prepare_kernel_cred` → setuid(0) depuis process non-root

- [ ] **B6** — Probe chargement de module kernel `T1014`
  - `kprobe/do_init_module` → nom du module + hash

- [ ] **B7** — Pipeline eBPF → sentinel-core
  - BPF ring buffer → `libbpf-rs` → `tokio::sync::mpsc::Sender<EbpfEvent>`
  - `EbpfEvent` → règles de détection → `Alert`

---

## SECTION C — Kernel Driver Windows (Phase 2b, long-term)

> nouveau crate : `sentinel-driver/` (WDK — windows-drivers-rs)

- [ ] **C1** — Setup crate `sentinel-driver` avec WDK toolchain
- [ ] **C2** — Minifilter file-system (`FltRegisterFilter`) — FIM kernel-level
- [ ] **C3** — Registry callbacks (`CmRegisterCallback`)
- [ ] **C4** — Process notify (`PsSetCreateProcessNotifyRoutineEx`)
- [ ] **C5** — `ObRegisterCallbacks` — self-protection contre EDR killers
- [ ] **C6** — ETW-TI (`Microsoft-Windows-Threat-Intelligence`) — nécessite PPL
  - Accès à VirtualAllocEx, WriteProcessMemory, SetThreadContext…
  - Requiert Microsoft-signed driver → WHQL + EV cert (6-9 mois)

---

## SECTION D — macOS: Endpoint Security Framework

> nouveau crate : `sentinel-esf/` (Swift + Rust FFI)

- [ ] **D1** — Swift module `ESAgent.swift` avec `es_new_client`
- [ ] **D2** — Events : `ES_EVENT_TYPE_NOTIFY_EXEC`, `ES_EVENT_TYPE_NOTIFY_CREATE`
- [ ] **D3** — `ES_EVENT_TYPE_AUTH_EXEC` — blocage d'exécution (mode prévention)
- [ ] **D4** — FFI Rust ↔ Swift (cbindgen / Swift Package Manager)

---

## Ordre d'exécution recommandé

```
A1 → A2 → A3   ✅ ETW consumer + bridge opérationnels
     ↓
A4             → providers réseau + fichier (quick win)
     ↓
A5             → TDH parsing (contenu, IOC matching)
     ↓
A6             → UI ETW stream
     ↓
B1 → B7        → Linux eBPF (parallélisable avec A5/A6)
     ↓
C1 → C6        → Driver Windows (long-term, ~6-9 mois)
D1 → D4        → macOS ESF (parallélisable)
```

---

## Crates touchées

| Crate | Sections | Statut |
|-------|----------|--------|
| `sentinel-platform` (Windows) | A1, A2, A3 | ✅ |
| `sentinel-platform` (Windows) | A4, A5 | ⏳ pending (A4 ✅) |
| `sentinel-desktop` | A6 | ✅ |
| `sentinel-ebpf` (nouveau) | B1–B7 | ⏳ pending |
| `sentinel-driver` (nouveau) | C1–C6 | 🔴 long-term |
| `sentinel-esf` (nouveau) | D1–D4 | ⏳ pending |
