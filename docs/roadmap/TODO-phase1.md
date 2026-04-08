# TODO — Phase 1 : Detection Engine + LOTL Rules
> Q2 2026 | ~40 ATT&CK techniques | Priorité : CRITIQUE

Légende : `[ ]` à faire · `[~]` en cours · `[x]` terminé

---

## SECTION A — sentinel-core : modèles + moteur de règles

- [x] **A1** — Ajouter `Alert` model avec champ `attack_id: String` et `severity: Severity`
  - fichier : `rust/sentinel-core/src/models/alert.rs` (existe, à compléter)
  - champs ajoutés : `attack_id`, `rule_id`, `metadata: HashMap<String,String>`

- [x] **A2** — Ajouter `ScoreFactor` pour l'explainabilité du scoring process
  - fichier : `rust/sentinel-core/src/models/process.rs`
  - struct `ProcessScore { total: u8, factors: Vec<ScoreFactor> }` ✅
  - struct `ScoreFactor { name: String, points: u8, attack_id: Option<String> }` ✅

- [x] **A3** — Créer le moteur de règles `sentinel-core/src/rules/`
  - [x] `mod.rs` — struct `DetectionRule`, enum `RuleCondition`, Pattern glob matcher
  - [x] `engine.rs` — fn `evaluate(rule, event) -> bool`, supporte `contains` / `endswith` / `regex`
  - [x] `lolbin.rs` — les 15 règles LOLBin hardcodées (SENT-1001 → SENT-1015)

---

## SECTION B — sentinel-platform (Windows) : persistence étendue

> fichier cible : `rust/sentinel-platform/src/windows/persistence.rs`

### B1 — WMI Event Subscriptions `T1546.003` · priorité P0
- [x] `wmic.exe /namespace:\\root\\subscription PATH __EventFilter/Consumer GET Name` parsé
- [x] Toute entrée non vide = `PersistenceEntry { kind: WmiSubscription }`
- [x] Ajouter `WmiSubscription` au enum `PersistenceKind` dans sentinel-core

### B2 — COM Hijacking HKCU `T1546.015` · priorité P0
- [x] Énumérer `HKCU\Software\Classes\CLSID\*\InprocServer32`
- [x] Croiser avec `HKLM\Software\Classes\CLSID\*` (HKCU = override = hijack potentiel)
- [x] Alerter si le DLL pointé n'est pas dans System32

### B3 — DLL Sideloading `T1574.002` · priorité P0
- [~] Stub compilant — implémentation complète requiert psapi/EnumProcessModules (Phase 2)

### B4 — BITS Jobs `T1197` · priorité P1
- [x] Parser `bitsadmin /list /allusers /verbose`
- [x] Flaguer les jobs qui pointent vers des URLs externes ou des chemins TEMP

### B5 — AppInit_DLLs `T1546.010` · priorité P1
- [x] Lire `HKLM\...\Windows\AppInit_DLLs` (64-bit + Wow6432Node)
- [x] Toute valeur non vide = alerte HIGH

### B6 — Image File Execution Options (IFEO) `T1546.012` · priorité P1
- [x] Énumérer `HKLM\...\Image File Execution Options\*`
- [x] Alerter si un sous-clé a `Debugger` = chemin vers un exécutable suspect

### B7 — Accessibility Features hijack `T1546.008` · priorité P1
- [x] SHA-256 de `sethc.exe`, `utilman.exe`, `osk.exe`, `narrator.exe`, `magnify.exe`
- [x] Flag si taille < 50 KB (remplacement par stub/hardlink)

### B8 — Print Monitor / LSA Provider `T1547.010 / T1547.002` · priorité P2
- [x] Lire `HKLM\SYSTEM\...\Print\Monitors\*`
- [x] Lire `HKLM\SYSTEM\...\Lsa\Authentication Packages`
- [x] Tout DLL/package non-Microsoft = HIGH

### B9 — Netsh Helper DLL `T1546.007` · priorité P2
- [x] Lire `HKLM\SOFTWARE\Microsoft\NetSh\*`
- [x] DLL hors System32 = HIGH

---

## SECTION C — sentinel-platform (Linux) : persistence étendue

> fichiers cibles : `rust/sentinel-platform/src/linux/persistence_detector.rs`

- [ ] **C1** — Systemd timers `T1053.006` — scanner `/etc/systemd/system/*.timer`
- [ ] **C2** — LD_PRELOAD `T1574.006` — lire `/etc/ld.so.preload`, alerter si non vide
- [ ] **C3** — Modules kernel `T1014` — parser `/proc/modules`, whitelist des modules connus
- [ ] **C4** — SSH authorized_keys `T1098.004` — FIM sur `~/.ssh/authorized_keys` de tous les users
- [ ] **C5** — PAM modules `T1556.003` — hash de `/etc/pam.d/*` + `/lib/security/*.so`
- [ ] **C6** — Shell profiles `T1546.004` — FIM sur `.bashrc`, `.profile`, `.bash_profile`
- [ ] **C7** — Git hooks `T1059` — scanner `.git/hooks/` dans les repos connus

---

## SECTION D — sentinel-platform (Windows) : règles LOLBin

> fichier : `rust/sentinel-core/src/rules/lolbin.rs`

- [x] **SENT-1001** `T1059.001` — PowerShell avec `-EncodedCommand` ou `-Enc`
- [x] **SENT-1002** `T1059.001` — PowerShell + `Invoke-WebRequest` / `Net.WebClient` / `wget`
- [x] **SENT-1003** `T1140` — `certutil.exe` avec `-decode` ou `-urlcache`
- [x] **SENT-1004** `T1218.005` — `mshta.exe` avec URL `http://` dans cmdline
- [x] **SENT-1005** `T1218.010` — `regsvr32.exe` + `scrobj.dll` ou URL distante
- [x] **SENT-1006** `T1218.011` — `rundll32.exe` avec URL dans cmdline
- [x] **SENT-1007** `T1197` — `bitsadmin.exe` + `/transfer`
- [x] **SENT-1008** `T1047` — `wmiprvse.exe` spawning `cmd.exe` / `powershell.exe`
- [x] **SENT-1009** `T1204.002` — Word/Excel/PowerPoint spawning shell
- [x] **SENT-1010** `T1053.005` — `schtasks.exe /create /s \\` (remote scheduled task)
- [x] **SENT-1011** `T1021.002` — accès `\\ADMIN$` ou `\\IPC$` + création service
- [x] **SENT-1012** `T1490` — `vssadmin delete shadows` ou `wmic shadowcopy delete`
- [x] **SENT-1013** `T1047` — `wmic.exe process call create` + binaire shell
- [x] **SENT-1014** `T1218.004` — `installutil.exe` depuis chemin non-système
- [x] **SENT-1015** `T1059` — `svchost.exe` / `spoolsv.exe` spawning `cmd.exe`

---

## SECTION E — Credential Theft Detection `TA0006`

> fichier : `rust/sentinel-platform/src/windows/cred_guard.rs`

- [~] **E1** — Scan de handle LSASS `T1003.001`
  - Stub — implémentation complète requiert NtQuerySystemInformation + SE_DEBUG_PRIVILEGE (Phase 2)

- [x] **E2** — Détection par nom de process
  - `mimikatz.exe`, `procdump.exe`, `nanodump.exe` etc. dans la liste = CRITICAL
  - Cmdline contenant `sekurlsa`, `lsadump`, `dcsync` = CRITICAL

- [x] **E3** — SAM dump `T1003.002`
  - `reg.exe save HKLM\SAM` dans cmdline = HIGH

- [~] **E4** — Browser credential access `T1555.003`
  - Stub — nécessite ETW / minifilter driver

- [x] **E5** — Ransomware pre-encryption signals `T1490`
  - `vssadmin.exe delete shadows /all` = CRITICAL
  - `bcdedit.exe /set {default} recoveryenabled No` = CRITICAL
  - `wbadmin.exe DELETE SYSTEMSTATEBACKUP` = CRITICAL

- [x] **E6** — AMSI bypass detection `T1562.001`
  - FFI vers `GetModuleHandleA` / `GetProcAddress` + compare 7 premiers bytes de `AmsiScanBuffer`

---

## SECTION F — File Integrity Monitoring (FIM)

> module : `rust/sentinel-platform/src/fim.rs`

- [x] **F1** — Struct `FimBaseline { entries: HashMap<PathBuf, [u8;32]> }`
- [x] **F2** — fn `build_baseline(paths: &[PathBuf]) -> FimBaseline` (SHA-256 au démarrage)
- [x] **F3** — fn `check_baseline(baseline, watch_paths) -> Vec<FimAlert>` (Modified/Deleted/Created)
- [x] **F4** — Chemins critiques Windows (lsass.exe, ntdll.dll, winlogon.exe, hosts, sethc.exe, utilman.exe)
- [x] **F5** — Chemins critiques Linux (/etc/passwd, /etc/shadow, /etc/sudoers, sshd_config, su, sudo)
- [x] **FimMonitor** — struct publique avec `init_baseline()`, `check()`, `rebuild_baseline()`

---

## SECTION G — Scoring process amélioré

> fichiers : `rust/sentinel-tui/src/app.rs` + `sentinel-desktop/src-tauri/src/lib.rs`

- [x] **G1** — Exe dans `%TEMP%` ou `%APPDATA%\Local\Temp` → +5 pts (`T1036.005`)
- [x] **G2** — Nom de process système depuis chemin non-système → +8 pts (`T1036.005`)
- [x] **G3** — Chemin hors `C:\Windows\` et `C:\Program Files\` → +3 pts (`T1553.002`)
- [x] **G4** — Nom de fichier avec entropie élevée (ratio voyelles < 10%) → +2 pts
- [x] **G5** — Parent = browser ou Office → +3 pts (`T1566.001`)
- [x] **G6** — Exécutable depuis partage réseau (`\\`) → +4 pts (`T1021.002`)
- [x] **G7** — `score_process()` retourne `ProcessScore { total, factors: Vec<ScoreFactor> }`

---

## SECTION H — UI : onglet Alerts

> fichiers : `sentinel-desktop/src/pages/Alerts.tsx` + mises à jour connexes

- [x] **H1** — Types `Alert`, `ScoreFactor`, `Severity` dans `src/lib/types.ts`
- [x] **H2** — Commande Tauri `get_alerts()` dans `src-tauri/src/lib.rs`
- [x] **H3** — Page `Alerts.tsx` : liste des alertes avec badge ATT&CK, sévérité colorée, timestamp
- [x] **H4** — `Alerts` dans la sidebar (icône `ShieldAlert`)
- [x] **H5** — Badge rouge sur l'icône sidebar si alertes CRITICAL non lues (polling 30s)
- [x] **H6** — ScoreFactor dans la page Processes (expand inline avec +pts, nom, ATT&CK ID)

---

## Ordre d'exécution recommandé

```
A1 → A2 → A3   ✅
     ↓
B1 → B2 → B3   ✅ (B3 stub)
     ↓
D (LOLBin rules) ✅
     ↓
E1 → E2 → E5   ✅ (E1, E4 stubs)
     ↓
F1 → F4         ✅
     ↓
G               ✅
     ↓
H               ✅
     ↓
B4–B9, C, F5   → Phase 1 suite (C Linux pending)
```

---

## Crates touchées

| Crate | Sections | Statut |
|-------|----------|--------|
| `sentinel-core` | A1, A2, A3 | ✅ |
| `sentinel-platform` | B1–B9, E1–E6, F1–F5 | ✅ (stubs: B3, E1, E4) |
| `sentinel-tui` | G | ✅ |
| `sentinel-desktop` (Tauri) | G, H | ✅ |
| `sentinel-platform` Linux | C1–C7 | ⏳ pending |
