# ARQENOR OSS — Audit de sécurité

- **Cible** : `arqenor/` (OSS, Apache 2.0) — moteur EDR Rust + orchestrateur Go
- **Branche** : `dev` (HEAD `9fd6e11`)
- **Date** : 2026-04-27
- **Périmètre** : Phases 1 à 5 du plan d'audit — cartographie, surface réseau, kernel/OS, pipeline détection, supply-chain, features-vs-réalité, configuration. Audit *boîte blanche*, lecture seule, pas d'exécution dynamique. Les sévérités sont indicatives (CVSS 3.1 abrégé) et supposent un déploiement réseau hostile.
- **Hors périmètre** : repo `arqenor-enterprise/` (privé), kernel driver (`arqenor-driver`, nightly + WDK), audit dynamique / fuzzing.

---

## Executive Summary

ARQENOR est un projet jeune mais structurellement sain : architecture en trois étages (CLI/TUI/REST → orchestrateur Go → analyseur Rust gRPC → collecteurs OS), workspace Rust + Go propre, `Cargo.lock`/`go.sum` commités, hooks `pre-push`, CI multi-jobs avec `rustsec/audit-check`, traits cross-OS (`arqenor-core`) implémentés par plateforme (`arqenor-platform`), pipeline de détection découplé du transport.

Cependant, la **posture de déploiement par défaut n'est pas production-ready**. Trois axes critiques :

1. **Surface réseau** : l'API REST de l'orchestrateur écoute sur `0.0.0.0:8080` (le défaut Go pour `:8080`) **alors que le `configs/arqenor.toml` indique `127.0.0.1:8080`** → le code ignore sa propre config. **Pas de TLS**, **pas de rate limiting**. Le gRPC localhost est correctement bind sur `127.0.0.1:50051`, mais lui aussi sans TLS ni authentification (acceptable IPC, dangereux dès qu'on le forwarde).
   > **Note importante** : l'absence d'authentification ([REST-AUTH], [GRPC-AUTH]) est **volontaire et déférée** à la couche SaaS Next.js qui n'a pas encore été développée. Tant que cette couche n'existe pas, la mitigation se fait par **bind strict `127.0.0.1`** + runbook de déploiement. Voir §7 Sprint 0.
2. **Robustesse moteur** : hashing SHA-256 fait via `std::fs::read()` — fichier entier en RAM — répandu dans **6 modules** (FIM, scanners FS Linux/macOS/Windows, NTDLL check, BYOVD, persistence avancée). Un fichier de 50 Go ⇒ OOM. Combiné à un `root_path` non canonicalisé côté gRPC, c'est un DoS *one-shot* via `ScanRequest`.
3. **Supply-chain** : `serde_yaml 0.9.34+deprecated` (RUSTSEC-2024-0320, unmaintained depuis mars 2024) est l'unique parser des règles SIGMA — point d'entrée privilégié pour tout attaquant qui contrôle `--sigma-dir`. `rustsec/audit-check` est `continue-on-error: true` ⇒ il signale sans bloquer.

À l'inverse, plusieurs choses sont **bien faites** : SQL paramétré côté Rust et Go, channels Tokio bornés (back-pressure), `unwrap()` quasi-absent du code de production, parsers IOC HTTPS-only (rustls-tls), correlation engine avec `flush_stale()` périodique, journal SQLite en mode WAL, NTDLL/AMSI tampering détectés, gracefully degraded eBPF (`SKIP_EBPF=1` + `loader_stub.rs`).

**Risque réputationnel "marketing-vs-réalité"** : très faible — le README et `CLAUDE.md` sont explicites sur les modules livrés vs en cours (eBPF wired depuis 2026-04-26, JA4 module-ready mais non câblé à un packet source, Isolation Forest pending). **Aucun cas de "OSS-washing" détecté.**

### Décompte global

| Sévérité | Nombre | IDs principaux |
|---|---|---|
| **Critical** | 3 | REST-AUTH *(deferred SaaS)*, REST-BIND, GRPC-AUTH *(deferred SaaS)* |
| **High** | 11 | GRPC-PATH, GRPC-STREAM, GRPC-METADATA, GRPC-RATE, REST-RATE, REST-SSE, IOC-SIZE, ETW-DEGRAD, FS-SYMLINK-WIN, FS-SYMLINK-LIN, PIPE-HASH-OOM |
| **Medium** | 16 | DEP-SERDE_YAML, SIGMA-REGEX, CORR-LEAK, CORR-INJECT, STORE-PERMS, MEMORY-PPL, IOC-CSV, IOC-FEED-TIMEOUT, GRPC-MAXSIZE, REST-LOGS, REST-CTX, ETW-PID-TOCTOU, EBPF-SILENT, EBPF-DROP, CI-AUDIT-SOFT, DEP-WINSYS-DUP |
| **Low / Info** | ~15 | divers (voir sections) |

---

## 1. Critical Findings (CVSS ≥ 7.0, exploitabilité directe)

### [REST-AUTH] API REST sans authentification — Critical (CVSS ~9.8) — **deferred / blocked-by: SaaS Next.js**

- **Composant** : `go/internal/api/routes/server.go:67-86`, `go/cmd/orchestrator/main.go`
- **Description** : Aucune des routes `v1/...` (`GET /alerts`, `POST /scans`, `GET /alerts/stream`, etc.) n'a de middleware d'authentification. Pas de Bearer token, pas d'API key, pas de mTLS, pas de session. Combiné à [REST-BIND] (bind sur `0.0.0.0`), l'orchestrateur expose ses RPC à toute machine sur le réseau.
- **Statut produit** : **L'authentification est intentionnellement reportée à la couche SaaS Next.js**, qui n'a pas encore été démarrée à la date de cet audit. Tant que ce panneau de contrôle n'existe pas, la mitigation est purement réseau (bind strict + runbook). Ne pas câbler de shared-secret intermédiaire qui serait jeté.
- **Impact (si exposé sans la couche SaaS)** :
  - Lecture exhaustive des alertes (intelligence sur la posture défensive).
  - `POST /scans` — déclenchement de scans réseau arbitraires (peut servir de point pivot pour scanner à partir de l'hôte EDR).
  - Connexions SSE permanentes (cf. [REST-SSE]) → DoS.
- **PoC** :
  ```bash
  curl http://target:8080/api/v1/alerts
  curl -X POST http://target:8080/api/v1/scans \
       -H 'Content-Type: application/json' \
       -d '{"cidr":"10.0.0.0/8","ports":[22,80,443,3389]}'
  ```
- **Mitigations en attendant la SaaS** :
  1. **[REST-BIND]** : forcer bind `127.0.0.1` (cf. ci-dessous).
  2. Runbook : *"ne pas exposer le port 8080 sur le réseau tant que la SaaS n'est pas en place"*.
  3. Si tests inter-hôtes nécessaires : tunnel SSH (`ssh -L 8080:127.0.0.1:8080`), pas d'exposition directe.
- **Fix final (au moment de la SaaS)** : OIDC / clé API émise par le control plane SaaS + mTLS si déploiement multi-host. Le moteur OSS valide juste la signature/présentation du token.

### [REST-BIND] L'orchestrateur ignore la config et bind sur `0.0.0.0:8080` — Critical (CVSS ~9.0)

- **Composant** : `go/cmd/orchestrator/main.go:82`
- **Description** :
  ```go
  ln, err := net.Listen("tcp", ":8080")
  ```
  Cette adresse est **hardcodée**. `configs/arqenor.toml:10` contient pourtant `listen_addr = "127.0.0.1:8080"` — la valeur par défaut intention de l'auteur. L'orchestrateur n'utilise jamais la valeur du fichier de config pour l'adresse de bind. En Go, `:8080` ⇒ `0.0.0.0:8080` (toutes interfaces).
- **Impact** : exposition sur tout réseau accessible (LAN d'entreprise, container avec port forwarding, cloud sans security group).
- **Fix** : charger `api.listen_addr` depuis le fichier de config (`config` crate côté Rust ou équivalent Go), avec fallback explicite `127.0.0.1:8080` documenté. Loguer l'adresse résolue au démarrage.

### [GRPC-AUTH] Service gRPC sans authentification ni TLS — Critical (CVSS ~9.1, contextuel) — **deferred / blocked-by: SaaS Next.js**

- **Composant** : `rust/arqenor-grpc/src/main.rs:31-41`, `go/internal/grpc/client.go` (côté client : `grpc.WithTransportCredentials(insecure.NewCredentials())`)
- **Description** :
  ```rust
  let addr = "127.0.0.1:50051".parse()?;
  tonic::transport::Server::builder()
      .add_service(host::host_analyzer_server::HostAnalyzerServer::new(host_svc))
      .serve(addr)
      .await?;
  ```
  Bind localhost (✓), mais aucun `tls_config`, aucun `Interceptor` d'authentification. Tout client localhost peut appeler `GetProcessSnapshot`, `WatchProcesses`, `WatchAlerts`, `ScanFilesystem`.
- **Statut produit** : même cause que [REST-AUTH] — l'auth gRPC sera adossée à la couche SaaS Next.js (token transmis du SaaS vers l'orchestrateur Go, qui le revalide vers le moteur Rust ; ou mTLS interne avec PKI émise par le control plane). Pas d'auth shared-secret intermédiaire à câbler maintenant — elle serait jetée au moment du SaaS.
- **Impact (en attendant)** : un programme non-privilégié sur la même machine peut *récupérer la liste de tous les processus avec cmdlines*, *écouter les détections en temps réel pour s'évader*, ou *piloter un scan FS arbitraire*. Risque accru si le canal est forwardé (SSH tunnel, sidecar K8s).
- **Mitigations en attendant la SaaS** :
  1. Bind localhost strict (déjà fait : `127.0.0.1:50051`).
  2. **Ne pas exposer le port 50051** dans Docker / K8s (`expose:`, `hostNetwork: true` interdits).
  3. Sur poste développeur multi-utilisateur Linux, considérer un Unix Domain Socket en `0700` pour le canal gRPC (refactor à prévoir si pertinent).
- **Fix final (au moment de la SaaS)** : mTLS interne (PKI émise par le control plane SaaS) + interceptor Tonic qui valide le SPIFFE-like ID du client.

---

## 2. High Findings

### [GRPC-PATH] `ScanRequest.root_path` non canonicalisé — High (CVSS ~7.5)

- **Composant** : `rust/arqenor-grpc/src/server/host_analyzer.rs` (handler `ScanFilesystem`), `rust/arqenor-platform/src/{linux,windows}/fs_scanner.rs`
- **Description** : `root_path` de la `ScanRequest` est converti directement en `PathBuf` puis passé à `WalkDir::new(root).follow_links(false)`. `follow_links(false)` empêche les symlinks au sein de la traversée, mais **n'empêche pas le `root_path` lui-même d'être un symlink** ni un chemin avec `..`. Aucune `canonicalize()` ni allowlist.
- **Impact** : tout client gRPC peut faire scanner et hasher `/etc`, `C:\Windows\System32\config`, `/proc/$pid/environ`, etc. Combiné à [GRPC-AUTH], n'importe quel programme local lit ainsi des hashes de fichiers privilégiés via gRPC. Combiné à [PIPE-HASH-OOM] : DoS one-shot avec `root_path = /` ou `C:\`.
- **Fix** : `let root = std::fs::canonicalize(root_path)?;` puis vérifier qu'il *commence par* l'un des préfixes de `[scan].fs_roots` (déjà présent dans `arqenor.toml`). Côté proto, ajouter `string root_path` doc claire.

### [GRPC-STREAM] Streams `Watch*` sans timeout / keepalive — High (CVSS ~7.2)

- **Composant** : handlers `WatchProcesses` / `WatchFilesystem` / `WatchAlerts`
- **Description** : les RPC streamés ouvrent un `mpsc::channel(256)` par client et restent vivants tant que le client ne déconnecte pas. Aucun `Server::keepalive_*`, aucun `max_connection_age`, aucun max d'abonnés.
- **Impact** : un attaquant ouvre N streams puis met sa fenêtre TCP à zéro → `256 × N` events bufferisés serveur-side. À 1 000 streams, ~250 K events en RAM (plusieurs GB selon la charge).
- **Fix** :
  ```rust
  Server::builder()
      .http2_keepalive_interval(Some(Duration::from_secs(30)))
      .http2_keepalive_timeout(Some(Duration::from_secs(10)))
      .max_connection_age(Some(Duration::from_secs(3600)))
  ```
  Plus une borne globale via `Arc<Semaphore>` injecté dans l'interceptor.

### [GRPC-METADATA] Metadata `Alert` non sanitisée propagée bout-en-bout — High (CVSS ~7.8)

- **Composant** : `proto/common.proto` (`map<string, string> metadata`), pipeline → gRPC → orchestrateur Go → SSE clients
- **Description** : La `metadata` d'une `Alert` est remplie depuis (1) cmdlines et chemins capturés OS-side, (2) tags issus des feeds IOC abuse.ch (CSV mal parsé : `splitn(',')` sans gestion des quotes / newlines, cf. [IOC-CSV]). Aucun *sanitize* avant export gRPC ; côté Go, broadcast tel-quel via SSE en JSON.
- **Impact** :
  - **Log injection** : un cmdline contenant `\n[ALERT]\nSEVERITY=critical` peut écrire des fausses lignes dans un sink de logs non-structuré.
  - **XSS** dans une UI tierce qui parserait naïvement le JSON SSE.
  - **Empoisonnement** via feed IOC (un upstream `abuse.ch` compromis ou MITM peut injecter du contenu arbitraire dans `tags` → propagation jusque dans la dernière alerte).
- **Fix** : valider clés metadata (`[A-Za-z0-9_]+`), valeurs (rejet de `\n`, `\r`, control chars `< 0x20`). Faire passer toutes les valeurs « cmdline » par une couche de redaction explicite avant insertion.

### [GRPC-RATE] Aucun rate-limit ni quota par client gRPC — High (CVSS ~7.1)

- **Composant** : `rust/arqenor-grpc/src/main.rs`
- **Description** : aucune limitation de concurrence — un client peut lancer 10 000 `ScanFilesystem` simultanés sur `/`. Le service n'a pas de Tower `RateLimitLayer` ni de `ConcurrencyLimitLayer`.
- **Fix** : `tower::ServiceBuilder::new().rate_limit(100, Duration::from_secs(1)).concurrency_limit(64).service(svc)`.

### [REST-RATE] Aucun rate-limit côté Gin — High (CVSS ~7.3)

- **Composant** : `go/internal/api/routes/server.go`
- **Description** : aucun middleware (`tollbooth`, `golang.org/x/time/rate`, ou maison). Combiné à [REST-AUTH], un attaquant peut spammer `/api/v1/scans` ou les SSE.
- **Fix** : middleware `rate.NewLimiter(rate.Every(50*time.Millisecond), 20)` — par IP source, pas global.

### [REST-SSE] Diffusion SSE sans plafond de connexions — High (CVSS ~7.2)

- **Composant** : `AlertBroadcaster.Subscribe` (channel `make(chan store.Alert, 64)`), handler `handleStreamAlerts`
- **Description** : `Publish` fait `select { case ch <- a: default: /* drop */ }` (drop silencieux). Mais on peut ouvrir des dizaines de milliers de subscribers — chacun consomme un goroutine + 64 slots de channel + un socket TCP côté serveur.
- **Fix** : cap global `MaxSSEConnections` côté `AlertBroadcaster`, plus rejet HTTP 503 quand atteint. Idéalement, par-IP.

### [IOC-SIZE] Téléchargement de feed sans `Content-Length` ni borne — High (CVSS ~7.2)

- **Composant** : `rust/arqenor-core/src/ioc/feeds.rs` (`resp.text()` après `conditional_get`)
- **Description** : `resp.text().await?` charge la réponse entière en RAM. Un feed compromis ou un MITM côté CDN peut renvoyer 1 GB de pseudo-CSV → OOM.
- **Fix** : `let max = 256 * 1024 * 1024;` puis `let body = resp.bytes_stream().take(max)…`. Logguer un warning si tronqué.

### [ETW-DEGRAD] Dégradation silencieuse quand aucun provider ETW ne s'attache — High

- **Composant** : `rust/arqenor-platform/src/windows/etw_consumer.rs:369-386` (boucle sur `PROVIDERS`)
- **Description** : si `EnableTraceEx2` échoue pour *chacun* des providers (lancement non-élevé, manque `SeTcbPrivilege`/`SeSystemProfilePrivilege`), la session ETW continue avec **zéro provider attaché** et le code retourne `Ok(_)`. L'opérateur croit avoir la télémétrie, n'a rien.
- **Fix** : compter les succès, exiger ≥1 provider du groupe `Process` *et* ≥1 du groupe `File/Network`, sinon `bail!()` au démarrage avec un message explicite ("run as Administrator").

### [FS-SYMLINK-WIN] `ReadDirectoryChangesW` suit symlinks/junctions sans vérification — High

- **Composant** : `rust/arqenor-platform/src/windows/fs_scanner.rs` (CreateFileW avec `FILE_FLAG_BACKUP_SEMANTICS`)
- **Description** : `FILE_FLAG_BACKUP_SEMANTICS` ouvre la cible d'un reparse point. Si la racine surveillée contient un junction/symlink contrôlé par un utilisateur non privilégié, la session monitore la cible (ex : `C:\Windows\System32`). Variante locale d'attaque par symlink.
- **Fix** : valider chaque composant via `GetFileAttributesW` + rejeter `FILE_ATTRIBUTE_REPARSE_POINT`, ou utiliser `FILE_FLAG_OPEN_REPARSE_POINT` et bailler.

### [FS-SYMLINK-LIN] `inotify` sur racine vérifiable manquante — High

- **Composant** : `rust/arqenor-platform/src/linux/fs_scanner.rs` (ajout watch sans `S_ISDIR()`/`!S_ISLNK()`)
- **Description** : si `--watch /tmp/foo` et qu'un user crée `/tmp/foo` en symlink vers `/etc`, la session monitore `/etc`. Surface équivalente à [FS-SYMLINK-WIN].
- **Fix** : `lstat()` la racine et chacun de ses parents jusqu'au mount-point, refuser si reparse-point ou monde-writable inattendu.

### [PIPE-HASH-OOM] Hash SHA-256 via `fs::read()` — fichier entier en RAM — High (CVSS ~7.5)

- **Composant** : 6 occurrences confirmées :
  - `rust/arqenor-platform/src/fim.rs:20`
  - `rust/arqenor-platform/src/linux/fs_scanner.rs:78`
  - `rust/arqenor-platform/src/macos/fs_scanner.rs:70`
  - `rust/arqenor-platform/src/windows/fs_scanner.rs:157`
  - `rust/arqenor-platform/src/windows/byovd.rs:52`
  - `rust/arqenor-platform/src/windows/ntdll_check.rs:70` (lit `ntdll.dll`, taille bornée — OK ici) et `:141` (idem)
  - `rust/arqenor-platform/src/linux/persistence_advanced.rs:45` (`sha256_file`)
- **Description** : pattern systématique
  ```rust
  let bytes = std::fs::read(path)?;
  let hash = Sha256::digest(&bytes);
  ```
  Un fichier de 50 GB ⇒ allocation de 50 GB. En FIM/scan permanent, un attaquant pose simplement un fichier sparse 1 TB sur un chemin scanné (par défaut `C:\Users` !).
- **PoC** (Linux) : `fallocate -l 50G /home/user/Documents/big.bin` puis attendre le tour du scanner.
- **Fix** : streamer en blocs de 64-256 KB avec `Sha256::new(); loop { hasher.update(&buf[..n]); }`. Ajouter une borne dure `max_file_size` (existe dans `arqenor.toml` : 10 MB) **et l'appliquer aussi côté collector**, pas seulement à la décision d'envoi de hash.

---

## 3. Medium Findings

### [DEP-SERDE_YAML] `serde_yaml 0.9.34+deprecated` sur le chemin SIGMA — Medium

- **Composant** : `rust/arqenor-core/Cargo.toml:17`, utilisé dans `src/rules/sigma.rs:20,29,49,50,175`
- **Description** : `serde_yaml` est unmaintained depuis mars 2024 (RUSTSEC-2024-0320) — `cargo audit` doit déjà l'avoir signalé en CI mais [CI-AUDIT-SOFT] fait que ce n'est pas bloquant. C'est l'unique parser des règles SIGMA, donc le point d'entrée privilégié pour tout attaquant qui contrôle `--sigma-dir`.
- **Fix** : migrer vers `serde_yml` (fork actif, drop-in) ou `yaml-rust2`. Combiner avec [SIGMA-LIMIT] (limite en taille / nombre).

### [SIGMA-REGEX] Backtracking catastrophique dans les conditions SIGMA — Medium

- **Composant** : `rust/arqenor-core/src/rules/sigma.rs:289-291` — `regex::Regex::new(pattern)` puis `is_match`
- **Description** : un attaquant capable de poser une règle SIGMA ou un événement piégé (cmdline contenant `aaaaa…X`) peut bloquer la pipeline avec un pattern `(a+)+` (ReDoS).
- **Fix** : la crate `regex` *n'est pas* affectée par le backtracking exponentiel (NFA bornée), mais elle peut avoir une complexité quadratique via `is_match` sur de très longs inputs. Borner la longueur de l'input matché à un seuil raisonnable (ex : 64 KB). Loguer la règle qui dépasse.

### [SIGMA-LIMIT] Pas de borne sur le nombre/taille des règles chargées — Low/Med

- **Composant** : `rust/arqenor-core/src/rules/sigma.rs:201-232`
- **Description** : `load_sigma_rules_from_dir` lit toutes les `*.yml` du répertoire. Si un attaquant peut poser des fichiers, il peut OOM le démarrage.
- **Fix** : `max 5 000` règles, `max 1 MB` par fichier, refuser symlinks (cf. [SIGMA-SYMLINK]).

### [CORR-LEAK] `flush_stale` doit être appelé — risque d'OOM si oublié — Medium

- **Composant** : `rust/arqenor-core/src/correlation.rs:17-18,284-332`
- **Description** : `active` HashMap croît avec chaque PID inconnu. La pipeline appelle bien `flush_stale()` toutes les ~60 s, mais le contrat n'est pas explicite — un futur consommateur de `CorrelationEngine` (le bridge eBPF, par ex.) peut l'oublier.
- **Fix** : doc-comment explicite + `debug_assert!(self.active.len() < 100_000)`. Idéalement, flush automatique géré par l'engine via un `Interval` interne.

### [CORR-INJECT] Caractères de contrôle dans `Alert.metadata` — Medium

- **Composant** : `rust/arqenor-core/src/pipeline.rs:452-462` (insertion de cmdline/user dans metadata)
- **Description** : pas de filtre pour `\n`, `\r`, `\0`. Selon le sink (logs structurés JSON → OK ; logs ligne plat → log injection).
- **Fix** : helper `sanitize_meta_value` au point d'insertion.

### [STORE-PERMS] DB SQLite créée avec `0o755` — Medium (Linux multi-user)

- **Composant** : `go/cmd/orchestrator/main.go:40` (`os.MkdirAll(filepath.Dir(dbPath), 0o755)`)
- **Description** : sur Linux multi-user, n'importe qui sur la machine peut lire `data/arqenor.db` (alertes, IOC, hashes de malware détectés). Sur Windows/macOS poste unique, impact moindre.
- **Fix** : `0o700` pour le répertoire, `0o600` pour les fichiers DB. Vérifier post-création et corriger si besoin (cas où le répertoire existait déjà).

### [MEMORY-PPL] `OpenProcess(PROCESS_VM_READ)` sur PPL → erreur, pas de fallback — Medium

- **Composant** : `rust/arqenor-platform/src/windows/memory_scan.rs:71-78`
- **Description** : LSASS, MsMpEng, etc. sont protégés PPL. `OpenProcess` retourne `ERROR_ACCESS_DENIED` → la fonction retourne `Err` → on n'a aucune télémétrie sur les processus les plus attaqués.
- **Fix** : essayer d'abord `PROCESS_VM_READ`, *fallback* sur `PROCESS_QUERY_INFORMATION` seul (énumération de modules par Toolhelp), retourner un `MemoryScanResult` partiel avec un flag `vm_read_denied`.

### [IOC-CSV] Parser CSV maison `splitn(',')` — Medium

- **Composant** : `rust/arqenor-core/src/ioc/feeds.rs:136-162` (MalwareBazaar, URLhaus, Feodo)
- **Description** : ne gère ni les quotes échappées ni les newlines dans les cellules. Un feed compromis peut empoisonner les IOC ou injecter dans `tags` (cf. [GRPC-METADATA]).
- **Fix** : `csv::ReaderBuilder::new().flexible(true).from_reader(...)`.

### [IOC-FEED-TIMEOUT] Refresh feed sans timeout global, peut bloquer le `RwLock<IocDb>` — Medium

- **Composant** : `rust/arqenor-grpc/src/server/host_analyzer.rs` (spawn loop) + `feeds.rs::refresh_all_feeds`
- **Description** : si abuse.ch est slow-loris-ed (MITM), `refresh_all_feeds` peut tenir le write-lock plusieurs minutes → toutes les détections IOC bloquées.
- **Fix** : `tokio::time::timeout(Duration::from_secs(120), …)` autour du fetch + lock acquis le plus tard possible (parser hors lock, swap dans le lock).

### [GRPC-MAXSIZE] `ScanRequest.max_size_bytes = 0` non interprété comme "non borné" en sécurité — Medium

- **Composant** : `rust/arqenor-grpc/src/server/host_analyzer.rs` (handler `ScanFilesystem`)
- **Description** : valeur 0 ou `u64::MAX` → la branche `size > max` n'éclaircit jamais → tous les fichiers hashés (combiné à [PIPE-HASH-OOM]).
- **Fix** : refuser `max_size_bytes == 0` ou le mapper à un défaut serveur (`configs/arqenor.toml` → `scan.max_file_size`).

### [REST-LOGS] Cmdlines / paths logués en `Info` — Medium (fuite)

- **Composant** : `go/internal/api/routes/server.go` (Gin Logger), nombreux `tracing::info!` côté collectors
- **Description** : si les logs sont forwardés à ELK/CloudWatch/Splunk sans redaction, les cmdlines (qui peuvent contenir des secrets : `--password=...`, tokens dans une URL) y atterrissent. À mettre dans le runbook de déploiement.
- **Fix** : helper `redact_cmdline()` qui masque les arguments suivants `--password`, `--token`, `Authorization`, `?token=...` avant log.

### [REST-CTX] `handleStartScan` lance une goroutine sans `context.WithTimeout` — Medium

- **Composant** : `go/internal/api/routes/server.go` (handler `handleStartScan`)
- **Description** : `go func() { s.scanner.ScanCIDR(ctx_background, ...) }()` — aucun deadline. Si le serveur Rust est down, la goroutine fuit jusqu'à reset TCP (souvent 7 j sur Linux).
- **Fix** : `ctx, cancel := context.WithTimeout(ctx, 10*time.Minute); defer cancel()` puis passer `ctx` à `ScanCIDR`.

### [ETW-PID-TOCTOU] Réutilisation de PID entre `NtQuerySystemInformation` et `sysinfo` — Medium

- **Composant** : `rust/arqenor-platform/src/windows/cred_guard.rs:312-327`
- **Description** : entre la snapshot de handles et le lookup `sys.process(pid)`, le PID peut être réutilisé → fausse alerte ou pire, *contrefaçon de PID* attaquée.
- **Fix** : capturer l'image path et le start time *au moment de l'énumération* dans `HandleEntry`, comparer ensuite.

### [EBPF-SILENT] Démarrage avec 0 probes attachées retourne `Ok` — Medium

- **Composant** : `arqenor-ebpf/src/loader.rs:145-260` (`EbpfAgent::start`)
- **Description** : chaque probe failed est logguée en `warn!`, mais si toutes échouent (kernel < 5.8 sans `CAP_SYS_ADMIN`, BTF absent), `attached_probes == 0` et la fonction retourne `Ok((Self, rx))`. L'opérateur a un `EbpfAgent` qui ne livre rien.
- **Fix** : `if attached == 0 { return Err(EbpfLoadError::NoProbesAttached); }`.

### [EBPF-DROP] Compteur de drops du ring buffer manquant — Medium

- **Composant** : `loader.rs:270-282` (`try_send_event` → `mpsc::TrySendError::Full` → `tracing::warn!`)
- **Description** : pas de compteur cumulé. Sous charge, on perd silencieusement un volume inconnu d'events.
- **Fix** : `static DROPPED: AtomicU64 = AtomicU64::new(0)` + métrique exportée toutes les 60 s ; alerte synthétique dès N drops/min.

### [DEP-WINSYS-DUP] Trois versions de `windows-sys` dans `Cargo.lock` — Medium

- **Composant** : `Cargo.lock` (présence simultanée de `windows-sys 0.52`, `0.60.2`, `0.61.2` à côté de `windows 0.62.2`)
- **Description** : provient de `sysinfo`, `clap`, `anstyle-wincon` qui n'ont pas été remontés. Pas de vuln directe, mais cible mouvante (et binaire plus gros).
- **Fix** : forcer `[workspace.dependencies.windows-sys] version = "0.62"` ou bumper `sysinfo`/`clap` en attendant.

### [CI-AUDIT-SOFT] `rustsec/audit-check` non bloquant — Medium

- **Composant** : `.github/workflows/ci.yml`
- **Description** : `continue-on-error: true` ⇒ une vuln critique nouvellement publiée sur une dépendance n'empêche pas le merge.
- **Fix** : faire passer à bloquant après cleanup de `serde_yaml` ([DEP-SERDE_YAML]). Brancher en parallèle `cargo deny check advisories bans licenses sources`.

---

## 4. Low / Informational

- **[UNSAFE-PARSE-NOTIFY]** `windows/fs_scanner.rs:40-82` (`parse_notify_buf`) : la borne `name_end > bytes` couvre le cas normal, mais `name_start + fname_bytes as usize` peut overflow si `fname_bytes == u32::MAX`. Trust kernel = OK pratique, mais defensive `saturating_add` recommandé. Sévérité **Low**.
- **[UNSAFE-TDH]** `windows/etw_tdh.rs:35-106` : pointeurs internes au buffer alloué localement ⇒ correct, mais doc-comment SAFETY à compléter pour les futurs mainteneurs. **Info**.
- **[AMSI-PROLOGUE]** `windows/cred_guard.rs:630-700` : pattern matching sur 7 octets — fragile face à un Windows futur ou un bypass par `jmp` au-delà de 7 octets. Multi-pattern + checksum de section recommandé. **Low**.
- **[LINUX-PROC-TOCTOU]** `linux/process_monitor.rs:145-205` : entre `refresh_processes` et lookup, un PID court-vie disparaît → `ProcessInfo` stub. Pas un risque sécurité, perte de visibilité. **Low**.
- **[MACOS-ESF-PARK]** `macos/esf_monitor.rs:221-250` : `thread::park_timeout(5s)` dans la boucle de drainage — ressources ne se libèrent pas immédiatement à shutdown. **Low**.
- **[STORE-IOC-CLEAR]** `ioc.db` non chiffré — feed source URLs et tags lisibles depuis le filesystem. **Low** (typique des EDR).
- **[REST-CIDR]** `POST /scans` accepte `0.0.0.0/0` — pas un risque sécurité direct (l'API est interne) mais en cas d'exposition cf. [REST-AUTH], permet de scanner Internet depuis l'hôte. **Low**.
- **[FEAT-JA4-DEAD]** `tls_fingerprint.rs` : code complet et testé mais pas appelé dans le pipeline (CLAUDE.md le dit). Risque : code mort qui rote. **Info**.
- **[FEAT-SIGMA-EMBED]** README L.64 « 3000+ SIGMA community rules » mais aucune n'est embarquée — l'utilisateur doit `--sigma-dir`. À reformuler en « *supports* 3000+ SIGMA rules ». **Info / réputationnel**.
- **[CI-PIN-SHA]** Actions GitHub utilisées par tag (`@v6`, `@stable`) au lieu de SHA. Tagjacking théorique. **Low**.
- **[GO-VULNCHECK]** Pas de `govulncheck` dans la CI Go. **Low**.
- **[NOTICE-MIN]** Le `NOTICE` ne liste pas les attributions de dépendances Apache 2.0 — bonne pratique non bloquante. **Info**.

---

## 5. Features Gap (advertised vs shipped)

| Feature annoncée (README / CLAUDE.md) | Status | Note |
|---|---|---|
| YARA in-memory scanning (`yara-x` 1.15) | ✅ Shipped (feature gate `yara`) | 9 familles de règles embarquées via `include_str!` |
| ETW 10 providers | ✅ Shipped | `windows/etw_consumer.rs` |
| eBPF 5 probes (B7) | ✅ Shipped 2026-04-26 | `arqenor-ebpf/src/loader.rs` ; bridge vers `DetectionPipeline` reste à brancher (déjà documenté) |
| LSASS handle scan | ✅ Shipped | `windows/cred_guard.rs` |
| DLL sideloading | ✅ Shipped | `windows/memory_scan.rs` |
| EndpointSecurity macOS | ✅ Shipped | `macos/esf_monitor.rs` |
| LOLBin rules (32) | ✅ Shipped | `core/rules/lolbin.rs` |
| MITRE ATT&CK mapping (~140 techniques) | ✅ Shipped | IDs présents dans rules |
| **JA4 TLS fingerprinting** | 🟡 Module-ready, **non câblé** | `tls_fingerprint.rs` testé en isolation ; pas de packet source. README *et* CLAUDE.md le disent. |
| **Behavioral ML / Isolation Forest** | 🟠 **Pending** (Phase 4 F2) | Non livré, documenté tel-quel. |
| **DGA detection** | ✅ Shipped (heuristique entropie) | `core/rules/network.rs::check_dga_score` |
| **Network scanner Rust-side** | 🟡 Proto défini, pas d'implémentation Rust | `proto/network_scanner.proto` orphelin côté Rust ; le poll Go n'a personne au bout. |
| **3 000+ SIGMA rules** | ⚠️ *Supportées* mais pas *fournies* | Voir [FEAT-SIGMA-EMBED] |

**Verdict réputationnel** : pas de "OSS-washing". Les modules en cours sont marqués comme tels. Deux clarifications à faire dans le README (JA4 + SIGMA pré-embarquées).

---

## 6. Dependency Risk Matrix

| Dépendance | Version | Critique | Statut | Action |
|---|---|---|---|---|
| **serde_yaml** | 0.9.34+deprecated | OUI (parser SIGMA) | RUSTSEC-2024-0320, unmaintained | **Migrer (`serde_yml` ou `yaml-rust2`)** |
| windows-sys (×3) | 0.52 / 0.60.2 / 0.61.2 | OUI (FFI Win32) | Friction supply-chain | Consolider à 0.62 |
| tonic | 0.14.5 | OUI | Stable | Surveiller |
| prost | 0.14 | OUI | Stable | OK |
| reqwest | 0.12.28 (rustls-tls) | OUI (feeds) | Stable | OK |
| yara-x | 1.15.0 | OUI | Stable | OK |
| libbpf-rs / libbpf-cargo | 0.24.x | OUI | Pinné cohérent | OK |
| rusqlite | 0.39 (bundled) | Moyen | OK | OK |
| chrono / time | 0.4 / >= 0.3.35 | Moyen | OK | OK |
| goblin | non utilisé | — | Pas de PE parsing externe à ce jour | À surveiller si introduit |
| Go: gin | 1.12.0 | OUI (front HTTP) | OK | Surveiller |
| Go: modernc.org/sqlite | 1.48.2 | Moyen | OK | OK |
| Go: quic-go | 0.59.0 | Moyen (transitive) | À vérifier `govulncheck` | [GO-VULNCHECK] |

---

## 7. Hardening Recommendations (ordre de priorité)

### Sprint 0 — runbook immédiat (avant que la SaaS Next.js soit prête)

L'auth ([REST-AUTH], [GRPC-AUTH]) est gated par la couche SaaS Next.js qui n'existe pas encore. En attendant, la posture reste tenable **uniquement si** :

- **[REST-BIND] corrigé** (Sprint 1 #1 ci-dessous) → le port 8080 ne sort pas de la machine.
- gRPC localhost reste sur `127.0.0.1:50051` (déjà fait).
- Aucun `docker run -p 8080:8080`, aucun K8s `Service` exposé, aucun `--bind` flag custom.
- Le `README.md` / `docs/deployment.md` doit dire explicitement : *"This OSS engine is not yet hardened for direct network exposure. Wait for the SaaS control plane, or front it with your own authenticated reverse proxy (Caddy, nginx + OAuth2-Proxy) on the same host."*

### Sprint 1 — bloquants production OSS (1-2 semaines, débloquables sans la SaaS)

1. **[REST-BIND]** : charger `[api].listen_addr` depuis `arqenor.toml` (Go lit déjà la config, il suffit de plumber le champ jusqu'au `net.Listen`). Fallback `127.0.0.1:8080`. C'est le *seul* fix d'exposition tant que la SaaS n'est pas là.
2. **[PIPE-HASH-OOM]** : refactor unique `fn sha256_stream(path) -> Result<[u8;32]>` dans `arqenor-core` ou `arqenor-platform`, remplacer les 6 sites. Plus borne `max_file_size` *appliquée* avant ouverture.
3. **[GRPC-PATH] + [GRPC-MAXSIZE]** : canonicalize + allowlist via `[scan].fs_roots` ; rejeter `max_size_bytes ∈ {0, > config_max}`.
4. **[DEP-SERDE_YAML]** : migrer vers `serde_yml`, puis activer `audit-check` bloquant ([CI-AUDIT-SOFT]).
5. **[REST-AUTH] + [GRPC-AUTH]** : *deferred — voir Sprint SaaS ci-dessous*.

### Sprint SaaS — au moment où Next.js démarre

- **[REST-AUTH]** : middleware Gin qui valide le JWT/OIDC émis par le control plane SaaS (audience = `arqenor-orchestrator`). JWKS rotaté.
- **[GRPC-AUTH]** : mTLS interne entre orchestrateur Go et moteur Rust, avec PKI bootstrappée par le SaaS au premier appairage.
- À ce moment-là seulement, on peut envisager d'ouvrir le port 8080 derrière un reverse-proxy.

### Sprint 2 — durcissement (2-4 semaines)

6. **[GRPC-RATE] + [REST-RATE] + [REST-SSE] + [GRPC-STREAM]** : Tower `RateLimitLayer` + `ConcurrencyLimitLayer` côté Rust ; `rate.NewLimiter` per-IP côté Go ; cap SSE.
7. **[ETW-DEGRAD] + [EBPF-SILENT]** : assertion "≥ 1 probe attachée" au démarrage, `bail!` explicite.
8. **[FS-SYMLINK-WIN] + [FS-SYMLINK-LIN]** : helper `validate_watch_root(path) -> Result<()>` partagé OS-cross.
9. **[GRPC-METADATA] + [CORR-INJECT] + [IOC-CSV]** : sanitization unique au point d'insertion `Alert.metadata`. Crate `csv` pour les feeds.

### Sprint 3 — opérabilité (4-8 semaines)

10. **[STORE-PERMS]** : `0o700`/`0o600` Linux/macOS, ACL Windows.
11. **[IOC-FEED-TIMEOUT] + [IOC-SIZE]** : timeout global, streaming bytes max, swap-after-parse.
12. **[EBPF-DROP]** : metric counter exposé en gRPC + alerte synthétique.
13. **[CI-AUDIT-SOFT] + [GO-VULNCHECK] + [CI-PIN-SHA]** : audit bloquant, `govulncheck`, SHA-pin actions, `cargo deny`.
14. **[FEAT-JA4-DEAD]** : soit câbler à pcap (Phase 3), soit isoler derrière `#[cfg(feature = "ja4_experimental")]` pour éviter le code mort en release.
15. **[REST-LOGS]** : redact helper systématique sur cmdlines / URLs avant tout `info!`.

---

## Annexe A — Bonnes pratiques observées (à conserver)

- SQL exclusivement paramétré (Rust `rusqlite::params!`, Go `?` placeholders).
- Channels Tokio bornés (`mpsc::channel(N)`) → back-pressure naturelle.
- `unwrap()` / `expect()` quasi absents en code de prod (le seul "scary" constaté en `connections.rs:418` est en fait dans un `#[cfg(test)]`).
- `panic!()` explicite : 2 occurrences, toutes deux dans des tests.
- `Cargo.lock` et `go.sum` commités.
- Hooks `pre-push` côté repo + workflow `enforce-main-policy` côté serveur.
- CI matrix Linux/Windows + path eBPF dégradable (`SKIP_EBPF=1` + `loader_stub.rs`).
- Mode WAL SQLite (concurrence + crash-safety).
- IOC feeds en HTTPS (rustls-tls), pas de `danger_accept_invalid_certs`.
- Correlation engine avec `flush_stale()` périodique, eBPF channels bornés.
- Architecture trait/impl OS-cross propre (`arqenor-core` agnostique, `arqenor-platform` cfg-gated).

## Annexe B — Méthodologie

- Audit boîte blanche, lecture seule, sans exécution dynamique.
- 5 sous-agents parallèles (gRPC/REST, kernel/OS, pipeline détection, supply-chain, marketing/config).
- Vérification *manuelle* des findings critiques contre la source avant publication. Un finding (`QUAL-01` du sub-agent supply-chain) a été reclassé `Info` car situé en `#[cfg(test)]`. Un autre (`UNSAFE-1` parse_notify_buf) a été reclassé `Low` après lecture du contexte (la borne est bien avant le déréférencement, contrairement à la première lecture de l'agent).
- Sévérités CVSS indicatives — vecteur exact à recalculer au moment du fix.

---

## 8. Remediation Status (2026-04-27)

A coordinated remediation pass was applied on 2026-04-27 by five parallel
domain agents (Go orchestrator, Rust gRPC, `arqenor-core`, `arqenor-platform`,
eBPF + CI). The status below reflects the OSS `dev` branch HEAD at that date.

### Resolved (29)

#### Critical (1)

| ID | Resolution |
|---|---|
| REST-BIND | `go/cmd/orchestrator/main.go` reads `cfg.Api.ListenAddr` from TOML (default `127.0.0.1:8080`); `:8080` no longer hardcoded. |

#### High (11)

| ID | Resolution |
|---|---|
| GRPC-PATH | `rust/arqenor-grpc/src/limits.rs::AllowedRoots` validates canonicalised `root_path` against `[scan].fs_roots`; rejects otherwise. |
| GRPC-STREAM | `rust/arqenor-grpc/src/main.rs`: `http2_keepalive_interval(30s)`, `http2_keepalive_timeout(10s)`, `max_connection_age(1h + 60s grace)`, unary `timeout(5min)`, `max_concurrent_streams(128)`. |
| GRPC-METADATA | All `metadata.value` and `message` fields routed through `arqenor_core::models::alert::sanitize_metadata_value` at the gRPC boundary (`core_alert_to_proto`) and at insertion sites (correlation, pipeline). |
| GRPC-RATE | Tower `ConcurrencyLimitLayer(64)` applied. (req/sec rate-limit not Tower 0.5 / Tonic 0.14 compatible — concurrency cap covers the same DoS vector.) |
| REST-RATE | `go/internal/api/middleware/ratelimit.go`: per-IP token-bucket via `golang.org/x/time/rate`, GC of inactive entries > 5 min, 429 + `Retry-After`. |
| REST-SSE | `AlertBroadcaster` cap configurable via `cfg.Api.MaxSSEConnections` (default 100), 503 when exceeded. |
| IOC-SIZE | `rust/arqenor-core/src/ioc/feeds.rs`: `MAX_FEED_SIZE = 256 MiB`, streaming `read_body_capped` with `Content-Length` belt + `take`. |
| ETW-DEGRAD | `rust/arqenor-platform/src/windows/etw_consumer.rs`: `ProviderGroup` (Process/File/Network/Security), bail if Process + (File or Network) absent, `error!` when `attached == 0`. |
| FS-SYMLINK-WIN | `rust/arqenor-platform/src/path_validate.rs::ensure_no_reparse` invoked before `CreateFileW` and at scan start. |
| FS-SYMLINK-LIN | Same `ensure_no_reparse_strict` invoked before `inotify::add`. |
| PIPE-HASH-OOM | New `rust/arqenor-platform/src/hash.rs` (streaming SHA-256, default 512 MiB cap), adopted across 9 sites (fim, byovd, cred_guard, fs_scanner Win/Lin/macOS, persistence_advanced, memory_scan, ntdll_check, persistence). |

#### Medium (16)

| ID | Resolution |
|---|---|
| DEP-SERDE_YAML | `serde_yaml = "0.9"` (RUSTSEC-2024-0320, deprecated) replaced by `serde_yml = "0.0.12"` in `arqenor-core`. |
| SIGMA-REGEX | Input bound `MAX_REGEX_INPUT = 64 KiB`, `RegexBuilder::size_limit(1MB)`, LRU cache for compiled regexes. |
| CORR-LEAK | `MAX_ACTIVE_INCIDENTS = 100_000` with auto-flush when reached, hardened doc-comment on `CorrelationEngine`. |
| CORR-INJECT | `sanitize_metadata_value` applied in `pipeline::emit_alert` and `correlation::ingest`. |
| STORE-PERMS | `data/` created `0o700`, DB file `chmod 0o600` post-creation (Linux/macOS — Windows respects ACLs). |
| MEMORY-PPL | Fallback to `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` when `VM_READ` denied; new public field `MemoryScanResult::vm_read_denied`. |
| IOC-CSV | Crate `csv` (`ReaderBuilder::flexible(true).comment(b'#')`) replaces handcrafted `splitn(',')`. |
| IOC-FEED-TIMEOUT | `tokio::time::timeout(120s)` global; fetch + parse outside the lock, atomic swap on `RwLock<IocDb>`. |
| GRPC-MAXSIZE | `resolve_max_size_bytes`: `0` → 10 GiB; `> 10 GiB` rejected. |
| REST-LOGS | `go/internal/util/redact.go` (`RedactCmdline`/`RedactURL`/`RedactHeader`) + custom Gin middleware replaces `gin.Logger()`. |
| REST-CTX | `handleStartScan` goroutine uses `context.WithTimeout(context.Background(), cfg.ScanTimeoutSeconds*time.Second)` (default 600s). |
| ETW-PID-TOCTOU | `ProcessIdentity { exe_path, creation_time }` captured at enumeration time, re-compared at lookup, skipped if PID recycled. |
| EBPF-SILENT | `EbpfAgent::start()` returns `Err(EbpfLoadError::NoProbesAttached)` when 0 probes attached. |
| EBPF-DROP | `pub static EBPF_DROPPED_EVENTS: AtomicU64` + 60s monitor task (warn > 0, error > 1000). |
| CI-AUDIT-SOFT | `continue-on-error: true` removed from `audit` job (now blocking); new `cargo-deny` and `govulncheck` (Go) jobs added. |
| DEP-WINSYS-DUP | `[workspace.dependencies.windows-sys] version = "0.61"` added at root `Cargo.toml`. **Partial consolidation** (3 → 2 versions; `ring`, `rustix 0.38`, `quinn-udp` still pin older upstream versions — documented inline). |

#### Low (1)

| ID | Resolution |
|---|---|
| UNSAFE-PARSE-NOTIFY | `windows/fs_scanner.rs::parse_notify_buf` now uses defensive `checked_add` on `name_start + fname_bytes` and `offset + next_entry`. |

### Deferred (2)

| ID | Reason |
|---|---|
| REST-AUTH | Gated by upcoming SaaS Next.js control plane. Mitigation: bind 127.0.0.1 + per-IP rate-limit + SSE cap. |
| GRPC-AUTH | Same as above. Mitigation: bind 127.0.0.1 + Tower concurrency cap. |

### Pending (Low / Info — to schedule)

| ID | Note |
|---|---|
| UNSAFE-TDH | Doc SAFETY comment to complete. |
| AMSI-PROLOGUE | Move to multi-pattern matching + section checksum. |
| LINUX-PROC-TOCTOU | Schedule once kernel-telemetry queue stabilises. |
| MACOS-ESF-PARK | Park-timeout in drain loop — to redesign for clean shutdown. |
| STORE-IOC-CLEAR | At-rest encryption, out of scope for early OSS. |
| REST-CIDR | Allow-list / explicit refusal of `0.0.0.0/0` in scan endpoint. |
| FEAT-JA4-DEAD | Gated by Phase 3 pcap source. |
| FEAT-SIGMA-EMBED | README phrasing nit, not a security risk. |
| CI-PIN-SHA | SHA-pin GitHub Actions to prevent tagjacking. |
| NOTICE-MIN | Apache 2.0 attributions in `NOTICE`. |
