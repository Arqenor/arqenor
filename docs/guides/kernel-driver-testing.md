# Guide : Tester le Kernel Driver ARQENOR sur VM

> Ce guide couvre l'installation et le test de `arqenor_driver.sys` sur une VM
> Windows en mode test signing. Aucun certificat payant n'est requis.

---

## Prerequis

### Sur ta machine de dev (host)

| Outil | Version | Installation |
|-------|---------|-------------|
| **Rust nightly** | Auto via `rust-toolchain.toml` | Le workspace `arqenor-driver/` force nightly |
| **WDK (Windows Driver Kit)** | 10.0.26100+ | [Download WDK](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk) |
| **Visual Studio Build Tools** | 2022+ | Workload "Desktop dev with C++" (pour `link.exe`) |
| **LLVM 17** | 17.0.6 | [LLVM Releases](https://github.com/llvm/llvm-project/releases/tag/llvmorg-17.0.6) — LLVM 18 casse bindgen ARM64 |
| **cargo-make** | 0.37+ | `cargo install cargo-make` |
| **cargo-wdk** | 0.3+ | `cargo install cargo-wdk` |

### Sur la VM (Windows 10/11)

| Requis | Detail |
|--------|--------|
| **Windows 10 21H2+** ou **Windows 11** | N'importe quelle edition |
| **Admin local** | Toutes les commandes driver requierent un shell admin |
| **WinDbg** (optionnel mais recommande) | Pour debugger un BSOD eventuel |

---

## Etape 1 — Preparer la VM

### 1.1 Activer le test signing

Ouvre PowerShell **en admin** dans la VM :

```powershell
bcdedit /set testsigning on
```

**Redemarrer la VM.** Un watermark "Test Mode" apparait en bas a droite — c'est normal.

### 1.2 (Optionnel) Activer le debug kernel

Si tu veux pouvoir debugger avec WinDbg en cas de BSOD :

```powershell
# Activer le debug via le port serie (pour Hyper-V / VMware / VirtualBox)
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200

# Ou via reseau (plus rapide) :
bcdedit /debug on
bcdedit /dbgsettings net hostip:<IP_HOST> port:50000
# Note la cle affichee — tu en auras besoin dans WinDbg
```

Redemarrer apres.

### 1.3 (Optionnel) Activer Driver Verifier

Driver Verifier detecte les bugs kernel (pool corruption, IRQL violations, etc.) :

```powershell
verifier /standard /driver arqenor_driver.sys
```

**Attention :** active verifier = plus de BSOD sur le moindre bug. Desactive-le si tu veux juste tester fonctionnellement :

```powershell
verifier /reset
```

---

## Etape 2 — Compiler le driver

Sur ta machine de dev :

```powershell
cd D:\dev\ARQENOR\arqenor-driver

# Verifier que LLVM 17 est dans le PATH
$env:LIBCLANG_PATH = "C:\Program Files\LLVM\bin"

# Build debug (plus rapide, avec symbols)
cargo make build-driver

# Ou build release (optimise)
cargo make build-driver-release
```

Le fichier produit :
- Debug : `arqenor-driver/target/debug/arqenor_driver.sys`
- Release : `arqenor-driver/target/release/arqenor_driver.sys`

### Verifier la compilation

```powershell
# Le .sys doit exister et faire ~100-500 KB
ls target\debug\arqenor_driver.sys
```

---

## Etape 3 — Signer le driver (test cert)

### Option A : Signature automatique (recommande)

```powershell
cargo make sign-test
```

Cela utilise le certificat WDK Test integre. Si ca echoue, cree un cert manuellement (option B).

### Option B : Creer un certificat de test manuellement

```powershell
# Creer un cert auto-signe (une seule fois)
# Ouvre "Developer Command Prompt for VS 2022" en admin :
makecert -r -pe -ss PrivateCertStore -n "CN=ARQENOR Dev Test" arqenor_test.cer

# Installer le cert dans le magasin de certificats root de la VM
certutil -addstore Root arqenor_test.cer
certutil -addstore TrustedPublisher arqenor_test.cer

# Signer le .sys
signtool sign /s PrivateCertStore /n "ARQENOR Dev Test" /fd sha256 target\debug\arqenor_driver.sys
```

### Verifier la signature

```powershell
signtool verify /v /pa target\debug\arqenor_driver.sys
# Doit afficher "Successfully verified"
```

---

## Etape 4 — Copier sur la VM

Copie `arqenor_driver.sys` sur la VM. Par exemple :

```powershell
# Partage de dossier, ou :
copy target\debug\arqenor_driver.sys \\VM_NAME\C$\Drivers\arqenor_driver.sys
```

Ou si tu utilises un dossier partage VMware/VirtualBox/Hyper-V, copie directement.

---

## Etape 5 — Installer et demarrer le driver

Dans la VM, PowerShell **admin** :

```powershell
# Installer le driver (mode demarrage manuel = "demand")
sc.exe create ArqenorDriver type= kernel start= demand binPath= "C:\Drivers\arqenor_driver.sys"

# Demarrer le driver
sc.exe start ArqenorDriver
```

**Si ca marche :**
```
SERVICE_NAME: ArqenorDriver
        TYPE               : 1  KERNEL_DRIVER
        STATE              : 4  RUNNING
```

**Si ca echoue :**
- `ERROR 577 (signature)` → Le test signing n'est pas actif ou le cert n'est pas installe
- `ERROR 2 (file not found)` → Mauvais chemin dans `binPath`
- `BSOD` → Bug dans le driver, verifier les logs WinDbg

### Verifier que le port IPC est cree

```powershell
# Le driver cree \ArqenorPort — si ce nom apparait dans les handles, c'est bon
# Methode simple : essayer de se connecter depuis ARQENOR
```

---

## Etape 6 — Lancer ARQENOR avec le driver

Sur la VM (ou en remote si le code est accessible) :

```powershell
cd D:\dev\ARQENOR
cargo run -p arqenor-cli --features kernel-driver -- watch
```

**Sortie attendue :**

```
  kernel driver: connected (\ArqenorPort)
ARQENOR watch — 16 process rules, 9 file rules | FIM: C:\Windows\System32 | db: arqenor.db
Press Ctrl-C to stop.
────────────────────────────────────────────────────────────────────────

[HIGH] 14:32:05 | lolbin | PowerShell Encoded Command — PID 9012 (powershell.exe) | T1059.001
[HIGH] 14:32:07 | registry_persistence | Registry persistence: SetValue on \Registry\Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | T1547.001
```

### Tester manuellement

Ouvre un autre terminal sur la VM et genere des evenements :

```powershell
# Process — devrait declencher la regle LOLBin
powershell -EncodedCommand ZQBjAGgAbwAgACIAdABlAHMAdAAiAA==

# Fichier — devrait declencher le FIM
echo "test" > C:\Windows\System32\drivers\etc\hosts

# Registry — devrait declencher l'alerte persistence
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v TestMalware /d "C:\temp\evil.exe" /f

# Nettoyage apres test
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v TestMalware /f
```

---

## Etape 7 — Arreter et desinstaller

```powershell
# Arreter le driver
sc.exe stop ArqenorDriver

# Supprimer le service
sc.exe delete ArqenorDriver

# (Optionnel) Desactiver le test signing
bcdedit /set testsigning off
# Redemarrer
```

---

## Commandes cargo make (raccourcis)

Toutes ces commandes s'executent depuis `arqenor-driver/` :

| Commande | Description |
|----------|-------------|
| `cargo make build-driver` | Build debug du .sys |
| `cargo make build-driver-release` | Build release du .sys |
| `cargo make build-client` | Build du client usermode (lib) |
| `cargo make build-all` | Build driver + client |
| `cargo make sign-test` | Signer avec le cert WDK test |
| `cargo make install-driver` | `sc create` + `sc start` |
| `cargo make uninstall-driver` | `sc stop` + `sc delete` |
| `cargo make enable-test-signing` | `bcdedit /set testsigning on` |
| `cargo make verifier-enable` | Activer Driver Verifier |
| `cargo make verifier-disable` | Desactiver Driver Verifier |

---

## Troubleshooting

### BSOD au demarrage du driver

1. Redemarrer la VM en mode sans echec : `bcdedit /set {current} safeboot minimal`
2. Supprimer le driver : `sc delete ArqenorDriver`
3. Redemarrer normal : `bcdedit /deletevalue {current} safeboot`
4. Analyser le dump : `C:\Windows\MEMORY.DMP` ou `C:\Windows\Minidump\*.dmp`
5. Ouvrir dans WinDbg : `!analyze -v`

### ERROR 577 : signature invalide

```powershell
# Verifier que test signing est actif
bcdedit | findstr testsigning
# Doit afficher: testsigning   Yes

# Verifier que le cert est installe
certutil -store Root | findstr ARQENOR
```

### Le driver demarre mais ARQENOR ne se connecte pas

```powershell
# Verifier que le driver tourne
sc.exe query ArqenorDriver
# STATE doit etre RUNNING

# Verifier les event logs pour des erreurs driver
Get-WinEvent -LogName System -MaxEvents 20 | Where-Object { $_.Message -like "*Arqenor*" }
```

### Performance : trop d'evenements

Le minifilter genere beaucoup d'events (chaque file I/O). Si la VM rame :

```powershell
# Ajouter des exclusions dans la config du bridge
# (pas encore implemente — TODO: DriverBridgeConfig.file_path_prefixes)
```

---

## Architecture du flux kernel

```
┌─────────────── KERNEL SPACE ───────────────────────┐
│                                                     │
│  PsSetCreateProcessNotifyRoutineEx ──┐              │
│  FltRegisterFilter (altitude 370010) ─┤──► IPC Port │
│  CmRegisterCallbackEx ───────────────┤  FltSendMsg  │
│  ObRegisterCallbacks (self-protect) ──┘              │
│                                                     │
└──────────────────────┬──────────────────────────────┘
                       │ \ArqenorPort
                       │ FilterGetMessage (blocking)
┌──────────────────────▼──────────────────────────────┐
│                                                     │
│  arqenor-driver-client (userspace)                 │
│  DriverClient::into_event_stream()                  │
│  │                                                  │
│  ▼                                                  │
│  driver_bridge.rs                                   │
│  ├─► ProcessEvent ──► DetectionPipeline (LOLBin)    │
│  ├─► FileEvent    ──► DetectionPipeline (FIM rules) │
│  └─► Alert        ──► Registry persistence direct   │
│                                                     │
│                 USER SPACE                           │
└─────────────────────────────────────────────────────┘
```

---

## Prochaines etapes (apres le test)

- [ ] Tester sur VM Windows 10 + Windows 11
- [ ] Verifier les 5 types d'events (process create/terminate, file create/write/rename/delete, registry)
- [ ] Benchmark : latence ajoutee par le minifilter sur les I/O fichier
- [ ] Tester Driver Verifier pendant 30 min sans BSOD
- [ ] Tester le self-protection : essayer de `taskkill /F` le process ARQENOR