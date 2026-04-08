# Phase 4 — ML Behavioral Engine
> Target: Q4 2026 | Priority: MEDIUM-HIGH | Effort: High

## Why Behavioral ML is Non-Negotiable in 2026

**84% of breaches use LOTL techniques** — attackers use legitimate tools, so
signature-based detection is blind. Even our Phase 1 LOTL rules will miss:
- Novel LOLBin combinations not in our ruleset
- Zero-day techniques that don't match any known pattern
- Slow/patient APTs that stay under individual thresholds
- Polymorphic malware that changes its binary on each infection

Behavioral ML detects **anomalies from normal behavior**, not known signatures.
If a process does something it's never done before, the model flags it —
regardless of whether it matches any rule.

---

## 4.1 — Static PE Analyzer

### First Line of Defense: Before Execution

When a new executable is created (via FIM or ETW), analyze its static features
before it runs. A lightweight model can give a risk score in < 10ms.

### Features

```rust
pub struct PeFeatures {
    // Header features
    pub file_size:          u64,
    pub header_entropy:     f64,
    pub section_count:      u8,
    pub has_debug_info:     bool,
    pub has_resources:      bool,
    pub compile_timestamp:  Option<u64>,  // None if stripped
    pub is_signed:          bool,
    pub signature_valid:    bool,

    // Section features
    pub max_section_entropy:   f64,   // > 7.0 = packed/encrypted
    pub mean_section_entropy:  f64,
    pub rx_section_count:      u8,    // executable sections
    pub rw_section_count:      u8,
    pub has_dot_text:          bool,
    pub abnormal_section_names: bool, // random-looking names

    // Import table features
    pub import_count:          u32,
    pub suspicious_imports:    Vec<String>,  // VirtualAllocEx, WriteProcessMemory, etc.
    pub import_entropy:        f64,
    pub has_crypto_imports:    bool,  // CryptEncrypt, etc.
    pub has_network_imports:   bool,  // WSAStartup, etc.

    // String features
    pub url_count:             u32,
    pub ip_count:              u32,
    pub registry_key_count:    u32,
    pub base64_blob_count:     u32,
    pub string_entropy_mean:   f64,
}
```

### Model: Gradient Boosted Trees (XGBoost)

Decision trees are ideal for on-device PE scoring:
- **Inference time**: < 1ms
- **Model size**: < 500KB (embeddable)
- **Accuracy**: ~96% on EMBER benchmark (industry standard)
- **Explainable**: Can output top contributing features ("high entropy section + VirtualAllocEx + no signature")

```rust
// sentinel-ml/src/pe_scorer.rs

pub struct PeScorer {
    model: GradientBoostModel,  // loaded from embedded bytes
}

impl PeScorer {
    pub fn score(&self, features: &PeFeatures) -> PeScore {
        PeScore {
            probability: self.model.predict(features),  // 0.0-1.0
            top_factors: self.model.explain(features),  // top 3 contributing features
        }
    }
}

// Model training: SOREL-20M dataset (20M PE samples from Sophos/ReversingLabs)
// or EMBER (1M samples from Elastic) — both publicly available
// Training: Python (scikit-learn / XGBoost) → export ONNX → load in Rust with ort crate
```

**Training pipeline** (separate from SENTINEL agent):
```
Python: train_pe_model.py
  → Load EMBER/SOREL-20M
  → Feature extraction
  → XGBoost training
  → ONNX export
  → Quantize to INT8 (model size reduction ~4x)
  → Embed in sentinel-ml/data/pe_model.onnx.zst
```

---

## 4.2 — Process Behavior Anomaly Detection

### The Core Idea

Build a **"normal behavior profile"** for each process type over time.
When a process deviates from its profile, generate an alert.

Example profiles:
- `chrome.exe` → normally makes HTTP/HTTPS connections, reads user profile files
- `svchost.exe -k netsvcs` → normally accesses registry, network, no process spawning
- `lsass.exe` → normally no outbound connections, no DLL loads from TEMP

If `chrome.exe` suddenly makes a connection on port 445 to an internal IP and
spawns a cmd.exe — that's an anomaly score of ~9.8/10.

### Feature Vector Per Process (per 5-minute window)

```rust
pub struct ProcessBehaviorWindow {
    pub pid:           u32,
    pub image_name:    String,
    pub window_start:  Instant,

    // Process operations
    pub children_spawned:      u32,
    pub unique_child_images:   Vec<String>,
    pub network_connections:   u32,
    pub unique_dest_ips:       u32,
    pub unique_dest_ports:     Vec<u16>,
    pub dns_queries:           u32,
    
    // File operations
    pub files_read:            u32,
    pub files_written:         u32,
    pub files_deleted:         u32,
    pub exe_files_written:     u32,  // writing PE files = suspicious
    
    // Registry operations
    pub registry_reads:        u32,
    pub registry_writes:       u32,
    pub autorun_keys_written:  u32,  // persistence attempt
    
    // Memory operations (from ETW phase 2)
    pub remote_memory_writes:  u32,
    pub rwx_allocations:       u32,
    
    // DLL loads
    pub new_dlls_loaded:       u32,
    pub unsigned_dlls_loaded:  u32,
}
```

### Model: Isolation Forest (Anomaly Detection)

Isolation Forest is ideal for anomaly detection (no labeled malware data required):

```
Training phase (30 days of normal activity):
  → Collect ProcessBehaviorWindow vectors for each process type
  → Fit Isolation Forest per process image name
  → Model stored per machine: ~/.sentinel/profiles/chrome.model

Detection phase (continuous):
  → Each 5-min window → compute features → score against model
  → Anomaly score > threshold → alert
  → Score = how "isolated" this sample is from normal behavior
```

**Advantages:**
- **Unsupervised** — no malware labels needed; learns what's normal for THIS machine
- **Adapts** over time — retrains monthly to account for software updates
- **Low false positive** — because it's calibrated to the specific machine's behavior

---

## 4.3 — SIGMA Rule Engine

SIGMA is the **open standard** for security detection rules — like Yara but
for log-based events. Thousands of community rules already exist, covering
nearly every ATT&CK technique.

### Why SIGMA Compatibility Matters

```yaml
# Example SIGMA rule (already written by the community)
title: Suspicious PowerShell Download
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - 'Invoke-WebRequest'
            - 'Net.WebClient'
            - 'DownloadString'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.001
```

By implementing SIGMA rule parsing, SENTINEL instantly gets **3,000+ detection rules**
from the community: https://github.com/SigmaHQ/sigma/tree/master/rules

```rust
// sentinel-core/src/rules/sigma.rs

pub struct SigmaRule {
    pub title:     String,
    pub attack_id: Vec<String>,
    pub level:     SigmaLevel,
    pub detection: Detection,
}

pub fn load_sigma_rules(path: &Path) -> Vec<SigmaRule> {
    // Parse YAML SIGMA files
    // Compile to SENTINEL's internal rule format
    // Support: process_creation, registry_event, network_connection, file_event
}

pub fn evaluate(rule: &SigmaRule, event: &TelemetryEvent) -> bool {
    // Match event fields against rule detection conditions
    // Support: contains, endswith, startswith, re (regex), all_of, 1_of
}
```

---

## 4.4 — Threat Intelligence Integration

### Local IOC Database

Store and match Indicators of Compromise locally (no external API needed in base tier):

```rust
// sentinel-store/src/ioc.rs

pub struct IocDatabase {
    pub hashes:    HashSet<[u8; 32]>,     // SHA-256 file hashes
    pub ips:       HashSet<Ipv4Addr>,     // known malicious IPs
    pub domains:   HashSet<String>,       // known malicious domains
    pub ja4_sigs:  HashSet<String>,       // malicious TLS fingerprints
}

impl IocDatabase {
    pub fn load_from_misp_feed(url: &str) -> Result<Self> { ... }
    pub fn load_from_abusech() -> Result<Self> { ... }  // Malware Bazaar
    pub fn load_from_otx() -> Result<Self> { ... }      // AlienVault OTX
    
    pub fn check_hash(&self, hash: &[u8; 32]) -> Option<&str> { ... }
    pub fn check_ip(&self, ip: Ipv4Addr) -> Option<&str> { ... }
    pub fn check_domain(&self, domain: &str) -> Option<&str> { ... }
}
```

**Free public feeds:**
- **MalwareBazaar** (abuse.ch) — malware hash feed, updated hourly
- **URLhaus** (abuse.ch) — malicious URLs
- **ThreatFox** (abuse.ch) — IOCs (IPs, domains, hashes)
- **Feodo Tracker** — botnet C2 IP blocklist
- **AlienVault OTX** — community threat intelligence
- **MISP** — feeds from various government CERTs

**Open-core premium:** Curated, high-fidelity feed with lower false positives,
automatic category tagging, and SLA for new IOC processing.

---

## 4.5 — Alert Correlation & Scoring

Single alerts are often benign. Combine them into incidents:

```
PowerShell encoded command (+30 pts)
   + DNS query to DGA-scored domain (+40 pts)
   + Outbound connection on unusual port (+20 pts)
   + No existing baseline for this behavior (+10 pts)
   ─────────────────────────────────────────────────
   = INCIDENT SCORE: 100 pts → CRITICAL incident
```

```rust
// sentinel-core/src/correlation.rs

pub struct Incident {
    pub id:          Uuid,
    pub score:       u32,
    pub severity:    Severity,
    pub attack_ids:  Vec<String>,
    pub events:      Vec<Alert>,
    pub summary:     String,        // human-readable narrative
    pub first_seen:  DateTime<Utc>,
    pub last_seen:   DateTime<Utc>,
}

pub struct CorrelationEngine {
    pub active_incidents: HashMap<u32 /* pid */, Incident>,
    pub rules: Vec<CorrelationRule>,
}
```

## Coverage After Phase 4

+25 techniques, mainly via SIGMA rule coverage:
- Complete T1059.* (all scripting/execution techniques)
- T1486 (ransomware pre-encryption behavior)
- T1566 (phishing execution patterns)
- Cross-technique attack chain detection
- Zero-day behavioral anomalies (not in any existing ruleset)
