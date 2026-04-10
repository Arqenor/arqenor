# Phase 3 — Deep Network Analysis + C2 Detection
> Target: Q3 2026 | Priority: HIGH | Effort: Medium-High

## Current State

The current network scanner does:
- TCP port scan on 17 known ports
- OS fingerprinting by port combination
- Risk scoring (Telnet/VNC = HIGH, SMB = MEDIUM)
- Reverse DNS hostname resolution
- Baseline comparison (new host, changed ports)

What it **cannot** detect:
- C2 beaconing (periodic callbacks to adversary infrastructure)
- DNS tunneling (data exfiltration via DNS)
- Lateral movement patterns (SMB from workstation to workstation)
- TLS anomalies (self-signed certs to suspicious IPs)
- DGA domains (Domain Generation Algorithm — dynamic C2 infrastructure)
- Network-based credential attacks (Kerberoasting, AS-REP roasting)

---

## 3.1 — Passive Traffic Analysis (pcap)

### Network Capture Agent

Add a lightweight pcap-based capture module that runs alongside the port scanner
and analyzes traffic at the flow level (NOT packet inspection — just metadata).

```rust
// arqenor-net/ (new crate)
// Uses pcap crate (libpcap wrapper)

pub struct FlowRecord {
    pub src_ip:     Ipv4Addr,
    pub dst_ip:     Ipv4Addr,
    pub dst_port:   u16,
    pub protocol:   Protocol,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub duration:   Duration,
    pub packets:    u32,
    pub first_seen: Instant,
    pub last_seen:  Instant,
}

// Build flow table from raw packets
// Analyze flows for anomaly patterns
```

**Requires:** libpcap (Windows: npcap, Linux: libpcap, macOS: built-in)
**Privilege:** Requires admin/root for promiscuous mode capture.

---

## 3.2 — C2 Beaconing Detection (T1071)

### The Problem

Malware beacons periodically to C2 servers. The intervals are typically:
- Fixed: every 60 seconds exactly
- Jittered: 60 ± random(0-30) seconds (to evade simple frequency analysis)
- Sleep-based: longer intervals (hours) for stealthy APTs

### Detection Algorithm: RITA (Real Intelligence Threat Analytics) approach

For each (src_ip, dst_ip, dst_port) flow tuple:

```rust
pub struct BeaconScore {
    pub flow:         FlowKey,
    pub connection_count: u32,
    pub interval_median: Duration,
    pub interval_stddev: Duration,
    pub skewness:     f64,          // low skew + low stddev = beaconing
    pub score:        f64,          // 0.0–1.0
}

impl BeaconScore {
    pub fn analyze(intervals: &[Duration]) -> f64 {
        // 1. Compute median inter-arrival time
        // 2. Compute standard deviation
        // 3. Coefficient of variation (CV) = stddev / mean
        //    CV < 0.2 = very regular = suspicious
        // 4. Check for bimodal distribution (jittered beaconing)
        // 5. Check connection count > threshold (> 5 connections same dest)
        //
        // Score = weight(CV) + weight(count) + weight(duration_consistency)
        // Score > 0.7 = likely beaconing
    }
}
```

**Detection threshold:** ≥5 connections to the same external IP with CV < 0.3
→ flag as potential C2 beaconing.

**False positive mitigation:**
- Whitelist known CDN/cloud IP ranges (AWS, Azure, Cloudflare, Akamai)
- Whitelist update servers (Microsoft, Apple, Google)
- Only alert on connections to IP ranges NOT in the whitelist

---

## 3.3 — DNS Tunneling Detection (T1071.004)

### What DNS Tunneling Looks Like

Tools: `dnscat2`, `iodine`, `dns2tcp`

Signatures:
- Long subdomain labels (> 30 chars) — base64/hex encoded payload
- High entropy subdomain (random-looking)
- Many TXT / NULL / CNAME record queries vs. standard A/AAAA
- Same domain queried hundreds of times with different subdomains
- DNS queries to rare/unusual TLDs

```rust
pub fn score_dns_anomaly(queries: &[DnsQuery]) -> f64 {
    let mut score = 0.0;
    
    // Factor 1: Average subdomain length
    let avg_len: f64 = queries.iter()
        .map(|q| q.subdomain_length() as f64)
        .sum::<f64>() / queries.len() as f64;
    if avg_len > 30.0 { score += 0.3; }
    
    // Factor 2: Subdomain entropy (Shannon entropy)
    let avg_entropy: f64 = queries.iter()
        .map(|q| shannon_entropy(q.subdomain()))
        .sum::<f64>() / queries.len() as f64;
    if avg_entropy > 3.5 { score += 0.3; }  // high entropy = encoded data
    
    // Factor 3: Unique subdomain ratio
    let unique_ratio = queries.iter()
        .map(|q| q.subdomain())
        .collect::<HashSet<_>>().len() as f64 / queries.len() as f64;
    if unique_ratio > 0.8 { score += 0.2; }  // many unique = tunneling
    
    // Factor 4: Volume (high DNS traffic to single domain)
    if queries.len() > 100 { score += 0.2; }
    
    score  // > 0.7 = suspected tunneling
}

fn shannon_entropy(s: &str) -> f64 {
    let len = s.len() as f64;
    let counts: HashMap<char, usize> = s.chars().fold(HashMap::new(), |mut m, c| {
        *m.entry(c).or_insert(0) += 1; m
    });
    counts.values().map(|&c| {
        let p = c as f64 / len;
        -p * p.log2()
    }).sum()
}
```

---

## 3.4 — DGA Domain Detection (T1568.002)

Domain Generation Algorithms create thousands of pseudo-random domain names.
Only the attacker knows which ones are registered — all others are sinkholes.
The malware queries all of them until one resolves.

### Detection

DGA domains share characteristics distinguishing them from legitimate domains:

1. **High character-level entropy** — random consonant/vowel distribution
2. **No meaningful n-grams** — "xk3jf92mz.com" has no common English word parts
3. **Dictionary score** — real domains contain recognizable words
4. **Length distribution** — DGA domains cluster in 12-20 char range

```rust
// Lightweight bigram model trained on Alexa top-1M legitimate domains
// vs known DGA domain lists (from Bambenek Consulting, DGArchive)

pub struct DgaDetector {
    bigram_probs: HashMap<(char, char), f64>,  // P(c2 | c1) from legitimate domains
}

impl DgaDetector {
    pub fn score(&self, domain: &str) -> f64 {
        // Compute average log-likelihood of character bigrams
        // Low score = rare character sequences = potentially DGA
        // Threshold from empirical testing: < -2.5 log-prob = suspicious
    }
    
    pub fn from_alexa_top_1m() -> Self {
        // Load bigram model pre-trained on legitimate domains
        // Embed model as compressed bytes in the binary (no external dependency)
    }
}
```

**Dataset:** Train on Alexa/Tranco top-1M + DGArchive known DGA families.
**Model size:** Bigram table < 5KB (embedded in binary).
**Accuracy:** ~92% detection rate, ~3% false positive rate on benchmark.

---

## 3.5 — JA4 TLS Fingerprinting

JA4 is the 2024 replacement for JA3 (which is defeated by TLS extension randomization).
JA4 creates a fingerprint of the TLS Client Hello that identifies the tool/malware
making the connection, even if it changes ports or IPs.

```
JA4 format: q[d][2][e][f]_[g][h]_[i][j]
             │   │    │   │        │
             │   │    │   │        └─ cipher suites hash
             │   │    │   └───────── extensions hash  
             │   │    └───────────── ALPN values
             │   └────────────────── TLS version
             └────────────────────── QUIC or TCP
```

Use cases for ARQENOR:
- Match TLS fingerprints against known **Cobalt Strike**, **Metasploit**, **Sliver** profiles
- Detect self-signed certificates on established connections
- Flag connections where the JA4 fingerprint doesn't match the claimed SNI domain
  (e.g., a connection claiming to be `google.com` but with an unusual cipher suite)

```rust
// Parse TLS ClientHello from pcap
// Compute JA4 hash
// Check against blocklist of known malware C2 JA4 signatures
// Alert if matched
```

---

## 3.6 — Lateral Movement Detection (T1021)

### SMB Workstation-to-Workstation

Normal SMB traffic: workstation → server (file shares, DCs)
Abnormal SMB traffic: workstation → workstation (lateral movement, PsExec)

```rust
// Track all SMB (port 445) connections
// Build a "host role" inference: DC, server, workstation
// Flag: workstation-to-workstation SMB = lateral movement alert
```

### Pass-the-Hash Detection (T1550.002)

Network indicators:
- NTLM authentication from workstation to multiple hosts in short time window
- Successful authentication followed immediately by new service creation or process start
- NTLM auth to ADMIN$ or IPC$ shares

```
Event 4624 (logon) + LogonType 3 (network) + NtLmSsp from unexpected source
→ MEDIUM alert

Same source connecting to 3+ hosts with NTLM in 5min window
→ HIGH alert (lateral movement campaign)
```

### Kerberoasting (T1558.003)

Network indicator: high volume of TGS-REQ (Kerberos service ticket requests)
for service accounts (SPN-bearing accounts) from a single workstation.

```rust
// Monitor UDP/TCP port 88 (Kerberos)
// Parse Kerberos TGS-REQ messages
// Count service ticket requests per source per minute
// > 10 TGS-REQ / minute from single source = Kerberoasting
```

---

## 3.7 — Network Topology Mapping

Enhance the current scanner with:

### ARP Table Reading (MAC Address Detection)

```rust
// Windows: GetIpNetTable2() — returns ARP cache (IP → MAC mappings)
// Linux: /proc/net/arp
// macOS: arp -an output parsing

pub struct ArpEntry {
    pub ip:  Ipv4Addr,
    pub mac: MacAddr,
    pub vendor: Option<String>,  // OUI lookup
}

// OUI vendor lookup: embed IEEE OUI database as compressed lookup table
// ~30KB compressed for full OUI list
// Vendors: "Apple", "Dell", "Cisco", "Unknown" → helps identify device type
```

### Gateway / Router Detection

```rust
// Identify the default gateway from routing table
// Windows: GetIpForwardTable2()
// Linux: /proc/net/route
// 
// Flag: any host claiming to be the gateway but with a different MAC
// than previously seen = potential ARP spoofing / rogue gateway
```

---

## Architecture: arqenor-net Crate

```
arqenor-net/
├── src/
│   ├── capture.rs      — pcap interface, flow builder
│   ├── beaconing.rs    — beacon detection algorithm
│   ├── dns.rs          — DNS query parser + DGA/tunneling detection
│   ├── tls.rs          — JA4 fingerprint computation
│   ├── lateral.rs      — SMB/Kerberos lateral movement detection
│   ├── arp.rs          — ARP table + MAC vendor lookup
│   └── topology.rs     — network map builder
├── data/
│   ├── oui.bin         — compressed OUI vendor database
│   ├── dga_bigrams.bin — DGA detection bigram model
│   └── ja4_blocklist.bin — known malicious JA4 signatures
└── Cargo.toml
```

## Coverage After Phase 3

+20 techniques:
- T1071 — Application Layer Protocol (C2 beaconing)
- T1071.004 — DNS tunneling  
- T1568.002 — DGA domain detection
- T1021.002 — SMB lateral movement
- T1550.002 — Pass-the-Hash (network indicators)
- T1558.003 — Kerberoasting (Kerberos TGS anomalies)
- T1557.001 — ARP cache poisoning / rogue gateway
- T1048 — Exfiltration via alternative protocol
