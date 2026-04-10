# Phase 6 — Cloud Dashboard + Fleet Management (Open-Core Premium)
> Target: Q2 2027 | Priority: MEDIUM | Effort: Very High

## Open-Core Business Model

```
FREE (open source, MIT license)          PAID (SaaS, closed source)
─────────────────────────────────────    ────────────────────────────────────
✅ Local agent (all detection)           🔒 Multi-machine fleet dashboard
✅ Terminal UI + Desktop app             🔒 Centralized alert correlation
✅ All detection phases 1-5              🔒 Managed threat intelligence feeds
✅ SIGMA rule engine                     🔒 ML model cloud updates (daily)
✅ Basic network scanner                 🔒 Automated response actions
✅ Local IOC matching                    🔒 Compliance reports (SOC2, PCI-DSS)
✅ Offline operation                     🔒 MDR (Managed Detection & Response)
                                         🔒 API for SIEM integration
                                         🔒 Threat hunting workspace
```

Comparable: Wazuh (free agent) + Wazuh Cloud (paid SIEM)
Our advantage: much stronger endpoint detection capability than Wazuh.

---

## 6.1 — Agent → Cloud Architecture

```
Endpoint A (ARQENOR agent)
Endpoint B (ARQENOR agent)    ──→  arqenor-cloud API  ──→  Web Dashboard
Endpoint C (ARQENOR agent)              │
                                         ▼
                               PostgreSQL (alerts, telemetry)
                               Redis (real-time event bus)
                               ClickHouse (high-volume telemetry OLAP)
                               OpenSearch (log search + threat hunting)
```

### Agent Telemetry Protocol

```protobuf
// proto/telemetry.proto (add to existing proto/ directory)

message AgentEvent {
    string  agent_id    = 1;
    string  hostname    = 2;
    string  os          = 3;
    int64   timestamp   = 4;
    oneof event {
        ProcessEvent    process    = 5;
        AlertEvent      alert      = 6;
        NetworkEvent    network    = 7;
        PersistenceEvent persist   = 8;
    }
}

message AlertEvent {
    string  rule_id     = 1;
    string  title       = 2;
    string  attack_id   = 3;
    Severity severity   = 4;
    map<string, string> context = 5;
}
```

Transport: gRPC over TLS (existing `arqenor-grpc` crate), with mutual TLS
authentication (agent cert issued at enrollment).

---

## 6.2 — Fleet Dashboard (React + Next.js)

### Pages

**Fleet Overview**
- World map (or network diagram) showing all endpoints
- Status: online/offline/alerting
- Top alerts across fleet in last 24h
- MITRE ATT&CK heatmap: which techniques active across fleet

**Per-Machine Drilldown**
- Timeline of all events (process, network, persistence, alerts)
- Process tree visualization (interactive, expandable)
- Network connections graph
- ATT&CK technique coverage for this machine

**Threat Hunting**
- SQL query interface over all telemetry
- Pre-built hunt templates:
  ```sql
  -- Find all PowerShell with encoded commands in last 7 days
  SELECT hostname, pid, cmdline, timestamp
  FROM process_events
  WHERE image LIKE '%powershell%'
    AND cmdline LIKE '%-EncodedCommand%'
    AND timestamp > NOW() - INTERVAL '7 days'
  ORDER BY timestamp DESC
  ```

**Alert Management**
- Incident queue with severity tiers
- One-click: isolate host, kill process, quarantine file
- Comment + assign + close workflow
- Slack/Teams/PagerDuty notification webhooks

---

## 6.3 — MITRE ATT&CK Heatmap

Visual representation of which techniques are active across the fleet.
Makes executive reporting dramatically easier.

```
ARQENOR ATT&CK Coverage — Last 30 days

TA0002 Execution    ████████████ T1059.001 (47 alerts)
                    ████         T1218.010 (12 alerts)
TA0003 Persistence  ████████     T1547.001 (28 alerts)
                    ██           T1053.005 (8 alerts)
TA0006 Cred Access  ████         T1003.001 (15 alerts, 2 CRITICAL)
```

---

## 6.4 — Automated Response (Premium)

**Process Isolation**
- Kill a flagged process remotely
- Prevent re-spawn (hash-block via AppLocker)

**Host Isolation**
- Block all network traffic except to ARQENOR cloud (for investigation)
- Implemented via Windows Firewall API / iptables on Linux
- One-click from dashboard

**File Quarantine**
- Move flagged file to encrypted quarantine container
- Record SHA-256, original path, timestamps
- One-click restore if false positive

**Automated Playbooks**
```yaml
# Example: auto-respond to LSASS access
name: lsass_protection
trigger:
  rule_id: SENT-CRED-001  # LSASS access by non-system process
actions:
  - type: alert_slack
    channel: "#security-alerts"
  - type: kill_process
    condition: score >= 8
  - type: create_memory_dump  # for forensics
    pid: "{{event.pid}}"
  - type: page_oncall
    condition: score >= 9
```

---

## 6.5 — Compliance Reporting

Automated report generation for common frameworks:

| Framework | Key Controls Covered |
|-----------|---------------------|
| SOC 2 Type II | CC6.1 (logical access), CC7.1 (security events monitoring) |
| PCI-DSS v4 | Req 10 (log monitoring), Req 11 (security testing) |
| NIST CSF 2.0 | Detect (DE.AE), Respond (RS.AN) |
| CIS Controls v8 | Control 8 (audit logs), Control 13 (network monitoring) |

---

## 6.6 — Architecture Decisions

### Why ClickHouse for Telemetry

ClickHouse handles:
- Billions of process events per day across thousands of endpoints
- Sub-second queries on 90-day rolling window
- Columnar storage = perfect for time-series telemetry
- Used by Cloudflare, ByteDance at massive scale

### Why Keep Agent Offline-First

The agent MUST function without cloud connectivity:
- Airports, air-gapped networks, cloud outage
- All Phase 1-5 detection works locally
- Cloud is additive (fleet view, managed feeds, response)
- This is a hard requirement that differentiates ARQENOR from SaaS-only tools

### gRPC + Existing arqenor-grpc

Re-use the existing `arqenor-grpc` crate (Phase 2 of original plan).
Add new proto definitions for fleet telemetry.
The cloud API is just a gRPC server in Go (existing plan) receiving from agents.

---

## Pricing Model (Reference)

| Tier | Price | Features |
|------|-------|----------|
| Community | Free | Full agent, local-only, all phases 1-5 |
| Teams | $8/endpoint/month | + Cloud dashboard, 3 users, 30-day retention |
| Business | $18/endpoint/month | + Automated response, 90-day retention, 20 users |
| Enterprise | Custom | + MDR, SIEM integration, custom retention, SLA |

Comparable: Wazuh Cloud ($3.50/agent), Elastic Security ($95/host/month).
ARQENOR positioning: stronger detection than Wazuh, fraction of Elastic's cost.
