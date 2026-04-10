use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// TlsInfo — TLS handshake metadata for fingerprinting
// ---------------------------------------------------------------------------

/// TLS handshake metadata extracted from a connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    /// JA4 fingerprint string (e.g. "t13d1516h2_8daaf6152771_b186095e22b6").
    pub ja4: String,
    /// Server Name Indication from the Client Hello.
    pub server_name: Option<String>,
    /// Human-readable TLS version (e.g. "TLS 1.3").
    pub tls_version: String,
}

// ---------------------------------------------------------------------------
// FlowKey — unique identifier for a connection flow
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub proto: String, // "TCP" or "UDP"
}

// ---------------------------------------------------------------------------
// FlowRecord — accumulated stats for a flow
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowRecord {
    pub key: FlowKey,
    pub pid: u32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub conn_count: u32,
    pub timestamps: Vec<DateTime<Utc>>, // connection timestamps for interval analysis
}

// ---------------------------------------------------------------------------
// BeaconScore — result of beacon analysis
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconScore {
    pub flow: FlowKey,
    pub connection_count: u32,
    pub interval_mean_ms: f64,
    pub interval_stddev_ms: f64,
    pub coefficient_of_variation: f64, // stddev/mean — low = regular = suspicious
    pub score: f64,                    // 0.0–1.0
}

// ---------------------------------------------------------------------------
// DnsQuery — a DNS query record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub domain: String,
    pub query_type: String, // "A", "AAAA", "TXT", "MX", etc.
    pub pid: u32,
    pub timestamp: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// DnsAnomalyScore — DNS tunneling / DGA analysis result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnomalyScore {
    pub domain: String,
    pub query_count: u32,
    pub unique_subdomains: u32,
    pub avg_subdomain_len: f64,
    pub avg_entropy: f64,
    pub tunneling_score: f64, // 0.0–1.0
    pub dga_score: f64,       // 0.0–1.0
}
