package models

import "time"

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Alert struct {
	ID         string            `json:"id"`
	Severity   Severity          `json:"severity"`
	Kind       string            `json:"kind"`
	Message    string            `json:"message"`
	OccurredAt time.Time         `json:"occurred_at"`
	Metadata   map[string]string `json:"metadata"`
}

type ScanResult struct {
	ScanID    string       `json:"scan_id"`
	CIDR      string       `json:"cidr"`
	StartedAt time.Time    `json:"started_at"`
	EndedAt   *time.Time   `json:"ended_at,omitempty"`
	Hosts     []HostResult `json:"hosts"`
}

type HostResult struct {
	IP       string       `json:"ip"`
	Hostname string       `json:"hostname,omitempty"`
	MAC      string       `json:"mac,omitempty"`
	IsUp     bool         `json:"is_up"`
	Ports    []PortResult `json:"ports,omitempty"`
}

type PortResult struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	State   string `json:"state"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
	Version string `json:"version,omitempty"`
}
