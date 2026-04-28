// Package scanner exposes the orchestrator-side data transfer types for
// network scan results.
//
// As of Phase 2C the actual scanning is performed by the Rust
// arqenor-grpc NetworkScanner service; the Go orchestrator only consumes
// the streaming results over gRPC and stores them via store.Store.  The
// HostResult / PortResult structs below remain here as the shared DTO
// shape used by the gRPC adapter (internal/grpc) and the REST handlers
// (internal/api/routes) — keeping them in this package avoids an import
// cycle and preserves the existing public surface for REST clients.
//
// The legacy in-process Go scanner (Scanner struct, hostsInCIDR, etc.)
// has been removed; do not re-introduce it.  If the Rust gRPC backend is
// unavailable the orchestrator's /scans endpoint must surface the error
// rather than silently falling back to a less capable engine.
package scanner

// HostResult holds scan results for one discovered host.
type HostResult struct {
	IP       string
	Hostname string
	MAC      string
	IsUp     bool
	Ports    []PortResult
}

// PortResult holds the result for one scanned port.
type PortResult struct {
	Port    int
	Proto   string // "tcp" | "udp"
	State   string // "open" | "closed" | "filtered"
	Service string
	Banner  string
}
