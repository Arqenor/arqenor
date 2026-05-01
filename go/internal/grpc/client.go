package grpcclient

import (
	"context"
	"fmt"
	"io"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "arqenor/go/internal/grpc/generated"
	"arqenor/go/internal/scanner"
	"arqenor/go/internal/store"
)

const defaultHostAnalyzerAddr = "127.0.0.1:50051"

// HostAnalyzerClient wraps the gRPC connection to the Rust host analyzer.
//
// A single underlying *grpc.ClientConn is shared between the HostAnalyzer
// and NetworkScanner stubs — both services are exposed by the same Rust
// arqenor-grpc process on :50051, so multiplexing them on one HTTP/2
// connection is the cheapest correct option (standard Tonic pattern).
type HostAnalyzerClient struct {
	conn       *grpc.ClientConn
	svc        pb.HostAnalyzerClient
	netScanSvc pb.NetworkScannerClient
	logger     *zap.Logger
}

func NewHostAnalyzerClient(logger *zap.Logger) (*HostAnalyzerClient, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	//nolint:staticcheck // grpc.DialContext deprecated in newer gRPC but kept for compatibility
	conn, err := grpc.DialContext(
		ctx,
		defaultHostAnalyzerAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("connect to host analyzer at %s: %w", defaultHostAnalyzerAddr, err)
	}

	logger.Info("connected to arqenor-grpc", zap.String("addr", defaultHostAnalyzerAddr))

	return &HostAnalyzerClient{
		conn:       conn,
		svc:        pb.NewHostAnalyzerClient(conn),
		netScanSvc: pb.NewNetworkScannerClient(conn),
		logger:     logger,
	}, nil
}

func (c *HostAnalyzerClient) Close() error {
	return c.conn.Close()
}

// NetworkScanner exposes the underlying NetworkScanner stub for callers
// that need to invoke methods not yet wrapped by this client.
func (c *HostAnalyzerClient) NetworkScanner() pb.NetworkScannerClient {
	return c.netScanSvc
}

// WatchAlerts subscribes to the real-time alert stream from the Rust detection
// pipeline.  For each received alert, onAlert is called synchronously.
// Returns when the stream ends or ctx is cancelled.
func (c *HostAnalyzerClient) WatchAlerts(ctx context.Context, onAlert func(store.Alert)) error {
	stream, err := c.svc.WatchAlerts(ctx, &emptypb.Empty{})
	if err != nil {
		return fmt.Errorf("open WatchAlerts stream: %w", err)
	}

	for {
		msg, err := stream.Recv()
		if err != nil {
			if err == io.EOF || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("recv alert: %w", err)
		}

		var occurredAt time.Time
		if ts := msg.GetOccurredAt(); ts != nil {
			occurredAt = time.Unix(ts.GetSeconds(), int64(ts.GetNanos())).UTC()
		} else {
			occurredAt = time.Now().UTC()
		}

		alert := store.Alert{
			ID:         msg.GetId(),
			Severity:   msg.GetSeverity().String(),
			Kind:       msg.GetKind(),
			Message:    msg.GetMessage(),
			OccurredAt: occurredAt,
			RuleID:     msg.GetRuleId(),
			AttackID:   msg.GetAttackId(),
		}
		onAlert(alert)
	}
}

// ProcessSnapshot calls GetProcessSnapshot (legacy placeholder kept for reference).
func (c *HostAnalyzerClient) ProcessSnapshot(ctx context.Context) error {
	resp, err := c.svc.GetProcessSnapshot(ctx, &emptypb.Empty{})
	if err != nil {
		return fmt.Errorf("process snapshot: %w", err)
	}
	c.logger.Info("process snapshot", zap.Int("count", len(resp.GetProcesses())))
	return nil
}

// ScanCIDR runs a network scan against the Rust NetworkScanner service and
// returns the full set of discovered hosts.  The Rust side streams results
// host-by-host; we drain the stream until io.EOF and convert each protobuf
// HostResult into the scanner.HostResult shape the orchestrator already
// uses for storage / REST responses.
//
// The signature mirrors the legacy scanner.Scanner.ScanCIDR so the REST
// handler can substitute one for the other transparently.  timeoutMs and
// serviceDetect are fixed at sensible defaults for Phase 2C; richer knobs
// can be plumbed through later via the REST request body.
func (c *HostAnalyzerClient) ScanCIDR(ctx context.Context, cidr string, ports []int) ([]scanner.HostResult, error) {
	const (
		defaultTimeoutMs     uint32 = 2000
		defaultServiceDetect bool   = false
	)
	return c.scanCIDR(ctx, cidr, ports, defaultTimeoutMs, defaultServiceDetect)
}

// scanCIDR is the internal worker behind ScanCIDR — split out so future
// callers can override the Rust-side timeout / service detection without
// changing the ScannerBackend interface.
func (c *HostAnalyzerClient) scanCIDR(
	ctx context.Context,
	cidr string,
	ports []int,
	timeoutMs uint32,
	serviceDetect bool,
) ([]scanner.HostResult, error) {
	pbPorts := make([]uint32, 0, len(ports))
	for _, p := range ports {
		if p < 0 || p > 65535 {
			return nil, fmt.Errorf("port out of range: %d", p)
		}
		pbPorts = append(pbPorts, uint32(p))
	}

	stream, err := c.netScanSvc.StartScan(ctx, &pb.ScanTarget{
		Cidr:          cidr,
		Ports:         pbPorts,
		TimeoutMs:     timeoutMs,
		ServiceDetect: serviceDetect,
	})
	if err != nil {
		return nil, fmt.Errorf("start scan %q: %w", cidr, err)
	}

	var results []scanner.HostResult
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("scan %q cancelled: %w", cidr, ctx.Err())
			}
			return nil, fmt.Errorf("recv host result: %w", err)
		}
		results = append(results, pbHostToScannerHost(msg))
	}
	return results, nil
}

// ReportAnomaly forwards an alert to the Rust NetworkScanner.ReportAnomaly
// endpoint.  Currently unused by the orchestrator but exposed for symmetry
// with the proto contract; safe to call concurrently with ScanCIDR (both
// share the same gRPC connection, multiplexed by HTTP/2).
func (c *HostAnalyzerClient) ReportAnomaly(ctx context.Context, alert *pb.Alert) error {
	if _, err := c.netScanSvc.ReportAnomaly(ctx, alert); err != nil {
		return fmt.Errorf("report anomaly: %w", err)
	}
	return nil
}

// pbHostToScannerHost is a pure, testable mapping from the wire-format
// HostResult to the orchestrator's internal DTO.  Kept package-private
// (lower-case) but exercised directly by client_test.go.
func pbHostToScannerHost(in *pb.HostResult) scanner.HostResult {
	if in == nil {
		return scanner.HostResult{}
	}
	out := scanner.HostResult{
		IP:       in.GetIp(),
		Hostname: in.GetHostname(),
		MAC:      in.GetMacAddr(),
		IsUp:     in.GetIsUp(),
	}
	openPorts := in.GetOpenPorts()
	if len(openPorts) > 0 {
		out.Ports = make([]scanner.PortResult, 0, len(openPorts))
		for _, p := range openPorts {
			if p == nil {
				continue
			}
			out.Ports = append(out.Ports, scanner.PortResult{
				Port:    int(p.GetPort()),
				Proto:   p.GetProto(),
				State:   p.GetState(),
				Service: p.GetService(),
				Banner:  p.GetBanner(),
			})
		}
	}
	return out
}
