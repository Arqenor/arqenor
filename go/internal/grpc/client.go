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
	"arqenor/go/internal/store"
)

const defaultHostAnalyzerAddr = "127.0.0.1:50051"

// HostAnalyzerClient wraps the gRPC connection to the Rust host analyzer.
type HostAnalyzerClient struct {
	conn   *grpc.ClientConn
	svc    pb.HostAnalyzerClient
	logger *zap.Logger
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
		conn:   conn,
		svc:    pb.NewHostAnalyzerClient(conn),
		logger: logger,
	}, nil
}

func (c *HostAnalyzerClient) Close() error {
	return c.conn.Close()
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
