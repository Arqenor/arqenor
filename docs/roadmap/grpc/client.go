package grpcclient

import (
	"context"
	"fmt"
	"io"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	// Generated stubs will be in ./generated after running scripts/gen-proto.ps1
	// pb "arqenor/go/internal/grpc/generated"
)

const defaultHostAnalyzerAddr = "127.0.0.1:50051"

// HostAnalyzerClient wraps the gRPC connection to the Rust host analyzer.
type HostAnalyzerClient struct {
	conn   *grpc.ClientConn
	logger *zap.Logger
	// svc    pb.HostAnalyzerClient  // uncomment after proto codegen
}

func NewHostAnalyzerClient(logger *zap.Logger) (*HostAnalyzerClient, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

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
		logger: logger,
		// svc: pb.NewHostAnalyzerClient(conn),
	}, nil
}

func (c *HostAnalyzerClient) Close() error {
	return c.conn.Close()
}

// ProcessSnapshot calls GetProcessSnapshot and returns raw JSON bytes for now.
// Replace with typed proto response once codegen runs.
func (c *HostAnalyzerClient) ProcessSnapshot(ctx context.Context) error {
	// TODO: uncomment after proto codegen
	// resp, err := c.svc.GetProcessSnapshot(ctx, &emptypb.Empty{})
	// if err != nil { return err }
	// c.logger.Info("process snapshot", zap.Int("count", len(resp.Processes)))
	c.logger.Info("ProcessSnapshot: proto codegen pending")
	_ = io.EOF // suppress unused import
	return nil
}
