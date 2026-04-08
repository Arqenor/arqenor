package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"sentinel/go/internal/api"
	grpcclient "sentinel/go/internal/grpc"
)

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Connect to the Rust host analyzer gRPC server.
	// sentinel-grpc must be running before the orchestrator starts.
	client, err := grpcclient.NewHostAnalyzerClient(logger)
	if err != nil {
		logger.Warn("could not connect to sentinel-grpc — host analysis unavailable",
			zap.Error(err))
	} else {
		defer client.Close()
	}

	// Start REST API
	router := api.NewServer(logger)
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		logger.Fatal("listen :8080", zap.Error(err))
	}

	go func() {
		logger.Info("REST API listening", zap.String("addr", ":8080"))
		if err := router.RunListener(ln); err != nil {
			logger.Error("API server error", zap.Error(err))
		}
	}()

	logger.Info("orchestrator ready")
	<-ctx.Done()
	logger.Info("orchestrator shutting down")
}
