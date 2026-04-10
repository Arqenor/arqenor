package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"go.uber.org/zap"

	"sentinel/go/internal/api"
	grpcclient "sentinel/go/internal/grpc"
	"sentinel/go/internal/scanner"
	"sentinel/go/internal/store"
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

	dbPath := filepath.Join("data", "sentinel.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		logger.Fatal("create data dir", zap.String("path", filepath.Dir(dbPath)), zap.Error(err))
	}

	st, err := store.Open(dbPath)
	if err != nil {
		logger.Fatal("open store", zap.String("path", dbPath), zap.Error(err))
	}
	defer st.Close()

	sc := scanner.New(logger)

	// Start REST API.
	router := api.NewServer(logger, sc, st)
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
