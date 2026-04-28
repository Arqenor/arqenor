package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"go.uber.org/zap"

	"arqenor/go/internal/api"
	"arqenor/go/internal/api/routes"
	"arqenor/go/internal/config"
	grpcclient "arqenor/go/internal/grpc"
	"arqenor/go/internal/store"
)

// dirPerm / dbPerm — secure-by-default permissions for the on-disk
// state. The orchestrator is expected to run as the same UID that owns
// the data directory; everyone else must be denied access (alerts may
// contain sensitive process arguments / paths).
const (
	dirPerm os.FileMode = 0o700
	dbPerm  os.FileMode = 0o600
)

func main() {
	logger, _ := zap.NewProduction()
	defer func() { _ = logger.Sync() }()

	// Load config first — every downstream helper takes its values
	// from cfg. Defaults are loopback-bound; absence of the TOML file
	// is acceptable, malformed TOML is fatal.
	cfg, cfgPath, err := config.Load("")
	if err != nil {
		logger.Fatal("load config", zap.String("path", cfgPath), zap.Error(err))
	}
	logger.Info("config loaded",
		zap.String("path", cfgPath),
		zap.String("listen_addr", cfg.Api.ListenAddr),
		zap.Int("max_sse_connections", cfg.Api.MaxSSEConnections),
		zap.Int("rate_limit_per_sec", cfg.Api.RateLimitPerSec),
		zap.Int("scan_timeout_seconds", cfg.Api.ScanTimeoutSeconds),
	)

	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Connect to the Rust host analyzer gRPC server.
	// arqenor-grpc must be running before the orchestrator starts.
	// The same connection is reused for the NetworkScanner service
	// (Phase 2C) — see grpcclient.HostAnalyzerClient.ScanCIDR.
	client, err := grpcclient.NewHostAnalyzerClient(logger)
	if err != nil {
		logger.Warn("could not connect to arqenor-grpc — host analysis and network scans unavailable",
			zap.Error(err))
	} else {
		defer func() { _ = client.Close() }()
	}

	dbPath := filepath.Join(cfg.General.DataDir, "arqenor.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), dirPerm); err != nil {
		logger.Fatal("create data dir", zap.String("path", filepath.Dir(dbPath)), zap.Error(err))
	}
	// MkdirAll respects umask; force tight perms even on platforms
	// (and test environments) where umask is 022.
	if err := os.Chmod(filepath.Dir(dbPath), dirPerm); err != nil {
		logger.Warn("chmod data dir", zap.Error(err))
	}

	st, err := store.Open(dbPath)
	if err != nil {
		logger.Fatal("open store", zap.String("path", dbPath), zap.Error(err))
	}
	// modernc.org/sqlite respects umask when creating the DB file; bring
	// the perms back to 0600 explicitly. Tolerate ENOENT in case Open
	// did not need to create the file (e.g. memory-only configs).
	if err := os.Chmod(dbPath, dbPerm); err != nil && !os.IsNotExist(err) {
		logger.Warn("chmod db file", zap.String("path", dbPath), zap.Error(err))
	}
	defer func() { _ = st.Close() }()

	// Pick the scanner backend.  When the gRPC client failed to dial
	// the Rust server, leave it nil — the REST handler will surface a
	// 503 instead of silently falling back to a less capable engine.
	var scannerBackend routes.ScannerBackend
	if client != nil {
		scannerBackend = client
	}

	broadcaster := routes.NewAlertBroadcaster(cfg.Api.MaxSSEConnections)

	// Subscribe to the Rust detection pipeline and fan alerts out to:
	//   1. SQLite (durable storage)
	//   2. AlertBroadcaster (live SSE clients)
	// Auto-reconnect on stream failure with a 5 s back-off.
	if client != nil {
		go func() {
			for {
				err := client.WatchAlerts(ctx, func(a store.Alert) {
					if insertErr := st.InsertAlert(a); insertErr != nil {
						logger.Warn("insert alert", zap.Error(insertErr))
					}
					broadcaster.Publish(a)
				})
				if ctx.Err() != nil {
					return // clean shutdown — stop reconnecting
				}
				logger.Warn("alert stream disconnected, reconnecting in 5 s",
					zap.Error(err))
				select {
				case <-time.After(5 * time.Second):
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Start REST API.
	router := api.NewServer(logger, scannerBackend, st, broadcaster, cfg.Api)
	ln, err := net.Listen("tcp", cfg.Api.ListenAddr)
	if err != nil {
		logger.Fatal("listen", zap.String("addr", cfg.Api.ListenAddr), zap.Error(err))
	}

	go func() {
		logger.Info("REST API listening", zap.String("addr", cfg.Api.ListenAddr))
		if err := router.RunListener(ln); err != nil {
			logger.Error("API server error", zap.Error(err))
		}
	}()

	logger.Info("orchestrator ready")
	<-ctx.Done()
	logger.Info("orchestrator shutting down")
}
