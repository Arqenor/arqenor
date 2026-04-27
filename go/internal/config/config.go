// Package config loads the orchestrator configuration from a TOML file.
//
// Source of truth is `configs/arqenor.toml` at the repository root. The
// loader is intentionally permissive: a missing config file is **not** an
// error and falls back to safe defaults (loopback bind, conservative limits).
// Only an unreadable / malformed file causes a fatal failure at startup.
//
// Lookup order:
//  1. Explicit path passed to Load.
//  2. ARQENOR_CONFIG environment variable.
//  3. ./configs/arqenor.toml (repo-relative default).
//
// Defaults are documented in DefaultConfig and are applied field-by-field
// after parsing so a partial TOML only overrides what it sets.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
)

// Config is the typed view over arqenor.toml.
//
// Only the fields the Go orchestrator actually consumes are mapped — the
// Rust side has its own loader for [scan] / [alerts]. Adding a field here
// means the orchestrator now reads it; do not mirror everything blindly.
type Config struct {
	General GeneralConfig `toml:"general"`
	Grpc    GrpcConfig    `toml:"grpc"`
	Api     ApiConfig     `toml:"api"`
}

// GeneralConfig groups process-wide knobs.
type GeneralConfig struct {
	LogLevel string `toml:"log_level"`
	DataDir  string `toml:"data_dir"`
}

// GrpcConfig holds upstream gRPC endpoints the orchestrator dials.
type GrpcConfig struct {
	HostAnalyzerAddr   string `toml:"host_analyzer_addr"`
	NetworkScannerAddr string `toml:"network_scanner_addr"`
}

// ApiConfig governs the public REST/SSE surface.
//
// MaxSSEConnections caps concurrent /alerts/stream subscribers.
// RateLimitPerSec is the per-IP token bucket rate (burst = 2x).
// ScanTimeoutSeconds bounds the lifetime of a /scans request goroutine.
type ApiConfig struct {
	ListenAddr         string `toml:"listen_addr"`
	MaxSSEConnections  int    `toml:"max_sse_connections"`
	RateLimitPerSec    int    `toml:"rate_limit_per_sec"`
	ScanTimeoutSeconds int    `toml:"scan_timeout_seconds"`
}

// DefaultConfig returns the in-code fallback values used when a field is
// missing from the TOML. All defaults are *secure-by-default*: bind to
// loopback, conservative limits, fail-closed behaviour.
func DefaultConfig() Config {
	return Config{
		General: GeneralConfig{
			LogLevel: "info",
			DataDir:  "./data",
		},
		Grpc: GrpcConfig{
			HostAnalyzerAddr:   "127.0.0.1:50051",
			NetworkScannerAddr: "127.0.0.1:50052",
		},
		Api: ApiConfig{
			ListenAddr:         "127.0.0.1:8080",
			MaxSSEConnections:  100,
			RateLimitPerSec:    20,
			ScanTimeoutSeconds: 600,
		},
	}
}

// EnvVar is the environment variable that overrides the default config path.
const EnvVar = "ARQENOR_CONFIG"

// DefaultPath is the repo-relative location used when neither an explicit
// path nor the env var is set.
const DefaultPath = "configs/arqenor.toml"

// Load reads the config file and merges it on top of DefaultConfig.
//
// If explicitPath is empty, ARQENOR_CONFIG is consulted, then DefaultPath.
// A non-existent file is *not* an error — defaults are returned. A file
// that exists but cannot be parsed *is* an error (caller should treat as
// fatal at startup).
func Load(explicitPath string) (Config, string, error) {
	path := resolvePath(explicitPath)

	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// No config file → defaults. Return the resolved path so the
			// caller can log "would have used X".
			return cfg, path, nil
		}
		return Config{}, path, fmt.Errorf("read config %s: %w", path, err)
	}

	// Decode into a fresh struct then merge non-zero fields onto defaults.
	// This way a TOML that only sets [api].listen_addr does not zero out
	// the other defaults.
	var fileCfg Config
	if err := toml.Unmarshal(data, &fileCfg); err != nil {
		return Config{}, path, fmt.Errorf("parse config %s: %w", path, err)
	}

	merge(&cfg, fileCfg)
	if err := validate(&cfg); err != nil {
		return Config{}, path, fmt.Errorf("validate config %s: %w", path, err)
	}
	return cfg, path, nil
}

func resolvePath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if env := os.Getenv(EnvVar); env != "" {
		return env
	}
	// Resolve relative to CWD; let the FS layer decide if it exists.
	return filepath.Clean(DefaultPath)
}

// merge overlays non-zero fields from src onto dst. Strings: only non-empty
// values overwrite. Ints: only non-zero values overwrite. Anything more
// sophisticated would need an "is_set" tri-state, which TOML doesn't give us
// natively — and zero/empty are unambiguously invalid for every field here.
func merge(dst *Config, src Config) {
	if src.General.LogLevel != "" {
		dst.General.LogLevel = src.General.LogLevel
	}
	if src.General.DataDir != "" {
		dst.General.DataDir = src.General.DataDir
	}

	if src.Grpc.HostAnalyzerAddr != "" {
		dst.Grpc.HostAnalyzerAddr = src.Grpc.HostAnalyzerAddr
	}
	if src.Grpc.NetworkScannerAddr != "" {
		dst.Grpc.NetworkScannerAddr = src.Grpc.NetworkScannerAddr
	}

	if src.Api.ListenAddr != "" {
		dst.Api.ListenAddr = src.Api.ListenAddr
	}
	if src.Api.MaxSSEConnections > 0 {
		dst.Api.MaxSSEConnections = src.Api.MaxSSEConnections
	}
	if src.Api.RateLimitPerSec > 0 {
		dst.Api.RateLimitPerSec = src.Api.RateLimitPerSec
	}
	if src.Api.ScanTimeoutSeconds > 0 {
		dst.Api.ScanTimeoutSeconds = src.Api.ScanTimeoutSeconds
	}
}

func validate(cfg *Config) error {
	if cfg.Api.ListenAddr == "" {
		return errors.New("api.listen_addr must not be empty")
	}
	if cfg.Api.MaxSSEConnections <= 0 {
		return errors.New("api.max_sse_connections must be > 0")
	}
	if cfg.Api.RateLimitPerSec <= 0 {
		return errors.New("api.rate_limit_per_sec must be > 0")
	}
	if cfg.Api.ScanTimeoutSeconds <= 0 {
		return errors.New("api.scan_timeout_seconds must be > 0")
	}
	if cfg.General.DataDir == "" {
		return errors.New("general.data_dir must not be empty")
	}
	return nil
}
