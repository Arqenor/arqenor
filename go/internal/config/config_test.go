package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig_SecureDefaults(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Api.ListenAddr != "127.0.0.1:8080" {
		t.Errorf("default ListenAddr = %q, want loopback bind", cfg.Api.ListenAddr)
	}
	if cfg.Api.MaxSSEConnections != 100 {
		t.Errorf("default MaxSSEConnections = %d, want 100", cfg.Api.MaxSSEConnections)
	}
	if cfg.Api.RateLimitPerSec != 20 {
		t.Errorf("default RateLimitPerSec = %d, want 20", cfg.Api.RateLimitPerSec)
	}
	if cfg.Api.ScanTimeoutSeconds != 600 {
		t.Errorf("default ScanTimeoutSeconds = %d, want 600", cfg.Api.ScanTimeoutSeconds)
	}
	if cfg.General.DataDir != "./data" {
		t.Errorf("default DataDir = %q, want ./data", cfg.General.DataDir)
	}
}

func TestLoad_MissingFileFallsBackToDefaults(t *testing.T) {
	cfg, _, err := Load(filepath.Join(t.TempDir(), "does-not-exist.toml"))
	if err != nil {
		t.Fatalf("Load on missing file should not error, got %v", err)
	}
	if cfg.Api.ListenAddr != "127.0.0.1:8080" {
		t.Errorf("ListenAddr = %q, want default", cfg.Api.ListenAddr)
	}
}

func TestLoad_PartialOverridesMergeOnDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "arqenor.toml")
	body := `
[api]
listen_addr = "127.0.0.1:9000"
max_sse_connections = 7
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	cfg, _, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// overridden
	if cfg.Api.ListenAddr != "127.0.0.1:9000" {
		t.Errorf("ListenAddr = %q, want 127.0.0.1:9000", cfg.Api.ListenAddr)
	}
	if cfg.Api.MaxSSEConnections != 7 {
		t.Errorf("MaxSSEConnections = %d, want 7", cfg.Api.MaxSSEConnections)
	}
	// preserved from defaults
	if cfg.Api.RateLimitPerSec != 20 {
		t.Errorf("RateLimitPerSec = %d, want default 20", cfg.Api.RateLimitPerSec)
	}
	if cfg.Grpc.HostAnalyzerAddr != "127.0.0.1:50051" {
		t.Errorf("HostAnalyzerAddr = %q, want default", cfg.Grpc.HostAnalyzerAddr)
	}
}

func TestLoad_MalformedTOMLIsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(path, []byte("this = is = not = toml"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	if _, _, err := Load(path); err == nil {
		t.Fatal("Load on malformed TOML should error")
	}
}

func TestLoad_EnvVarOverridesDefaultPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "env.toml")
	body := `[api]
listen_addr = "127.0.0.1:1234"`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	t.Setenv(EnvVar, path)

	cfg, resolved, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if resolved != path {
		t.Errorf("resolved path = %q, want %q", resolved, path)
	}
	if cfg.Api.ListenAddr != "127.0.0.1:1234" {
		t.Errorf("ListenAddr = %q, want override", cfg.Api.ListenAddr)
	}
}
