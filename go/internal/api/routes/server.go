package routes

import (
	"context"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"arqenor/go/internal/api/middleware"
	"arqenor/go/internal/config"
	"arqenor/go/internal/scanner"
	"arqenor/go/internal/store"
)

// ── Alert broadcaster (fan-out to SSE subscribers) ───────────────────────────

// AlertBroadcaster fans alerts out to any number of SSE subscribers up
// to MaxSubscribers; further subscribe attempts return ok=false so the
// HTTP handler can respond 503.
//
// The subscriber count is tracked with atomic.Int32 (cheap to read in the
// 503 fast-path) and reconciled with the map under the mutex on
// add/remove so the two views never diverge.
type AlertBroadcaster struct {
	mu             sync.Mutex
	subs           map[string]chan store.Alert
	subCount       atomic.Int32
	maxSubscribers int32
}

// NewAlertBroadcaster returns a broadcaster that admits up to maxSubs
// concurrent subscribers. A non-positive value disables the cap (legacy
// behaviour, used in tests).
func NewAlertBroadcaster(maxSubs int) *AlertBroadcaster {
	max := int32(maxSubs)
	if maxSubs <= 0 {
		max = 0 // 0 = unlimited
	}
	return &AlertBroadcaster{
		subs:           make(map[string]chan store.Alert),
		maxSubscribers: max,
	}
}

// Subscribe registers a new fan-out channel. Returns ok=false when the
// configured cap is exceeded; the caller MUST NOT use the returned id/ch
// in that case.
func (b *AlertBroadcaster) Subscribe() (id string, ch <-chan store.Alert, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.maxSubscribers > 0 && b.subCount.Load() >= b.maxSubscribers {
		return "", nil, false
	}

	raw := make(chan store.Alert, 64)
	id = uuid.New().String()
	b.subs[id] = raw
	b.subCount.Add(1)
	return id, raw, true
}

// Unsubscribe removes a previously-registered subscriber. Safe to call
// with an unknown id.
func (b *AlertBroadcaster) Unsubscribe(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ch, ok := b.subs[id]; ok {
		close(ch)
		delete(b.subs, id)
		b.subCount.Add(-1)
	}
}

// Publish delivers an alert to every subscriber, dropping the message
// for any subscriber whose buffer is full (back-pressure should not
// block the publisher / detection pipeline).
func (b *AlertBroadcaster) Publish(a store.Alert) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs {
		select {
		case ch <- a:
		default: // slow subscriber — drop rather than block
		}
	}
}

// SubscriberCount is exposed for tests / metrics.
func (b *AlertBroadcaster) SubscriberCount() int {
	return int(b.subCount.Load())
}

// ── HTTP server ───────────────────────────────────────────────────────────────

// ScannerBackend abstracts the scan engine the REST layer talks to.
//
// As of Phase 2C the production implementation is the gRPC client in
// internal/grpc that streams results from the Rust NetworkScanner
// service; the abstraction is kept narrow on purpose so unit tests can
// substitute a fake without pulling in a full gRPC stack.
type ScannerBackend interface {
	ScanCIDR(ctx context.Context, cidr string, ports []int) ([]scanner.HostResult, error)
}

type Server struct {
	scanner     ScannerBackend
	store       *store.Store
	logger      *zap.Logger
	broadcaster *AlertBroadcaster
	cfg         config.ApiConfig
}

// NewServer wires the Gin router with security middlewares (rate limit,
// redacting request logger), the v1 routes, and the alert broadcaster.
//
// The IPRateLimiter is owned by the returned engine — there is currently
// no Stop hook because the orchestrator process exits when the engine
// stops serving. Add one if/when the server is ever embedded in a longer
// host process.
//
// sc may be nil when the Rust gRPC backend is unreachable at startup;
// in that case POST /scans responds 503 Service Unavailable rather than
// silently dropping the request.
func NewServer(logger *zap.Logger, sc ScannerBackend, st *store.Store, b *AlertBroadcaster, cfg config.ApiConfig) *gin.Engine {
	srv := &Server{scanner: sc, store: st, logger: logger, broadcaster: b, cfg: cfg}

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.RequestLogger(logger))

	rl := middleware.NewIPRateLimiter(cfg.RateLimitPerSec, cfg.RateLimitPerSec*2)

	v1 := r.Group("/api/v1")
	v1.Use(middleware.RateLimit(rl))
	{
		v1.GET("/health", srv.handleHealth)
		v1.GET("/alerts", srv.handleListAlerts)
		v1.GET("/alerts/stream", srv.handleStreamAlerts)
		v1.GET("/scans", srv.handleListScans)
		v1.POST("/scans", srv.handleStartScan)
		v1.GET("/hosts", srv.handleListHosts)
	}

	return r
}

func (s *Server) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "arqenor-orchestrator"})
}

func (s *Server) handleListAlerts(c *gin.Context) {
	alerts, err := s.store.ListAlerts()
	if err != nil {
		s.logger.Error("list alerts", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch alerts"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"alerts": alerts})
}

// handleStreamAlerts streams real-time alerts as Server-Sent Events.
//
// Concurrency cap: enforced by AlertBroadcaster.Subscribe. When the cap
// is hit, returns 503 Service Unavailable rather than a 429 (this is a
// resource-saturation condition, not a per-client throttle).
func (s *Server) handleStreamAlerts(c *gin.Context) {
	id, ch, ok := s.broadcaster.Subscribe()
	if !ok {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "max sse connections reached",
		})
		return
	}
	defer s.broadcaster.Unsubscribe(id)

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no") // disable nginx response buffering

	clientCtx := c.Request.Context()

	c.Stream(func(_ io.Writer) bool {
		select {
		case alert, ok := <-ch:
			if !ok {
				return false
			}
			c.SSEvent("alert", alert)
			return true
		case <-clientCtx.Done():
			return false
		}
	})
}

func (s *Server) handleListScans(c *gin.Context) {
	scans, err := s.store.ListScans()
	if err != nil {
		s.logger.Error("list scans", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch scans"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"scans": scans})
}

func (s *Server) handleStartScan(c *gin.Context) {
	var req struct {
		CIDR  string `json:"cidr"  binding:"required"`
		Ports []int  `json:"ports"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if s.scanner == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "scanner backend unavailable",
		})
		return
	}

	scanID := uuid.New().String()
	if err := s.store.InsertScan(store.Scan{
		ID:        scanID,
		CIDR:      req.CIDR,
		Status:    "running",
		StartedAt: time.Now(),
	}); err != nil {
		s.logger.Error("insert scan", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record scan"})
		return
	}

	// Detach the scan from the request lifetime: we already returned
	// 202 to the client, so c.Request.Context() will be cancelled the
	// moment the response is flushed. Use a fresh background context
	// bounded by the configured scan timeout to prevent goroutine
	// leaks if scanner.ScanCIDR hangs (slow DNS / unresponsive hosts).
	timeout := time.Duration(s.cfg.ScanTimeoutSeconds) * time.Second
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		results, err := s.scanner.ScanCIDR(ctx, req.CIDR, req.Ports)
		if err != nil {
			s.logger.Error("scan failed",
				zap.String("id", scanID),
				zap.Error(err),
			)
			if updErr := s.store.UpdateScan(scanID, "error", 0); updErr != nil {
				s.logger.Error("update scan", zap.Error(updErr))
			}
			return
		}
		for _, h := range results {
			if err := s.store.UpsertHost(h.IP, h.Hostname); err != nil {
				s.logger.Warn("upsert host", zap.String("ip", h.IP), zap.Error(err))
			}
		}
		if err := s.store.UpdateScan(scanID, "done", len(results)); err != nil {
			s.logger.Error("update scan", zap.Error(err))
		}
	}()

	c.JSON(http.StatusAccepted, gin.H{"scan_id": scanID, "cidr": req.CIDR, "status": "running"})
}

func (s *Server) handleListHosts(c *gin.Context) {
	hosts, err := s.store.ListHosts()
	if err != nil {
		s.logger.Error("list hosts", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch hosts"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"hosts": hosts})
}
