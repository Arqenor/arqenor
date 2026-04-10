package routes

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"sentinel/go/internal/scanner"
	"sentinel/go/internal/store"
)

type Server struct {
	scanner *scanner.Scanner
	store   *store.Store
	logger  *zap.Logger
}

func NewServer(logger *zap.Logger, sc *scanner.Scanner, st *store.Store) *gin.Engine {
	srv := &Server{scanner: sc, store: st, logger: logger}

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(requestLogger(logger))

	v1 := r.Group("/api/v1")
	{
		v1.GET("/health", srv.handleHealth)
		v1.GET("/alerts", srv.handleListAlerts)
		v1.GET("/scans", srv.handleListScans)
		v1.POST("/scans", srv.handleStartScan)
		v1.GET("/hosts", srv.handleListHosts)
	}

	return r
}

func (s *Server) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "sentinel-orchestrator"})
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

	go func() {
		results, err := s.scanner.ScanCIDR(context.Background(), req.CIDR, req.Ports)
		if err != nil {
			s.logger.Error("scan failed", zap.String("id", scanID), zap.Error(err))
			s.store.UpdateScan(scanID, "error", 0)
			return
		}
		for _, h := range results {
			s.store.UpsertHost(h.IP, h.Hostname)
		}
		s.store.UpdateScan(scanID, "done", len(results))
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

func requestLogger(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		logger.Info("request",
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.Int("status", c.Writer.Status()),
		)
	}
}
