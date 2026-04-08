package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// NewServer creates and configures the Gin REST API router.
func NewServer(logger *zap.Logger) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()

	r.Use(gin.Recovery())
	r.Use(requestLogger(logger))

	v1 := r.Group("/api/v1")
	{
		v1.GET("/health", handleHealth)
		v1.GET("/alerts", handleListAlerts)
		v1.GET("/scans", handleListScans)
		v1.POST("/scans", handleStartScan)
		v1.GET("/hosts", handleListHosts)
	}

	return r
}

func handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"service": "sentinel-orchestrator",
	})
}

func handleListAlerts(c *gin.Context) {
	// TODO: query SQLite store
	c.JSON(http.StatusOK, gin.H{"alerts": []interface{}{}})
}

func handleListScans(c *gin.Context) {
	// TODO: return scan history
	c.JSON(http.StatusOK, gin.H{"scans": []interface{}{}})
}

func handleStartScan(c *gin.Context) {
	var req struct {
		CIDR  string `json:"cidr"  binding:"required"`
		Ports []int  `json:"ports"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// TODO: dispatch to scanner.ScanCIDR
	c.JSON(http.StatusAccepted, gin.H{"scan_id": "pending", "cidr": req.CIDR})
}

func handleListHosts(c *gin.Context) {
	// TODO: return known network hosts from SQLite
	c.JSON(http.StatusOK, gin.H{"hosts": []interface{}{}})
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
