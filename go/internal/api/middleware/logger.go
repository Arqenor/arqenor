package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"arqenor/go/internal/util"
)

// RequestLogger replaces gin.Logger() with a zap-backed implementation
// that redacts secrets in URL query strings before they reach the log.
//
// Format intentionally minimal — adding fields is cheap, removing them is
// a breaking log-pipeline change.
func RequestLogger(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		latency := time.Since(start)

		query := util.RedactURL(c.Request.URL.RawQuery)

		logger.Info("request",
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.String("query", query),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("latency", latency),
			zap.String("client_ip", clientIP(c.Request.RemoteAddr)),
		)
	}
}
