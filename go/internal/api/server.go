package api

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"arqenor/go/internal/api/routes"
	"arqenor/go/internal/config"
	"arqenor/go/internal/scanner"
	"arqenor/go/internal/store"
)

// NewServer is a thin re-export so callers don't need to import the
// internal/api/routes package directly.
func NewServer(logger *zap.Logger, sc *scanner.Scanner, st *store.Store, b *routes.AlertBroadcaster, cfg config.ApiConfig) *gin.Engine {
	return routes.NewServer(logger, sc, st, b, cfg)
}
