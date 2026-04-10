package api

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"sentinel/go/internal/api/routes"
	"sentinel/go/internal/scanner"
	"sentinel/go/internal/store"
)

func NewServer(logger *zap.Logger, sc *scanner.Scanner, st *store.Store, b *routes.AlertBroadcaster) *gin.Engine {
	return routes.NewServer(logger, sc, st, b)
}
