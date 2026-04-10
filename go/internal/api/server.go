package api

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"arqenor/go/internal/api/routes"
	"arqenor/go/internal/scanner"
	"arqenor/go/internal/store"
)

func NewServer(logger *zap.Logger, sc *scanner.Scanner, st *store.Store, b *routes.AlertBroadcaster) *gin.Engine {
	return routes.NewServer(logger, sc, st, b)
}
