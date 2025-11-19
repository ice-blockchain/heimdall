// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	swaggerfiles "github.com/swaggo/files"
	ginswagger "github.com/swaggo/gin-swagger"

	"github.com/ice-blockchain/heimdall/cmd/heimdall-token-analytics/api"
	"github.com/ice-blockchain/heimdall/cmd/heimdall-token-analytics/server"
	"github.com/ice-blockchain/heimdall/cmd/heimdall-token-analytics/server/websocket"
)

func (s *service) RegisterRoutes(router server.Router) {
	router.GET("/healthz", func(c *gin.Context) {
		err := s.CheckHealth(c)
		if err != nil {
			slog.ErrorContext(c, "health check failed", "error", err)
			c.Writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		c.Writer.WriteHeader(http.StatusOK)
	})

	router.GET("/v1/community-tokens", server.RootHandler(s.GetCommunityTokens))
	router.GET("/v1/community-tokens/:type", server.RootHandler(s.GetCommunityTokensByType))
	router.POST("/v1/community-tokens/:type/viewing-sessions", server.RootHandler(s.CreateCommunityTokensSessionView))
	router.GET("/v1/community-tokens/:type/viewing-sessions/:viewingSessionId", server.RootHandler(s.GetCommunityTokensSessionByID))

	// `:type` param here is `ionConnectAddress` actually but gin does not support having different param names for the same endpoint structure.
	router.GET("/v1/community-tokens/:type/latest-trades", server.RootHandler(s.GetCommunityTokensTradesByAddress))

	api.SwaggerInfo.Version = readVersionString()
	router.GET("/docs", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/docs/swagger/index.html")
	})
	router.GET("/docs/swagger/*any", ginswagger.WrapHandler(swaggerfiles.Handler))

}

func (s *service) HandleWS(ctx context.Context, stream websocket.ReaderWriter) {
	// TBD.
}
