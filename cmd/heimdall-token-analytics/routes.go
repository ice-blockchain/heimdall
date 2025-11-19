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

	tokensV1 := router.Group("/v1/community-tokens")

	tokensV1.GET("/", server.RootHandler(s.GetCommunityTokens))
	tokensV1.GET("/:type", server.RootHandler(s.GetCommunityTokensByType))
	tokensV1.POST("/:type/viewing-sessions", server.RootHandler(s.CreateCommunityTokensSessionView))
	tokensV1.GET("/:type/viewing-sessions/:viewingSessionId", server.RootHandler(s.GetCommunityTokensSessionByID))

	// `:type` param here is `:ionConnectAddress` actually because gin does not support having different param names for the same endpoint structure.
	tokensV1.GET("/:type/latest-trades", server.RootHandler(s.GetCommunityTokensTradesByAddress))

	api.SwaggerInfo.Version = readVersionString()
	router.GET("/docs", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/docs/swagger/index.html")
	})
	router.GET("/docs/swagger/*any", ginswagger.WrapHandler(swaggerfiles.Handler))

	s.RegisterStreams(router)
}

func (s *service) RegisterStreams(router server.Router) {
	tokenStreamsV1 := router.Group("/v1sse/community-tokens", server.StreamMiddleware())
	tokenStreamsV1.GET("/", server.StreamHandler(s.StreamCommunityTokens))
	tokenStreamsV1.GET("/:type", server.StreamHandler(s.StreamCommunityTokensByType))

	// `:type` is the `:ionConnectAddress` bellow.
	tokenStreamsV1.GET("/:type/top-holders", server.StreamHandler(s.StreamCommunityTokensTopHolders))
	tokenStreamsV1.GET("/:type/latest-trades", server.StreamHandler(s.StreamCommunityTokensLatestTrades))
	tokenStreamsV1.GET("/:type/trading-stats", server.StreamHandler(s.StreamCommunityTokensTradingStats))
	tokenStreamsV1.GET("/:type/ohlcv", server.StreamHandler(s.StreamCommunityTokensOHLCV))
}

func (s *service) HandleWS(ctx context.Context, stream websocket.ReaderWriter) {
	// TBD.
}
