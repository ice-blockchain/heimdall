// SPDX-License-Identifier: ice License 1.0

package main

import (
	"log/slog"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	swaggerfiles "github.com/swaggo/files"
	ginswagger "github.com/swaggo/gin-swagger"

	"github.com/ice-blockchain/heimdall/cmd/heimdall-token-analytics/api"
	"github.com/ice-blockchain/heimdall/cmd/heimdall-token-analytics/server"
)

func (s *service) httpHealthCheckHandler(c *gin.Context) {
	err := s.CheckHealth(c)
	if err != nil {
		slog.ErrorContext(c, "health check failed", "error", err)
		c.Writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	c.Writer.WriteHeader(http.StatusOK)
}

func (s *service) RegisterRoutes(router gin.IRouter) {
	corsConfig := cors.Config{
		AllowOrigins:     []string{"https://x.com", "https://pumpit.now"},
		AllowMethods:     []string{"GET", "POST", "PUT", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		AllowCredentials: false,
	}
	router.Use(cors.New(corsConfig))

	router.Use(server.AuthMiddleware())

	router.GET("/healthz", s.httpHealthCheckHandler)
	router.GET("/health-check", s.httpHealthCheckHandler)

	s.RegisterREST(router)
	s.RegisterStreams(router)
	s.RegisterWS(router)
}

func (s *service) RegisterREST(router gin.IRouter) {
	tokensV1 := router.Group("/v1/community-tokens")

	tokensV1.GET("/", server.RootHandler(s.GetCommunityTokens))
	tokensV1.GET("/:externalAddressOrViewType", server.RootHandler(s.GetCommunityTokensByType))
	tokensV1.POST("/:externalAddressOrViewType/viewing-sessions", server.RootHandler(s.CreateCommunityTokensSessionView))
	tokensV1.GET("/:externalAddressOrViewType/viewing-sessions/:viewingSessionId", server.RootHandler(s.GetCommunityTokensSessionByID))

	tokensV1.GET("/:externalAddressOrViewType/latest-trades", server.RootHandler(s.GetCommunityTokensTradesByAddress))
	tokensV1.PUT("/:externalAddressOrViewType/external-data", server.RootHandler(s.SyncCommunityTokenExternalData))

	api.SwaggerInfo.Version = readVersionString()
	router.GET("/docs", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/docs/swagger/index.html")
	})
	router.GET("/docs/swagger/*any", ginswagger.WrapHandler(swaggerfiles.Handler))
}

func (s *service) RegisterStreams(router gin.IRouter) {
	tokenStreamsV1 := router.Group("/v1sse/community-tokens", server.StreamMiddleware())
	tokenStreamsV1.GET("/", server.StreamHandler(s.StreamCommunityTokens))
	tokenStreamsV1.GET("/:externalAddressOrViewType", server.StreamHandler(s.StreamCommunityTokensByType))

	tokenStreamsV1.GET("/:externalAddressOrViewType/top-holders", server.StreamHandler(s.StreamCommunityTokensTopHolders))
	tokenStreamsV1.GET("/:externalAddressOrViewType/latest-trades", server.StreamHandler(s.StreamCommunityTokensLatestTrades))
	tokenStreamsV1.GET("/:externalAddressOrViewType/trading-stats", server.StreamHandler(s.StreamCommunityTokensTradingStats))
	tokenStreamsV1.GET("/:externalAddressOrViewType/ohlcv", server.StreamHandler(s.StreamCommunityTokensOHLCV))
}

func (s *service) RegisterWS(router gin.IRouter) {
	tokenWebsocketV1 := router.Group("/v1ws/community-tokens")
	tokenWebsocketV1.GET("/", server.WebsocketHandler(server.Stream2WebsocketHandler(s.StreamCommunityTokens)))
	tokenWebsocketV1.GET("/:externalAddressOrViewType", server.WebsocketHandler(server.Stream2WebsocketHandler(s.StreamCommunityTokensByType)))

	tokenWebsocketV1.GET("/:externalAddressOrViewType/top-holders", server.WebsocketHandler(server.Stream2WebsocketHandler(s.StreamCommunityTokensTopHolders)))
	tokenWebsocketV1.GET("/:externalAddressOrViewType/latest-trades", server.WebsocketHandler(server.Stream2WebsocketHandler(s.StreamCommunityTokensLatestTrades)))
	tokenWebsocketV1.GET("/:externalAddressOrViewType/trading-stats", server.WebsocketHandler(server.Stream2WebsocketHandler(s.StreamCommunityTokensTradingStats)))
	tokenWebsocketV1.GET("/:externalAddressOrViewType/ohlcv", server.WebsocketHandler(server.Stream2WebsocketHandler(s.StreamCommunityTokensOHLCV)))
}
