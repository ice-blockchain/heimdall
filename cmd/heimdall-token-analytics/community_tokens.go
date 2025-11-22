// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/go-faker/faker/v4"

	"github.com/ice-blockchain/heimdall/cmd/heimdall-token-analytics/server"
	ta "github.com/ice-blockchain/heimdall/token-analytics"
)

type (
	PaginationRequest struct {
		Limit  uint64 `form:"limit"  swaggerignore:"true"`
		Offset uint64 `form:"offset" swaggerignore:"true"`
	}
	TokenInfoRequest struct {
		Addresses []string `form:"ionConnectAddress" required:"true" swaggerignore:"true"`
	}
	TokenInfoRequestByType struct {
		PaginationRequest
		Type    string `uri:"type" required:"true" swaggerignore:"true"`
		Keyword string `form:"keyword" swaggerignore:"true"`
	}
	TokenInfoRequestByTypeAndSessionID struct {
		TokenInfoRequestByType
		SessionID string `uri:"viewingSessionId" required:"true" swaggerignore:"true"`
		Keyword   string `form:"keyword" swaggerignore:"true"`
	}
	TokenInfoStreamTypeAndSessionQuery struct {
		PaginationRequest
		Type      string `uri:"type" required:"true" swaggerignore:"true"`
		SessionID string `form:"viewingSessionId" swaggerignore:"true"`
	}
	SessionViewCreateRequest struct {
		Type string `uri:"type" binding:"required,oneof=top trending" swaggerignore:"true"`
	}
	SessionViewCreateResponse struct {
		ID  string `json:"id" example:"550e8400-e29b-41d4-a716-446655440000"`
		TTL uint64 `json:"ttl" example:"1800" description:"Session TTL in seconds"` // Session TTL in seconds
	}
	TradeRequest struct {
		PaginationRequest
		Address string `uri:"type" required:"true" swaggerignore:"true"` // Map `type` to `address`.
	}
	TopHoldersRequest struct {
		Address string `uri:"type" required:"true" swaggerignore:"true"`
		Limit   uint32 `form:"limit" swaggerignore:"true"`
	}
	OHLCVRequest struct {
		Interval string `form:"interval" required:"true" swaggerignore:"true"` // e.g., "1m", "5m", "1h", etc.
		Address  string `uri:"type" required:"true" swaggerignore:"true"`      // Map `type` to `address`.
	}
)

// GetCommunityTokens godoc
//
//	@Schemes
//	@Description	Returns community tokens information for the given Ion Connect addresses.
//	@Tags			Tokens
//	@Produce		json
//	@Param			ionConnectAddress	query		[]string	true	"Ion Connect address of the user"	example(0x1234...,0x5678...)
//	@Param			Authorization		header		string		true	"Auth token"
//	@Success		200					{array}		ta.CommunityToken
//	@Failure		500					{object}	server.ResponseErrorBody
//	@Failure		504					{object}	server.ResponseErrorBody	"if request times out"
//	@Router			/v1/community-tokens [GET].
func (s *service) GetCommunityTokens(ctx context.Context, req *server.Request[TokenInfoRequest]) (*server.Response[[]*ta.CommunityToken], error) {
	if len(req.Data.Addresses) == 0 {
		return nil, server.BadRequest(errors.New("ionConnectAddress[] is required"), invalidPropertiesErrorCode)
	}
	tokens, err := s.tokenAnalytics.GetCommunityTokensByIonConnectAddresses(ctx, req.Data.Addresses, req.Token.GetMasterPublicKey())
	if err != nil {
		return nil, fmt.Errorf("failed to get community tokens: %w", err)
	}

	return server.OK(&tokens), nil
}

// GetCommunityTokensByType godoc
//
//	@Schemes
//	@Description	Returns community tokens information for the given Ion Connect addresses.
//	@Tags			Tokens
//	@Produce		json
//	@Param			type			path		string	true	"Type of data"				example("latest")
//	@Param			keyword			query		string	false	"Search keyword"			example("bitcoin")
//	@Param			limit			query		uint32	false	"Number of items to return"	example(10)
//	@Param			offset			query		uint32	false	"Number of items to skip"	example(0)
//	@Param			Authorization	header		string	true	"Auth token"
//	@Success		200				{array}		ta.CommunityToken
//	@Failure		500				{object}	server.ResponseErrorBody
//	@Failure		504				{object}	server.ResponseErrorBody	"if request times out"
//	@Router			/v1/community-tokens/{type} [GET].
func (s *service) GetCommunityTokensByType(ctx context.Context, req *server.Request[TokenInfoRequestByType]) (*server.Response[[]*ta.CommunityToken], error) {
	validTypes := map[string]bool{
		ta.TokenTypeLatest: true,
	}
	if !validTypes[req.Data.Type] {
		return nil, server.BadRequest(fmt.Errorf("invalid type: must be %s", ta.TokenTypeLatest), invalidPropertiesErrorCode)
	}

	limit := req.Data.Limit
	if limit == 0 {
		limit = 10
	}
	tokens, err := s.tokenAnalytics.GetCommunityTokensByType(ctx, req.Data.Type, req.Data.Keyword, limit, req.Data.Offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get community tokens by type: %w", err)
	}

	return server.OK(&tokens), nil
}

// CreateCommunityTokensSessionView godoc
//
//	@Schemes
//	@Description	Creates a new session view for community tokens analytics.
//	@Tags			Tokens
//	@Produce		json
//	@Param			type			path		string	true	"Type of session view"	example("latest")
//	@Param			Authorization	header		string	true	"Auth token"
//	@Success		200				{object}	SessionViewCreateResponse
//	@Failure		500				{object}	server.ResponseErrorBody
//	@Failure		504				{object}	server.ResponseErrorBody	"if request times out"
//	@Router			/v1/community-tokens/{type}/viewing-sessions [POST].
func (s *service) CreateCommunityTokensSessionView(ctx context.Context, req *server.Request[SessionViewCreateRequest]) (*server.Response[SessionViewCreateResponse], error) {
	clientIP := req.Context.ClientIP()
	deviceKey := req.Token.GetDeviceKey()
	sessionID, ttl, err := s.tokenAnalytics.CreateViewingSession(ctx, req.Data.Type, clientIP, deviceKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create viewing session: %w", err)
	}

	resp := SessionViewCreateResponse{
		ID:  sessionID,
		TTL: ttl,
	}
	return server.OK(&resp), nil
}

// GetCommunityTokensSessionByID godoc
//
//	@Schemes
//	@Description	Returns community tokens information for a specific viewing session.
//	@Tags			Tokens
//	@Produce		json
//	@Param			type				path		string	true	"Type of data"				example("top")
//	@Param			viewingSessionId	path		string	true	"Viewing session ID"		example("550e8400-e29b-41d4-a716-446655440000")
//	@Param			keyword				query		string	false	"Search keyword"			example("bitcoin")
//	@Param			limit				query		uint32	false	"Number of items to return"	example(10)
//	@Param			offset				query		uint32	false	"Number of items to skip"	example(0)
//	@Param			Authorization		header		string	true	"Auth token"
//	@Success		200					{array}		ta.CommunityToken
//	@Failure		500					{object}	server.ResponseErrorBody
//	@Failure		504					{object}	server.ResponseErrorBody	"if request times out"
//	@Router			/v1/community-tokens/{type}/viewing-sessions/{viewingSessionId} [GET].
func (s *service) GetCommunityTokensSessionByID(ctx context.Context, req *server.Request[TokenInfoRequestByTypeAndSessionID]) (*server.Response[[]*ta.CommunityToken], error) {
	limit := req.Data.Limit
	if limit == 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}
	offset := req.Data.Offset
	resp, err := s.tokenAnalytics.GetTokensFromViewingSession(ctx, req.Data.Type, req.Data.SessionID, req.Data.Keyword, limit, offset)
	if err != nil {
		if errors.Is(err, ta.ErrSessionNotFound) {
			return nil, server.NotFound(ta.ErrSessionNotFound, sessionNotFoundErrorCode)
		}
		return nil, fmt.Errorf("failed to get tokens from viewing session: %w", err)
	}

	return server.OK(&resp), nil
}

// GetCommunityTokensTradesByAddress godoc
//
//	@Schemes
//	@Description	Returns trade history for a specific community token address.
//	@Tags			Tokens
//	@Produce		json
//	@Param			ionConnectAddress	path		string	true	"Ion Connect address"		example("0x1234...")
//	@Param			limit				query		uint32	false	"Number of items to return"	example(10)
//	@Param			offset				query		uint32	false	"Number of items to skip"	example(0)
//	@Param			Authorization		header		string	true	"Auth token"
//	@Success		200					{array}		ta.Trade
//	@Failure		500					{object}	server.ResponseErrorBody
//	@Failure		504					{object}	server.ResponseErrorBody	"if request times out"
//	@Router			/v1/community-tokens/{ionConnectAddress}/latest-trades [GET].
func (s *service) GetCommunityTokensTradesByAddress(ctx context.Context, req *server.Request[TradeRequest]) (*server.Response[[]*ta.Trade], error) {
	limit := req.Data.Limit
	if limit == 0 {
		limit = 50
	}
	resp, _, err := s.tokenAnalytics.GetLatestTrades(ctx, req.Data.Address, limit, req.Data.Offset, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest trades: %w", err)
	}

	return server.OK(&resp), nil
}

func newFakeStreamOf[T any]() (server.StreamEventEmitter[T], error) {
	return func(ctx context.Context) (<-chan server.StreamEvent[T], error) {
		events := make(chan server.StreamEvent[T])
		fire := make(chan struct{}, 1)
		ticker := time.NewTicker(time.Minute)

		fire <- struct{}{}

		go func() {
			defer close(events)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					select {
					case fire <- struct{}{}:
					default:
					}
				case <-fire:
					var e T

					slog.DebugContext(ctx, "emitting fake stream event", "type", fmt.Sprintf("%T", e))
					if err := faker.FakeData(&e); err != nil {
						events <- server.StreamEvent[T]{Err: fmt.Errorf("failed to fake stream data: %w", err)}
						return
					}
					events <- server.StreamEvent[T]{Data: &e, Type: "message"}
				}
			}
		}()

		return events, nil
	}, nil
}

// StreamCommunityTokens godoc
//
//	@Schemes
//	@Description	Streams community tokens information for the given Ion Connect addresses.
//	@Tags			sse
//	@Produce		text/event-stream
//	@Param			ionConnectAddress	query		[]string	true	"Ion Connect address of the user"	example(0x1234...,0x5678...)
//	@Param			Authorization		header		string		true	"Auth token"
//	@Success		200					{object}	ta.CommunityToken
//	@Failure		500					{object}	server.ResponseErrorBody
//	@Failure		504					{object}	server.ResponseErrorBody	"if request times out"
//	@Router			/v1sse/community-tokens [GET].
func (s *service) StreamCommunityTokens(ctx context.Context, req *server.Request[TokenInfoRequest]) (server.StreamEventEmitter[ta.CommunityToken], error) {
	if len(req.Data.Addresses) == 0 {
		return nil, server.BadRequest(errors.New("ionConnectAddress[] is required"), invalidPropertiesErrorCode)
	}

	return func(ctx context.Context) (<-chan server.StreamEvent[ta.CommunityToken], error) {
		events := make(chan server.StreamEvent[ta.CommunityToken], 100)

		sendData := func() bool {
			tokens, err := s.tokenAnalytics.GetCommunityTokensByIonConnectAddresses(ctx, req.Data.Addresses, req.Token.GetMasterPublicKey())
			if err != nil {
				slog.ErrorContext(ctx, "failed to get community tokens for streaming", "error", err, "addresses", req.Data.Addresses)
				events <- server.StreamEvent[ta.CommunityToken]{
					Type: "error",
					Data: nil,
					Err:  err,
					ID:   fmt.Sprintf("error-%d", time.Now().UnixNano()),
				}

				return false
			}
			for _, token := range tokens {
				events <- server.StreamEvent[ta.CommunityToken]{
					Type: "message",
					Data: token,
					ID:   fmt.Sprintf("token-%d", time.Now().UnixNano()),
				}
			}
			slog.DebugContext(ctx, "sent community tokens update", "count", len(tokens))

			return true
		}

		ticker := time.NewTicker(1 * time.Second)
		go func() {
			defer close(events)
			defer ticker.Stop()

			if !sendData() {
				slog.ErrorContext(ctx, "initial data send failed for community tokens stream")

				return
			}

			for ctx.Err() == nil {
				select {
				case <-ctx.Done():
					slog.DebugContext(ctx, "community tokens stream context cancelled")

					return

				case <-ticker.C:
					if !sendData() {
						slog.ErrorContext(ctx, "periodic data send failed for community tokens stream")

						return
					}
				}
			}
		}()

		return events, nil
	}, nil
}

// StreamCommunityTokensByType godoc
//
//	@Schemes
//	@Description	Streams community tokens information for the given type.
//	@Tags			sse
//	@Produce		text/event-stream
//	@Param			type				path		string	true	"Type of data"	example("latest","featured","top","trending")
//	@Param			viewingSessionId	query		string	false	"Viewing session ID (required for top/trending)"	example("550e8400-e29b-41d4-a716-446655440000")
//	@Param			Authorization		header		string	true	"Auth token"
//	@Success		200					{array}		ta.CommunityToken
//	@Failure		400					{object}	server.ResponseErrorBody
//	@Failure		500					{object}	server.ResponseErrorBody
//	@Failure		504					{object}	server.ResponseErrorBody	"if request times out"
//	@Router			/v1sse/community-tokens/{type} [GET].
func (s *service) StreamCommunityTokensByType(ctx context.Context, req *server.Request[TokenInfoStreamTypeAndSessionQuery]) (server.StreamEventEmitter[[]*ta.CommunityToken], error) {
	validTypes := map[string]bool{
		ta.TokenTypeLatest:   true,
		ta.TokenTypeFeatured: true,
		ta.TokenTypeTop:      true,
		ta.TokenTypeTrending: true,
	}
	if !validTypes[req.Data.Type] {
		return nil, server.BadRequest(fmt.Errorf("invalid type: must be one of %s, %s, %s, %s", ta.TokenTypeLatest, ta.TokenTypeFeatured, ta.TokenTypeTop, ta.TokenTypeTrending), invalidPropertiesErrorCode)
	}

	if (req.Data.Type == ta.TokenTypeTop || req.Data.Type == ta.TokenTypeTrending) && req.Data.SessionID == "" {
		return nil, server.BadRequest(errors.New("viewingSessionId is required for top and trending types"), invalidPropertiesErrorCode)
	}

	limit := uint64(100)
	return func(ctx context.Context) (<-chan server.StreamEvent[[]*ta.CommunityToken], error) {
		events := make(chan server.StreamEvent[[]*ta.CommunityToken], 100)

		sendData := func() bool {
			var tokens []*ta.CommunityToken
			var err error
			if (req.Data.Type == ta.TokenTypeTop || req.Data.Type == ta.TokenTypeTrending) && req.Data.SessionID != "" {
				tokens, err = s.tokenAnalytics.GetTokensFromViewingSession(ctx, req.Data.Type, req.Data.SessionID, "", limit, 0)
			} else {
				tokens, err = s.tokenAnalytics.GetCommunityTokensByType(ctx, req.Data.Type, "", limit, 0)
			}

			if err != nil {
				slog.ErrorContext(ctx, "failed to get community tokens for streaming", "error", err, "type", req.Data.Type, "sessionID", req.Data.SessionID)
				events <- server.StreamEvent[[]*ta.CommunityToken]{
					Type: "error",
					Data: nil,
					Err:  err,
				}

				return false
			}

			events <- server.StreamEvent[[]*ta.CommunityToken]{
				Type: "message",
				Data: &tokens,
			}
			slog.DebugContext(ctx, "sent community tokens update", "type", req.Data.Type, "sessionID", req.Data.SessionID, "count", len(tokens))

			return true
		}

		ticker := time.NewTicker(1 * time.Second)
		go func() {
			defer close(events)
			defer ticker.Stop()
			if !sendData() {
				slog.ErrorContext(ctx, "initial data send failed for community tokens stream", "type", req.Data.Type, "sessionID", req.Data.SessionID)
				return
			}

			for ctx.Err() == nil {
				select {
				case <-ctx.Done():
					slog.DebugContext(ctx, "community tokens stream context cancelled", "type", req.Data.Type, "sessionID", req.Data.SessionID)

					return

				case <-ticker.C:
					if !sendData() {
						slog.ErrorContext(ctx, "periodic data send failed for community tokens stream", "type", req.Data.Type, "sessionID", req.Data.SessionID)

						return
					}
				}
			}
		}()

		return events, nil
	}, nil
}

// StreamCommunityTokensTopHolders godoc
//
//	@Schemes
//	@Description	Streams top holders information for a specific community token address.
//	@Tags			sse
//	@Produce		text/event-stream
//	@Param			ionConnectAddress	path		string	true	"Ion Connect address"		example("0x1234...")
//	@Param			limit				query		uint32	false	"Number of items to return"	example(10)
//	@Param			Authorization		header		string	true	"Auth token"
//	@Success		200					{object}	[]ta.TopHolderPosition
//	@Failure		500					{object}	server.ResponseErrorBody
//	@Failure		504					{object}	server.ResponseErrorBody	"if request times out"
//	@Router			/v1sse/community-tokens/{ionConnectAddress}/top-holders [GET].
func (s *service) StreamCommunityTokensTopHolders(ctx context.Context, req *server.Request[TopHoldersRequest]) (server.StreamEventEmitter[[]*ta.TopHolderPosition], error) {
	ionConnectAddress := req.Data.Address
	limit := req.Data.Limit
	if limit == 0 {
		limit = 10
	}
	if limit > 200 {
		limit = 200
	}

	return func(ctx context.Context) (<-chan server.StreamEvent[[]*ta.TopHolderPosition], error) {
		events := make(chan server.StreamEvent[[]*ta.TopHolderPosition], 2)
		holders, err := s.tokenAnalytics.GetTopHolders(ctx, ionConnectAddress, int64(limit))
		if err != nil {
			return nil, fmt.Errorf("failed to get initial top holders: %w", err)
		}
		events <- server.StreamEvent[[]*ta.TopHolderPosition]{
			Type: "message",
			Data: &holders,
		}

		emptyHolders := make([]*ta.TopHolderPosition, 0)
		events <- server.StreamEvent[[]*ta.TopHolderPosition]{
			Type: "eose",
			Data: &emptyHolders,
			ID:   "end-of-snapshot",
		}

		ticker := time.NewTicker(1 * time.Second)
		go func() {
			defer close(events)
			defer ticker.Stop()

			for ctx.Err() == nil {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					holders, err := s.tokenAnalytics.GetTopHolders(ctx, ionConnectAddress, int64(limit))
					if err != nil {
						events <- server.StreamEvent[[]*ta.TopHolderPosition]{
							Err:  err,
							Data: nil,
							Type: "error",
						}
						return
					}
					events <- server.StreamEvent[[]*ta.TopHolderPosition]{
						Type: "message",
						Data: &holders,
					}
				}
			}
		}()

		return events, nil
	}, nil
}

// StreamCommunityTokensLatestTrades godoc
//
//	@Schemes
//	@Description	Streams latest trades for a specific community token address.
//	@Tags			sse
//	@Produce		text/event-stream
//	@Param			ionConnectAddress	path		string	true	"Ion Connect address"		example("0x1234...")
//	@Param			limit				query		uint32	false	"Number of items to return"	example(10)
//	@Param			offset				query		uint32	false	"Number of items to skip"	example(0)
//	@Param			Authorization		header		string	true	"Auth token"
//	@Success		200					{object}	ta.Trade
//	@Failure		500					{object}	server.ResponseErrorBody
//	@Failure		504					{object}	server.ResponseErrorBody	"if request times out"
//	@Router			/v1sse/community-tokens/{ionConnectAddress}/latest-trades [GET].
func (s *service) StreamCommunityTokensLatestTrades(ctx context.Context, req *server.Request[TradeRequest]) (server.StreamEventEmitter[ta.Trade], error) {
	return s.latestTradesStream(req.Data.Address, req.Data.Limit, 0)
}

// StreamCommunityTokensTradingStats godoc
//
//	@Schemes
//	@Description	Streams trading statistics for a specific community token address.
//	@Tags			sse
//	@Produce		text/event-stream
//	@Param			ionConnectAddress	path		string	true	"Ion Connect address"	example("0x1234...")
//	@Param			Authorization		header		string	true	"Auth token"
//	@Success		200					{object}	ta.TradeStats
//	@Failure		500					{object}	server.ResponseErrorBody
//	@Failure		504					{object}	server.ResponseErrorBody	"if request times out"
//	@Router			/v1sse/community-tokens/{ionConnectAddress}/trading-stats [GET].
func (s *service) StreamCommunityTokensTradingStats(ctx context.Context, req *server.Request[TradeRequest]) (server.StreamEventEmitter[ta.TradeStats], error) {
	return s.tradingStatsStream(req.Data.Address)
}

// StreamCommunityTokensOHLCV godoc
//
//	@Schemes
//	@Description	Streams OHLCV (Open, High, Low, Close, Volume) data for a specific community token address.
//	@Tags			sse
//	@Produce		text/event-stream
//	@Param			ionConnectAddress	path		string	true	"Ion Connect address"	example("0x1234...")
//	@Param			interval			query		string	true	"Time interval"			example("1m")
//	@Param			Authorization		header		string	true	"Auth token"
//	@Success		200					{object}	ta.OHLCV
//	@Failure		500					{object}	server.ResponseErrorBody
//	@Failure		504					{object}	server.ResponseErrorBody	"if request times out"
//	@Router			/v1sse/community-tokens/{ionConnectAddress}/ohlcv [GET].
func (s *service) StreamCommunityTokensOHLCV(ctx context.Context, req *server.Request[OHLCVRequest]) (server.StreamEventEmitter[ta.OHLCV], error) {
	return s.ohlcvStream(req.Data.Address, req.Data.Interval)
}

func (s *service) ohlcvStream(ionContentAddress string, intervalStr string) (server.StreamEventEmitter[ta.OHLCV], error) {
	interval := ta.Interval(intervalStr)
	if err := interval.Validate(); err != nil {
		return nil, errors.Wrapf(err, "invalid interval")
	}
	return func(ctx context.Context) (<-chan server.StreamEvent[ta.OHLCV], error) {
		events := make(chan server.StreamEvent[ta.OHLCV], 100) // buffered to populate initial data in candlechart without blocking
		now := time.Now()
		start := now.Add(-time.Duration(interval.WindowSize()))
		ohlcvs, err := s.tokenAnalytics.GetOHLVCHistory(ctx, now, start, ionContentAddress, interval)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get initial ohlcv data (history)")
		}
		recent, err := s.tokenAnalytics.GetOHLVCRecent(ctx, now, ionContentAddress, interval)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get initial ohlcv data (recent)")
		}
		for i := range ohlcvs {
			events <- server.StreamEvent[ta.OHLCV]{
				Err:  nil,
				Data: ohlcvs[i],
				Type: "message",
				ID:   fmt.Sprintf("ohlcv_%v", ohlcvs[i].Timestamp),
			}
		}
		events <- server.StreamEvent[ta.OHLCV]{
			Err:  nil,
			Data: recent,
			Type: "message",
			ID:   fmt.Sprintf("ohlcv_%v", recent.Timestamp),
		}
		ticker := time.NewTicker(1 * time.Second) // TODO: cfg?
		go func() {
			defer close(events)
			defer ticker.Stop()
			for ctx.Err() == nil {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					now = time.Now()
					recent, err = s.tokenAnalytics.GetOHLVCRecent(ctx, now, ionContentAddress, interval)
					if err != nil {
						events <- server.StreamEvent[ta.OHLCV]{
							Err:  err,
							Data: nil,
							Type: "error",
							ID:   fmt.Sprintf("ohlcv_%v", now.UnixNano()),
						}
						return
					}
					events <- server.StreamEvent[ta.OHLCV]{
						Err:  nil,
						Data: recent,
						Type: "message",
						ID:   fmt.Sprintf("ohlcv_%v", recent.Timestamp),
					}
				}
			}
		}()
		return events, nil
	}, nil
}

func (s *service) tradingStatsStream(ionContentAddress string) (server.StreamEventEmitter[ta.TradeStats], error) {
	return func(ctx context.Context) (<-chan server.StreamEvent[ta.TradeStats], error) {
		events := make(chan server.StreamEvent[ta.TradeStats], 1)
		now := time.Now()
		stats, err := s.tokenAnalytics.GetTradingStats(ctx, now, ionContentAddress)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get initial trading stats for %v", ionContentAddress)
		}
		events <- server.StreamEvent[ta.TradeStats]{
			Err:  nil,
			Data: stats,
			Type: "message",
		}
		ticker := time.NewTicker(1 * time.Second) // TODO: cfg?
		go func() {
			defer close(events)
			defer ticker.Stop()
			for ctx.Err() == nil {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					now = time.Now()
					stats, err = s.tokenAnalytics.UpdateTradingStats(ctx, now, ionContentAddress)
					if err != nil {
						events <- server.StreamEvent[ta.TradeStats]{
							Err:  err,
							Data: nil,
							Type: "error",
						}
						return
					}
					events <- server.StreamEvent[ta.TradeStats]{
						Err:  nil,
						Data: stats,
						Type: "message",
					}
				}
			}
		}()
		return events, nil
	}, nil
}
func (s *service) latestTradesStream(ionContentAddress string, limit, offset uint32) (server.StreamEventEmitter[ta.Trade], error) {
	return func(ctx context.Context) (<-chan server.StreamEvent[ta.Trade], error) {
		events := make(chan server.StreamEvent[ta.Trade], limit)
		trades, lastTs, err := s.tokenAnalytics.GetLatestTrades(ctx, ionContentAddress, limit, offset, nil)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get initial last trades %v", ionContentAddress)
		}
		for _, t := range trades {
			events <- server.StreamEvent[ta.Trade]{
				Err:  nil,
				Data: t,
				Type: "message",
			}
		}

		ticker := time.NewTicker(1 * time.Second) // TODO: cfg?
		go func() {
			defer close(events)
			defer ticker.Stop()
			for ctx.Err() == nil {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					trades, lastTs, err = s.tokenAnalytics.GetLatestTrades(ctx, ionContentAddress, limit, 0, &lastTs)
					if err != nil {
						events <- server.StreamEvent[ta.Trade]{
							Err:  err,
							Data: nil,
							Type: "error",
						}
						return
					}
					for _, t := range trades {
						events <- server.StreamEvent[ta.Trade]{
							Err:  nil,
							Data: t,
							Type: "message",
						}
					}
				}
			}
		}()
		return events, nil
	}, nil
}
