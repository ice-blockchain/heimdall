// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/go-faker/faker/v4"

	"github.com/ice-blockchain/heimdall/cmd/heimdall-token-analytics/server"
	ta "github.com/ice-blockchain/heimdall/token-analytics"
)

type (
	PaginationRequest struct {
		Limit  uint32 `form:"limit"  swaggerignore:"true"`
		Offset uint32 `form:"offset" swaggerignore:"true"`
	}
	TokenInfoRequest struct {
		Addresses []string `form:"ionConnectAddress" required:"true" swaggerignore:"true"`
	}
	TokenInfoRequestByType struct {
		PaginationRequest
		Type string `uri:"type" required:"true" swaggerignore:"true"`
	}
	TokenInfoRequestByTypeAndSessionID struct {
		TokenInfoRequestByType
		SessionID string `uri:"viewingSessionId" required:"true" swaggerignore:"true"`
	}
	SessionViewCreateRequest struct {
		Type string `uri:"type" required:"true" swaggerignore:"true"`
	}
	SessionViewCreateResponse struct {
		ID        string `json:"id" example:"session_12345"`
		TTLmillis uint64 `json:"ttl" example:"3600000"`
	}
	TradeRequest struct {
		Address string `uri:"type" required:"true" swaggerignore:"true"` // Map `type` to `address`.
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
	tokens, err := s.tokenAnalytics.GetCommunityTokens(ctx, req.Data.Addresses, "")
	if err != nil {
		return nil, server.Unexpected(fmt.Errorf("failed to get community tokens: %w", err))
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
func (s *service) GetCommunityTokensByType(ctx context.Context, req *server.Request[TokenInfoRequestByType]) (*server.Response[[]ta.CommunityToken], error) {
	var resp []ta.CommunityToken
	for range 1 + rand.IntN(3) {
		var e ta.CommunityToken

		if err := faker.FakeData(&e); err != nil {
			return nil, fmt.Errorf("failed to fake data: %w", err)
		}
		resp = append(resp, e)
	}

	return server.OK(&resp), nil
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
	resp := SessionViewCreateResponse{
		ID:        fmt.Sprintf("session_%08d", rand.Int64()),
		TTLmillis: 3600000,
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
//	@Param			viewingSessionId	path		string	true	"Viewing session ID"		example("session_12345")
//	@Param			keyword				query		string	false	"Search keyword"			example("bitcoin")
//	@Param			limit				query		uint32	false	"Number of items to return"	example(10)
//	@Param			offset				query		uint32	false	"Number of items to skip"	example(0)
//	@Param			Authorization		header		string	true	"Auth token"
//	@Success		200					{array}		ta.CommunityToken
//	@Failure		500					{object}	server.ResponseErrorBody
//	@Failure		504					{object}	server.ResponseErrorBody	"if request times out"
//	@Router			/v1/community-tokens/{type}/viewing-sessions/{viewingSessionId} [GET].
func (s *service) GetCommunityTokensSessionByID(ctx context.Context, req *server.Request[TokenInfoRequestByTypeAndSessionID]) (*server.Response[[]ta.CommunityToken], error) {
	var resp []ta.CommunityToken
	for range 1 + rand.IntN(3) {
		var e ta.CommunityToken

		if err := faker.FakeData(&e); err != nil {
			return nil, fmt.Errorf("failed to fake data: %w", err)
		}
		resp = append(resp, e)
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
func (s *service) GetCommunityTokensTradesByAddress(ctx context.Context, req *server.Request[TradeRequest]) (*server.Response[[]ta.Trade], error) {
	var resp []ta.Trade
	for range 1 + rand.IntN(3) {
		var e ta.Trade

		if err := faker.FakeData(&e); err != nil {
			return nil, fmt.Errorf("failed to fake data: %w", err)
		}
		resp = append(resp, e)
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
	return newFakeStreamOf[ta.CommunityToken]()
}

// StreamCommunityTokensByType godoc
//
//	@Schemes
//	@Description	Streams community tokens information for the given type.
//	@Tags			sse
//	@Produce		text/event-stream
//	@Param			type			path		string	true	"Type of data"	example("latest")
//	@Param			Authorization	header		string	true	"Auth token"
//	@Success		200				{object}	ta.CommunityToken
//	@Failure		500				{object}	server.ResponseErrorBody
//	@Failure		504				{object}	server.ResponseErrorBody	"if request times out"
//	@Router			/v1sse/community-tokens/{type} [GET].
func (s *service) StreamCommunityTokensByType(ctx context.Context, req *server.Request[TokenInfoRequestByType]) (server.StreamEventEmitter[ta.CommunityToken], error) {
	return newFakeStreamOf[ta.CommunityToken]()
}

// StreamCommunityTokensTopHolders godoc
//
//	@Schemes
//	@Description	Streams top holders information for a specific community token address.
//	@Tags			sse
//	@Produce		text/event-stream
//	@Param			ionConnectAddress	path		string	true	"Ion Connect address"		example("0x1234...")
//	@Param			limit				query		uint32	false	"Number of items to return"	example(10)
//	@Param			offset				query		uint32	false	"Number of items to skip"	example(0)
//	@Param			Authorization		header		string	true	"Auth token"
//	@Success		200					{object}	ta.Trade
//	@Failure		500					{object}	server.ResponseErrorBody
//	@Failure		504					{object}	server.ResponseErrorBody	"if request times out"
//	@Router			/v1sse/community-tokens/{ionConnectAddress}/top-holders [GET].
func (s *service) StreamCommunityTokensTopHolders(ctx context.Context, req *server.Request[TradeRequest]) (server.StreamEventEmitter[ta.Trade], error) {
	return newFakeStreamOf[ta.Trade]()
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
	return newFakeStreamOf[ta.Trade]()
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
		ticker := time.NewTicker(5 * time.Second) // TODO: cfg?
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
		ticker := time.NewTicker(5 * time.Second) // TODO: cfg?
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
