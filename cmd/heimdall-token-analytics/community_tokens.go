// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"fmt"
	"math/rand/v2"

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
		PaginationRequest
		Address string `uri:"type" required:"true" swaggerignore:"true"` // Map `type` to `address`.
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
func (s *service) GetCommunityTokens(ctx context.Context, req *server.Request[TokenInfoRequest]) (*server.Response[[]ta.CommunityToken], error) {
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
