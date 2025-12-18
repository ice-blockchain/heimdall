// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/ice-blockchain/heimdall/server"
)

func (s *service) setupCommunityTokenRoutes(router gin.IRoutes) {
	router.POST("/v1/community-tokens/adaptors", server.RootHandler(s.CreateCommunityTokenAdaptor))
}

// CreateCommunityTokenAdaptor godoc
//
//	@Schemes
//	@Description	Creates a kind 31175 Nostr event for a X.com community token and publishes it to the relay.
//	@Tags			CommunityTokens
//	@Accept			json
//	@Produce		json
//	@Param			X-API-Key	header		string													true	"API Key for authentication"
//	@Param			request		body		CommunityTokenAdaptorRequest							true	"Request body"
//	@Success		201			{object}	server.Response[accounts.CommunityTokenAdaptorResponse]	"Created - returns the address (a tag) of the 31175 event"
//	@Failure		400			{object}	server.ErrorResponse									"Bad request"
//	@Failure		401			{object}	server.ErrorResponse									"Unauthorized"
//	@Failure		500			{object}	server.ErrorResponse									"Internal server error"
//	@Router			/v1/community-tokens/adaptors [POST]
func (s *service) CreateCommunityTokenAdaptor(
	ctx context.Context,
	req *server.Request[CommunityTokenAdaptorRequest, accounts.CommunityTokenAdaptorResponse],
) (*server.Response[accounts.CommunityTokenAdaptorResponse], *server.ErrResponse[*server.ErrorResponse]) {
	if req.Data.APIKey == "" {
		return nil, server.Unauthorized(errors.New("missing API key"))
	}
	if req.Data.APIKey != s.cfg.CommunityTokenAPIKey {
		return nil, server.Unauthorized(errors.New("invalid API key"))
	}
	resp, err := s.accounts.CreateCommunityTokenAdaptor(ctx, req.Data.Platform, req.Data.PostID)
	if err != nil {
		return nil, server.Unexpected(errors.Wrap(err, "failed to create community token adaptor"))
	}

	return &server.Response[accounts.CommunityTokenAdaptorResponse]{
		Data: resp,
		Code: 201,
	}, nil
}
