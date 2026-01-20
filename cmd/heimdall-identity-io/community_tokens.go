// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts"
	relaymanagement "github.com/ice-blockchain/heimdall/relay-management"
	"github.com/ice-blockchain/heimdall/server"
)

var (
	supportedPlatforms = map[string]bool{
		accounts.PlatformXCom: true,
	}
)

func (s *service) setupCommunityTokenRoutes(router gin.IRoutes) {
	router.POST("/v1/community-tokens/adaptors", server.RootHandler(s.CreateCommunityTokenAdaptor))
	router.GET("/v1/users/:userIdOrMasterKey/ion-connect-post-previews/:eventAddress", server.RootHandler(s.GetIonConnectPostPreview))
	router.PUT("/v1/onlineplus-deeplinks/:eventAddress", server.RootHandler(s.UpdateOnlinePlusDeeplink))
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
	if req.Data.Platform == "" {
		return nil, server.BadRequest(errors.New("platform is required"), "INVALID_PROPERTIES")
	}
	if !supportedPlatforms[strings.ToLower(req.Data.Platform)] {
		return nil, server.BadRequest(errors.Errorf("unsupported platform: %s (supported: x.com)", req.Data.Platform), "UNSUPPORTED_PLATFORM")
	}
	if req.Data.PostID == "" {
		return nil, server.BadRequest(errors.New("postId is required"), "INVALID_PROPERTIES")
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

// GetIonConnectPostPreview godoc
//
//	@Schemes
//	@Description	Returns the preview of an Ion Connect post (online+)
//	@Tags			CommunityTokens
//	@Produce		json
//	@Param			userIdOrMasterKey	path		string											true	"User ID or Master Key"
//	@Param			eventAddress		path		string											true	"Event Address (Ion Connect post address)"
//	@Success		200					{object}	server.Response[CommunityPostPreviewResponse]	"OK"
//	@Failure		400					{object}	server.ErrorResponse							"Bad request"
//	@Failure		404					{object}	server.ErrorResponse							"User or event not found"
//	@Failure		500					{object}	server.ErrorResponse							"Internal server error"
//	@Router			/v1/users/{userIdOrMasterKey}/ion-connect-post-previews/{eventAddress} [GET]
func (s *service) GetIonConnectPostPreview(
	ctx context.Context,
	req *server.Request[CommunityPostPreviewRequest, CommunityPostPreviewResponse],
) (*server.Response[CommunityPostPreviewResponse], *server.ErrResponse[*server.ErrorResponse]) {
	relays, err := s.accounts.GetIONConnectRelaysForUsers(ctx, []string{req.Data.UserIDOrMasterKey})
	if err != nil || len(relays) == 0 {
		return nil, server.NotFound(errors.Wrapf(err, "user %s not found", req.Data.UserIDOrMasterKey), "USER_NOT_FOUND")
	}
	var requestingFromRelay string
	for _, relay := range relays[0].IONConnectRelays {
		if relay.Type == "write" {
			requestingFromRelay = relay.URL
			break
		}
	}
	deeplink, err := s.accounts.GetDeeplink(ctx, req.Data.EventAddress)
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrNotFound):
			return nil, server.NotFound(errors.Wrapf(err, "deeplink for event %v not found", req.Data.EventAddress), "DEEPLINK_NOT_FOUND")
		default:
			return nil, server.Unexpected(errors.Wrapf(err, "failed to get deeplink for event %v", req.Data.EventAddress))
		}
	}
	preview, err := s.ionConnectClient.GetPost(ctx, requestingFromRelay, req.Data.EventAddress)
	if err != nil {
		switch {
		case errors.Is(err, relaymanagement.ErrNotFound):
			return nil, server.NotFound(errors.Wrapf(err, "event %v not found", req.Data.EventAddress), "EVENT_NOT_FOUND")
		default:
			return nil, server.Unexpected(errors.Wrapf(err, "failed to get ion connect post %v preview", req.Data.EventAddress))
		}

	}
	res := &CommunityPostPreviewResponse{
		OnlinePlusDeeplink: deeplink,
		PostPreview:        preview,
	}
	return &server.Response[CommunityPostPreviewResponse]{
		Data: res,
		Code: 200,
	}, nil
}

// UpdateOnlinePlusDeeplink godoc
//
//	@Schemes
//	@Description	Updates the deeplink for an online+ event
//	@Tags			CommunityTokens
//	@Accept			json
//	@Produce		json
//	@Param			Authorization	header		string					true	"Authorization token"
//	@Param			eventAddress	path		string					true	"Event Address (e/a tag)"
//	@Param			request			body		UpdateDeeplinkRequest	true	"Request body"
//	@Success		200				{object}	server.Response[any]	"OK"
//	@Failure		400				{object}	server.ErrorResponse	"Bad request"
//	@Failure		401				{object}	server.ErrorResponse	"Unauthorized"
//	@Failure		500				{object}	server.ErrorResponse	"Internal server error"
//	@Router			/v1/onlineplus-deeplinks/{eventAddress} [PUT]
func (s *service) UpdateOnlinePlusDeeplink(
	ctx context.Context,
	req *server.Request[UpdateDeeplinkRequest, any],
) (*server.Response[any], *server.ErrResponse[*server.ErrorResponse]) {
	if err := s.accounts.UpsertDeeplink(ctx, req.Data.EventAddress, req.Data.Deeplink); err != nil {
		return nil, server.Unexpected(errors.Wrap(err, "failed to upsert deeplink"))
	}

	return &server.Response[any]{
		Data: nil,
		Code: 200,
	}, nil
}
