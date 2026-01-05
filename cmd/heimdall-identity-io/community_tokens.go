// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"math/rand"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts"
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
	profile, err := s.accounts.GetSocialProfile(ctx, req.Data.UserIDOrMasterKey)
	if err != nil {
		return nil, server.NotFound(errors.Wrapf(err, "user %s not found", req.Data.UserIDOrMasterKey), "USER_NOT_FOUND")
	}
	avatarURL := ""
	if profile.Avatar != nil {
		avatarURL = *profile.Avatar
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomComments := rng.Intn(1000)
	randomReposts := rng.Intn(5000)
	randomLikes := rng.Intn(50000)
	randomTime := time.Now().UTC()

	postTypes := []string{"post", "video", "article"}
	randomType := postTypes[rng.Intn(len(postTypes))]

	contentVariations := []string{
		"Check out this amazing view! 🌅 #online+",
		"Just finished an incredible workout session 💪 https://example.com/video1.mp4 #online+",
		"Beautiful day at the beach https://example.com/beach.webp #online+ #summer",
		"New project launch! So excited to share this with everyone https://example.com/project.webp #online+",
		"Coffee and coding ☕️ https://example.com/coding.webp https://example.com/timelapse.mp4 #online+ #developer",
	}
	randomContent := contentVariations[rng.Intn(len(contentVariations))]
	var media []CommunityPostMedia
	numMedia := rng.Intn(4)
	for i := 0; i < numMedia; i++ {
		mediaType := "image"
		var thumbnail *string
		if rng.Float32() > 0.5 {
			mediaType = "video"
			thumbURL := "https://example.com/thumbnail" + string(rune('A'+i)) + ".webp"
			thumbnail = &thumbURL
		}
		media = append(media, CommunityPostMedia{
			URL:       "https://example.com/media" + string(rune('A'+i)) + ".webp",
			Thumbnail: thumbnail,
			Type:      mediaType,
		})
	}

	resp := &CommunityPostPreviewResponse{
		Author: CommunityPostAuthor{
			Name:        profile.Username,
			DisplayName: profile.DisplayName,
			Avatar:      avatarURL,
			Verified:    rng.Float32() > 0.5,
		},
		Type:               randomType,
		Media:              media,
		Comments:           randomComments,
		Reposts:            randomReposts,
		Likes:              randomLikes,
		CreatedAt:          &randomTime,
		Content:            randomContent,
		OnlinePlusDeeplink: "online.app://some/path/to/" + req.Data.EventAddress,
	}

	return &server.Response[CommunityPostPreviewResponse]{
		Data: resp,
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
