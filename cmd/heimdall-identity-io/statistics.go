// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nbd-wtf/go-nostr"
	"github.com/pkg/errors"

	nftcontent "github.com/ice-blockchain/heimdall/nft-content"
	"github.com/ice-blockchain/heimdall/server"
	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/subzero/validation"
)

func (s *service) setupStatisticsRoutes(router gin.IRoutes) {
	router.POST("/v1/statistics/hashtags", server.RootHandler(s.ProcessHashtagsEvents))
	router.GET("/v1/statistics/hashtags", server.RootHandler(s.GetTopHashtags))
	router.POST("/v1/statistics/nft-content", server.RootHandler(s.ProcessNFTContent))
}

// ProcessHashtagsEvents godoc
//
//	@Schemes
//	@Description	Process hashtags from events
//	@Tags			Statistics
//	@Accept			json
//	@Produce		json
//	@Param			request	body	HashtagsEventsReq	true	"Events with hashtags"
//	@Success		202
//	@Failure		400	{object}	server.ErrorResponse	"if invalid events provided"
//	@Failure		500	{object}	server.ErrorResponse
//	@Failure		504	{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/statistics/hashtags [POST].
func (s *service) ProcessHashtagsEvents(
	ctx context.Context,
	req *server.Request[HashtagsEventsReq, any],
) (successResp *server.Response[any], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	for _, event := range req.Data.Events {
		if err := validateEvent(ctx, event); err != nil {
			return nil, server.UnprocessableEntity(err, invalidPropertiesErrorCode)
		}
	}
	if err := s.hashtagStatistics.Process(ctx, req.Data.Events); err != nil {
		return nil, server.Unexpected(errors.Wrap(err, "failed to process hashtag events"))
	}

	return &server.Response[any]{Code: http.StatusAccepted}, nil
}

// GetTopHashtags godoc
//
//	@Schemes
//	@Description	Returns top hashtags
//	@Tags			Statistics
//	@Produce		json
//	@Param			limit			query		int		false	"Limit for the number of hashtags to return (default: 10)"
//	@Param			keyword			query		string	false	"Filter hashtags starting with this keyword"
//	@Param			Authorization	header		string	true	"Auth token"	default(Bearer <Add token here>)
//	@Success		200				{array}		string
//	@Failure		500				{object}	server.ErrorResponse
//	@Failure		504				{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/statistics/hashtags [GET].
func (s *service) GetTopHashtags(
	ctx context.Context,
	req *server.Request[GetTopHashtagsReq, []string],
) (successResp *server.Response[[]string], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	limit := 10
	if req.Data.Limit != 0 {
		limit = req.Data.Limit
	}
	var hashtags []string
	var err error
	if req.Data.Keyword != "" {
		hashtags, err = s.hashtagStatistics.GetTopHashtagsByKeyword(ctx, req.Data.Keyword, limit)
	} else {
		hashtags, err = s.hashtagStatistics.GetTopHashtags(ctx, limit)
	}
	if err != nil {
		return nil, server.Unexpected(errors.Wrap(err, "failed to get top hashtags"))
	}

	return server.OK(&hashtags), nil
}

// ProcessNFTContent godoc
//
//	@Schemes
//	@Description	Process NFT content events
//	@Tags			Statistics
//	@Accept			json
//	@Produce		json
//	@Param			request	body	NFTContentEventsReq	true	"Events for NFT content (2-3 events: 10100, 0, and optional content)"
//	@Success		202
//	@Failure		400	{object}	server.ErrorResponse	"if invalid events provided"
//	@Failure		500	{object}	server.ErrorResponse
//	@Failure		504	{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/statistics/nft-content [POST].
func (s *service) ProcessNFTContent(
	ctx context.Context,
	req *server.Request[NFTContentEventsReq, any],
) (successResp *server.Response[any], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	if err := validateNFTContentEvents(ctx, req.Data.Events); err != nil {
		return nil, server.UnprocessableEntity(err, invalidPropertiesErrorCode)
	}
	if err := s.nftContent.Process(ctx, req.Data.Events); err != nil {
		if errors.Is(err, nftcontent.ErrForbiddenContent) || errors.Is(err, nftcontent.ErrOnBehalfAccessDenied) {
			return nil, server.BadRequest(err, invalidPropertiesErrorCode)
		}

		return nil, server.Unexpected(errors.Wrap(err, "failed to process NFT content events"))
	}

	return &server.Response[any]{Code: http.StatusAccepted}, nil
}

func validateEvent(ctx context.Context, event *model.Event) error {
	if event.Kind != nostr.KindTextNote && event.Kind != model.CustomIONKindEditableTextNote && event.Kind != nostr.KindArticle {
		return errors.Errorf("invalid event kind: %d", event.Kind)
	}
	if err := validation.Validate(ctx, event); err != nil {
		return errors.Wrap(err, "invalid event")
	}

	return nil
}

func validateNFTContentEvents(ctx context.Context, events []*model.Event) error {
	if len(events) != 2 && len(events) != 3 {
		return errors.Errorf("2 or 3 events required, got %d", len(events))
	}
	allowedKinds := map[int]bool{
		nostr.KindProfileMetadata:           true,
		nostr.KindTextNote:                  true,
		model.CustomIONKindAttestation:      true,
		nostr.KindArticle:                   true,
		model.CustomIONKindEditableTextNote: true,
	}
	var eventProfileMetadata, eventAttestation, contentEvent *model.Event
	for _, event := range events {
		if !allowedKinds[event.Kind] {
			return errors.Errorf("invalid event kind: %d, allowed kinds: 0, 1, 10100, 30023, 30175", event.Kind)
		}
		switch event.Kind {
		case model.CustomIONKindAttestation:
			if eventAttestation != nil {
				return errors.Errorf("only one attestation event allowed")
			}
			eventAttestation = event
		case nostr.KindProfileMetadata:
			if eventProfileMetadata != nil {
				return errors.Errorf("only one profile metadata event allowed")
			}
			eventProfileMetadata = event
		case nostr.KindTextNote, model.CustomIONKindEditableTextNote, nostr.KindArticle:
			if contentEvent != nil {
				return errors.Errorf("only one content event allowed")
			}
			if event.IsCommunityPost() {
				return errors.Errorf("community posts are not allowed")
			} else if event.IsComment() {
				return errors.Errorf("comments are not allowed")
			} else if event.IsStory() {
				return errors.Errorf("stories are not allowed")
			}
			contentEvent = event
		}
	}
	if eventAttestation == nil {
		return errors.Errorf("one attestation event is required")
	}
	if eventProfileMetadata == nil {
		return errors.Errorf("one profile metadata event is required")
	}
	if err := validation.Validate(ctx, events...); err != nil {
		return errors.Wrap(err, "invalid events")
	}

	return nil
}
