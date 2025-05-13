// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nbd-wtf/go-nostr"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/server"
	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/subzero/validation"
)

func (s *service) setupStatisticsRoutes(router gin.IRoutes) {
	router.POST("/v1/statistics/hashtags", server.RootHandler(s.ProcessHashtagsEvents))
	router.GET("/v1/statistics/hashtags", server.RootHandler(s.GetTopHashtags))
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

func validateEvent(ctx context.Context, event *model.Event) error {
	if event.Kind != nostr.KindTextNote && event.Kind != model.CustomIONKindEditableTextNote && event.Kind != nostr.KindArticle {
		return errors.Errorf("invalid event kind: %d", event.Kind)
	}
	if err := validation.Validate(ctx, event); err != nil {
		return errors.Wrap(err, "invalid event")
	}

	return nil
}
