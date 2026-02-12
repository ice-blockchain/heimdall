// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"math/big"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/cockroachdb/errors"

	"github.com/ice-blockchain/heimdall/cmd/heimdall-token-analytics/server"
	ta "github.com/ice-blockchain/heimdall/token-analytics"
)

type (
	PaginationRequest struct {
		Limit  uint64 `form:"limit"  swaggerignore:"true"`
		Offset uint64 `form:"offset" swaggerignore:"true"`
	}
	TokenInfoRequest struct {
		ExternalAddresses         []string `form:"externalAddresses" swaggerignore:"true"`
		IncludeTopPlatformHolders *uint32  `form:"includeTopPlatformHolders" swaggerignore:"true"`
		Keyword                   string   `form:"keyword" swaggerignore:"true"`
		Holder                    string   `form:"holder" swaggerignore:"true"`
		PaginationRequest
	}
	LatestTokensRequest struct {
		server.NoAuthRequired
		Type          *string `form:"type" binding:"omitempty,oneof=profile post video article anyPost xcom" swaggerignore:"true"`
		ViewType      string  `uri:"externalAddressOrViewType" swaggerignore:"true"`
		Keyword       string  `form:"keyword" swaggerignore:"true"`
		ReferenceDate *string `form:"referenceDate" swaggerignore:"true"`
		PaginationRequest
	}
	ViewingSessionTokensRequest struct {
		ViewType         string `uri:"externalAddressOrViewType" swaggerignore:"true"`
		ViewingSessionID string `uri:"viewingSessionId" required:"true" swaggerignore:"true"`
		Keyword          string `form:"keyword" swaggerignore:"true"`
		PaginationRequest
	}
	TokenInfoStreamTypeAndSessionQuery struct {
		ViewType         string  `uri:"externalAddressOrViewType" swaggerignore:"true"`
		ViewingSessionID string  `form:"viewingSessionId" swaggerignore:"true"`
		Type             *string `form:"type" binding:"omitempty,oneof=profile post video article anyPost xcom" swaggerignore:"true"`
		PaginationRequest
	}
	CreateViewingSessionRequest struct {
		ViewType string  `uri:"externalAddressOrViewType" swaggerignore:"true"`
		Type     *string `form:"type" binding:"omitempty,oneof=profile post video article anyPost xcom" swaggerignore:"true"`
	}
	SessionViewCreateResponse struct {
		ID  string `json:"id" example:"550e8400-e29b-41d4-a716-446655440000"`
		TTL uint64 `json:"ttl" example:"1800" description:"Session TTL in seconds"` // Session TTL in seconds
	}
	TradeRequest struct {
		ExternalAddress string `uri:"externalAddressOrViewType" required:"true" swaggerignore:"true"`
		PaginationRequest
	}
	TopHoldersRequest struct {
		ExternalAddress string `uri:"externalAddressOrViewType" required:"true" swaggerignore:"true"`
		Limit           uint32 `form:"limit" swaggerignore:"true"`
	}
	ExternalDataRequest struct {
		ExternalAddress string `uri:"externalAddressOrViewType" required:"true" swaggerignore:"true"`
		ExternalDataRequestBody
	}
	ExternalDataRequestBody struct {
		UserExternalAddress  string `json:"userExternalAddress,omitempty" example:"1234567890"`
		UserUsername         string `json:"userUsername,omitempty" example:"johndoe"`
		UserDisplayName      string `json:"userDisplayName,omitempty" example:"John Doe"`
		UserAvatar           string `json:"userAvatar,omitempty" example:"https://example.com/avatar.png"`
		UserVerified         bool   `json:"userVerified,omitempty" example:"true"`
		UserBSCWalletAddress string `json:"userBSCWalletAddress,omitempty" example:"0x1234567890abcdef1234567890abcdef12345678"`

		PostAuthorExternalAddress string `json:"postAuthorExternalAddress,omitempty" example:"30023:431cbb22566b87c35ce6cffcca5593876cc64b9085d1355944c03d865540a95b:ionconnect.app"`
		PostAuthorUsername        string `json:"postAuthorUsername,omitempty" example:"johndoe"`
		PostAuthorDisplayName     string `json:"postAuthorDisplayName,omitempty" example:"John Doe"`
		PostAuthorAvatar          string `json:"postAuthorAvatar,omitempty" example:"https://example.com/avatar.png"`
		PostAuthorVerified        bool   `json:"postAuthorVerified,omitempty" example:"true"`
		TokenImageUrl             string `json:"tokenImageUrl,omitempty" example:"https://example.com/token.png"`
	}

	SuggestCreationDetailsRequest  = ta.CreationDetailsData
	SuggestCreationDetailsResponse = ta.SuggestedCreationDetails

	GetOHLCVRequest struct {
		PaginationRequest
		OHLCVRequest
	}
	OHLCVRequest struct {
		ExternalAddress string `uri:"externalAddressOrViewType" required:"true" swaggerignore:"true"`
		Interval        string `form:"interval" swaggerignore:"true"` // e.g., "1m", "5m", "1h", etc.
	}
	HolderPositionsRequest struct {
		ExternalAddress         string   `uri:"externalAddressOrViewType" required:"true" swaggerignore:"true"`
		ExternalHolderAddresses []string `form:"externalHolderAddresses" required:"true" swaggerignore:"true"`
	}
	BondingCurveProgressRequest struct {
		ExternalAddress string `uri:"externalAddressOrViewType" required:"true" swaggerignore:"true"`
	}
	BondingCurveProgressResponse = ta.BondingCurveProgress
	PricingRequest               struct {
		ExternalAddress string   `uri:"externalAddressOrViewType" required:"true" swaggerignore:"true"`
		Type            string   `form:"type" swaggerignore:"true" example:"buy"`
		Amount          *big.Int `form:"amount" swaggerignore:"true" example:"100000000"`
		AmountBNB       *big.Int `form:"amountBNB" swaggerignore:"true" example:"100000000"`
		AmountUSD       float64  `form:"amountUSD" swaggerignore:"true" example:"1.99"`
	}
	PriceResponse struct {
		FeeSponsorAddress string  `json:"feeSponsorAddress"`
		FeeSponsorId      string  `json:"feeSponsorId"`
		Amount            string  `json:"amount"`
		AmountBNB         string  `json:"amountBNB"`
		AmountUSD         float64 `json:"amountUSD"`
		IONPriceUSD       float64 `json:"usdPriceION"`
		BNBPriceUSD       float64 `json:"usdPriceBNB"`
		*ta.StartTokenParams
		CreatorTokenParams *ta.StartTokenParams `json:"creatorTokenParams,omitempty"`
	}
	TokenAnalyticsRequest struct {
		AnalyticsType string `uri:"analyticsType" swaggerignore:"true"`
		Interval      string `form:"interval" swaggerignore:"true"`
	}
	TokenAnalyticsResponse struct {
		Launched uint64  `json:"launched"`
		Migrated uint64  `json:"migrated"`
		Volume   float64 `json:"volume"`
	}
)

const (
	analyticsTypeGlobal = "global"

	analyticsInterval24h = "24h"
	analyticsInterval7d  = "7d"
	analyticsInterval30d = "30d"
)

// GetCommunityTokens godoc
//
//	@Schemes
//	@Description	Returns community tokens information for the given Ion Connect addresses.
//	@Tags			Tokens
//	@Produce		json
//	@Param			externalAddresses			query		[]string					false	"External addresses of the tokens"					collectionFormat(multi)
//	@Param			holder						query		string						false	"Holder external address to get tokens by holder"	example("0:holder123:")
//	@Param			includeTopPlatformHolders	query		int							false	"Number of top platform holders to include (1-10)"	minimum(1)	maximum(10)	example(3)
//	@Param			keyword						query		string						false	"Search keyword for filtering tokens"				example("bitcoin")
//	@Param			limit						query		uint32						false	"Number of items to return (requires keyword)"		example(10)
//	@Param			offset						query		uint32						false	"Number of items to skip (requires keyword)"		example(0)
//	@Success		200							{array}		ta.CommunityToken			"Returns tokens list with X_Total_Holdings header when holder parameter is used"
//	@Header			200							{integer}	X_Total_Holdings			"Total holdings amount for the specified holder (only present when holder parameter is provided)"
//	@Failure		400							{object}	server.ResponseErrorBody	"if request parameters are invalid"
//	@Failure		401							{object}	server.ResponseErrorBody	"if auth token is missing or invalid"
//	@Failure		500							{object}	server.ResponseErrorBody
//	@Failure		504							{object}	server.ResponseErrorBody	"if request times out"
//	@Security		Nostr
//	@Security		XCom
//	@Router			/v1/community-tokens [GET].
func (s *service) GetCommunityTokens(ctx context.Context, req *server.Request[TokenInfoRequest]) (*server.Response[[]*ta.CommunityToken], error) {
	if req.Data.Holder != "" {
		tokens, totalHoldings, err := s.tokenAnalytics.GetCommunityTokensByHolder(ctx, req.Data.Holder, req.Token.GetMasterPublicKey(), req.Data.Limit, req.Data.Offset)
		if err != nil {
			return nil, fmt.Errorf("failed to get community tokens by holder: %w", err)
		}
		resp := server.OK(&tokens)
		if resp.Headers == nil {
			resp.Headers = make(map[string]string)
		}
		resp.Headers["X_Total_Holdings"] = strconv.FormatUint(totalHoldings, 10)

		return resp, nil
	}

	if req.Data.Keyword == "" && len(req.Data.ExternalAddresses) == 0 {
		return nil, server.BadRequest(errors.New("externalAddresses[] is required when keyword is not provided"), invalidPropertiesErrorCode)
	}
	if req.Data.IncludeTopPlatformHolders != nil {
		if *req.Data.IncludeTopPlatformHolders < 1 || *req.Data.IncludeTopPlatformHolders > 10 {
			return nil, server.BadRequest(errors.New("includeTopPlatformHolders must be between 1 and 10"), invalidPropertiesErrorCode)
		}
	}
	if req.Data.Keyword == "" && (req.Data.Limit > 0 || req.Data.Offset > 0) {
		return nil, server.BadRequest(errors.New("limit and offset can only be used with keyword parameter"), invalidPropertiesErrorCode)
	}

	tokens, err := s.tokenAnalytics.GetCommunityTokensByExternalAddresses(ctx, req.Data.ExternalAddresses, req.Token.GetMasterPublicKey(), req.Data.IncludeTopPlatformHolders, req.Data.Keyword, req.Data.Limit, req.Data.Offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get community tokens: %w", err)
	}

	return server.OK(&tokens), nil
}

// GetCommunityTokensByType godoc
//
//	@Schemes
//	@Description	Returns community tokens by view type. "latest" requires authentication; "rewardsDistribution" is public and requires referenceDate.
//	@Tags			Tokens
//	@Produce		json
//	@Param			externalAddressOrViewType	path		string	true	"View type"											Enums(latest, rewardsDistribution)				example("latest")
//	@Param			type						query		string	false	"Token type filter"									Enums(profile,post,video,article,anyPost,xcom)	example("profile")
//	@Param			keyword						query		string	false	"Search keyword"									example("bitcoin")
//	@Param			referenceDate				query		string	false	"Reference date (required for rewardsDistribution)"	example("2025-01-03T16:00:00Z")
//	@Param			limit						query		uint32	false	"Number of items to return"							example(10)
//	@Param			offset						query		uint32	false	"Number of items to skip"							example(0)
//	@Success		200							{array}		ta.CommunityToken
//	@Failure		400							{object}	server.ResponseErrorBody	"if required params are missing"
//	@Failure		403							{object}	server.ResponseErrorBody	"if auth is required but missing (latest)"
//	@Failure		500							{object}	server.ResponseErrorBody
//	@Failure		504							{object}	server.ResponseErrorBody	"if request times out"
//	@Security		Nostr
//	@Security		XCom
//	@Router			/v1/community-tokens/{externalAddressOrViewType} [GET].
func (s *service) GetCommunityTokensByType(ctx context.Context, req *server.Request[LatestTokensRequest]) (*server.Response[[]*ta.CommunityToken], error) {
	if req.Data.ViewType == "" {
		return nil, server.BadRequest(fmt.Errorf("viewType is required"), invalidPropertiesErrorCode)
	}
	limit := req.Data.Limit
	if limit == 0 {
		limit = 10
	}

	switch req.Data.ViewType {
	case ta.TokenTypeLatest:
		if _, authErr := server.RequireAuth(req.Context); authErr != nil {
			return nil, authErr
		}
		tokens, err := s.tokenAnalytics.GetCommunityTokensByType(ctx, req.Data.ViewType, req.Data.Type, req.Data.Keyword, limit, req.Data.Offset)
		if err != nil {
			return nil, fmt.Errorf("failed to get community tokens by type: %w", err)
		}
		return server.OK(&tokens), nil

	case ta.TokenTypeRewardsDistribution:
		if req.Data.ReferenceDate == nil || *req.Data.ReferenceDate == "" {
			return nil, server.BadRequest(fmt.Errorf("referenceDate is required for rewardsDistribution"), invalidPropertiesErrorCode)
		}
		refDate, err := parseFlexibleDate(*req.Data.ReferenceDate)
		if err != nil {
			return nil, server.BadRequest(fmt.Errorf("invalid referenceDate: %w", err), invalidPropertiesErrorCode)
		}
		tokens, err := s.tokenAnalytics.GetCommunityTokensByRewardsDistribution(ctx, refDate, limit, req.Data.Offset)
		if err != nil {
			return nil, fmt.Errorf("failed to get community tokens by rewards distribution: %w", err)
		}
		return server.OK(&tokens), nil

	default:
		return nil, server.BadRequest(fmt.Errorf("invalid viewType '%s': supported values are '%s', '%s'", req.Data.ViewType, ta.TokenTypeLatest, ta.TokenTypeRewardsDistribution), invalidPropertiesErrorCode)
	}
}

func parseFlexibleDate(s string) (time.Time, error) {
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04",
		"2006-01-02 15:04",
		"2006-01-02",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}
	if ts, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(ts, 0), nil
	}
	if ts, err := strconv.ParseInt(s, 10, 64); err == nil && ts > 1e12 {
		return time.Unix(ts/1000, (ts%1000)*int64(time.Millisecond)), nil
	}

	return time.Time{}, fmt.Errorf("unable to parse date: %s", s)
}

// CreateCommunityTokensSessionView godoc
//
//	@Schemes
//	@Description	Creates a new session view for community tokens analytics.
//	@Tags			Tokens
//	@Produce		json
//	@Param			externalAddressOrViewType	path		string	true	"View type"			Enums(top,trending,bondingCurveProgress)		example("top")
//	@Param			type						query		string	false	"Token type filter"	Enums(profile,post,video,article,anyPost,xcom)	example("profile")
//	@Success		200							{object}	SessionViewCreateResponse
//	@Failure		401							{object}	server.ResponseErrorBody	"if auth token is missing or invalid"
//	@Failure		500							{object}	server.ResponseErrorBody
//	@Failure		504							{object}	server.ResponseErrorBody	"if request times out"
//	@Security		Nostr
//	@Security		XCom
//	@Router			/v1/community-tokens/{externalAddressOrViewType}/viewing-sessions [POST].
func (s *service) CreateCommunityTokensSessionView(ctx context.Context, req *server.Request[CreateViewingSessionRequest]) (*server.Response[SessionViewCreateResponse], error) {
	if req.Data.ViewType == "" {
		return nil, server.BadRequest(fmt.Errorf("viewType is required"), invalidPropertiesErrorCode)
	}
	validTypes := map[string]bool{
		ta.TokenTypeTop:                  true,
		ta.TokenTypeTrending:             true,
		ta.TokenTypeBondingCurveProgress: true,
	}
	if !validTypes[req.Data.ViewType] {
		return nil, server.BadRequest(fmt.Errorf("invalid viewType '%s': must be one of: %s, %s, %s", req.Data.ViewType, ta.TokenTypeTop, ta.TokenTypeTrending, ta.TokenTypeBondingCurveProgress), invalidPropertiesErrorCode)
	}
	clientIP := req.Context.ClientIP()
	deviceKey := req.Token.GetDevicePublicKey()
	sessionID, ttl, err := s.tokenAnalytics.CreateViewingSession(ctx, req.Data.ViewType, clientIP, deviceKey, req.Data.Type)
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
//	@Param			externalAddressOrViewType	path		string	true	"View type"					Enums(top,trending,bondingCurveProgress)	example("top")
//	@Param			viewingSessionId			path		string	true	"Viewing session ID"		example("550e8400-e29b-41d4-a716-446655440000")
//	@Param			keyword						query		string	false	"Search keyword"			example("bitcoin")
//	@Param			limit						query		uint32	false	"Number of items to return"	example(10)
//	@Param			offset						query		uint32	false	"Number of items to skip"	example(0)
//	@Success		200							{array}		ta.CommunityToken
//	@Failure		401							{object}	server.ResponseErrorBody	"if auth token is missing or invalid"
//	@Failure		500							{object}	server.ResponseErrorBody
//	@Failure		504							{object}	server.ResponseErrorBody	"if request times out"
//	@Security		Nostr
//	@Security		XCom
//	@Router			/v1/community-tokens/{externalAddressOrViewType}/viewing-sessions/{viewingSessionId} [GET].
func (s *service) GetCommunityTokensSessionByID(ctx context.Context, req *server.Request[ViewingSessionTokensRequest]) (*server.Response[[]*ta.CommunityToken], error) {
	if req.Data.ViewType == "" {
		return nil, server.BadRequest(fmt.Errorf("viewType is required"), invalidPropertiesErrorCode)
	}
	validTypes := map[string]bool{
		ta.TokenTypeTop:                  true,
		ta.TokenTypeTrending:             true,
		ta.TokenTypeBondingCurveProgress: true,
	}
	if !validTypes[req.Data.ViewType] {
		return nil, server.BadRequest(fmt.Errorf("invalid viewType '%s': must be one of: %s, %s, %s", req.Data.ViewType, ta.TokenTypeTop, ta.TokenTypeTrending, ta.TokenTypeBondingCurveProgress), invalidPropertiesErrorCode)
	}
	limit := req.Data.Limit
	if limit == 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}
	offset := req.Data.Offset
	resp, err := s.tokenAnalytics.GetTokensFromViewingSession(ctx, req.Data.ViewType, req.Data.ViewingSessionID, req.Data.Keyword, limit, offset)
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
//	@Param			externalAddressOrViewType	path		string	true	"External address"			example("0x1234...")
//	@Param			limit						query		uint32	false	"Number of items to return"	example(10)
//	@Param			offset						query		uint32	false	"Number of items to skip"	example(0)
//	@Success		200							{array}		ta.Trade
//	@Failure		401							{object}	server.ResponseErrorBody	"if auth token is missing or invalid"
//	@Failure		500							{object}	server.ResponseErrorBody
//	@Failure		504							{object}	server.ResponseErrorBody	"if request times out"
//	@Security		Nostr
//	@Security		XCom
//	@Router			/v1/community-tokens/{externalAddressOrViewType}/latest-trades [GET].
func (s *service) GetCommunityTokensTradesByAddress(ctx context.Context, req *server.Request[TradeRequest]) (*server.Response[[]*ta.Trade], error) {
	limit := req.Data.Limit
	if limit == 0 {
		limit = 50
	}
	resp, _, err := s.tokenAnalytics.GetLatestTrades(ctx, req.Data.ExternalAddress, limit, req.Data.Offset, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest trades: %w", err)
	}

	return server.OK(&resp), nil
}

// GetCommunityTokenHolderPositions godoc
//
//	@Schemes
//	@Description	Returns positions for specific holders of a community token.
//	@Tags			Tokens
//	@Produce		json
//	@Param			externalAddressOrViewType	path		string		true	"External address of the token"	example("0:9dbf3f196310fb4a1818f619a686b15e6ffa78d723e843973fcdc9125f15bc2f:")
//	@Param			externalHolderAddresses		query		[]string	true	"External addresses of holders"	example("0:abc123:,0:def456:")
//	@Success		200							{array}		ta.HolderPosition
//	@Failure		400							{object}	server.ResponseErrorBody	"if request parameters are invalid"
//	@Failure		401							{object}	server.ResponseErrorBody	"if auth token is missing or invalid"
//	@Failure		500							{object}	server.ResponseErrorBody
//	@Failure		504							{object}	server.ResponseErrorBody	"if request times out"
//	@Security		Nostr
//	@Security		XCom
//	@Router			/v1/community-tokens/{externalAddressOrViewType}/positions [GET].
func (s *service) GetCommunityTokenHolderPositions(ctx context.Context, req *server.Request[HolderPositionsRequest]) (*server.Response[[]*ta.HolderPosition], error) {
	if len(req.Data.ExternalHolderAddresses) == 0 {
		return nil, server.BadRequest(errors.New("externalHolderAddresses is required"), invalidPropertiesErrorCode)
	}

	positions, err := s.tokenAnalytics.GetHolderPositions(ctx, req.Data.ExternalAddress, req.Data.ExternalHolderAddresses)
	if err != nil {
		return nil, fmt.Errorf("failed to get holder positions: %w", err)
	}

	return server.OK(&positions), nil
}

// GetCommunityTokenBondingCurveProgress godoc
//
//	@Schemes
//	@Description	Returns progress of bonding curve for the community token
//	@Tags			Tokens
//	@Produce		json
//	@Param			externalAddressOrViewType	path		string	true	"External address of the token"	example("0:9dbf3f196310fb4a1818f619a686b15e6ffa78d723e843973fcdc9125f15bc2f:")
//	@Success		200							{object}	ta.BondingCurveProgress
//	@Failure		400							{object}	server.ResponseErrorBody	"if request parameters are invalid"
//	@Failure		401							{object}	server.ResponseErrorBody	"if auth token is missing or invalid"
//	@Failure		500							{object}	server.ResponseErrorBody
//	@Failure		504							{object}	server.ResponseErrorBody	"if request times out"
//	@Security		Nostr
//	@Security		XCom
//	@Router			/v1/community-tokens/{externalAddressOrViewType}/bondingCurveProgress [GET].
func (s *service) GetCommunityTokenBondingCurveProgress(ctx context.Context, req *server.Request[BondingCurveProgressRequest]) (*server.Response[*BondingCurveProgressResponse], error) {
	progress, err := s.tokenAnalytics.GetBondingCurveProgress(ctx, req.Data.ExternalAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get bonding curve progress for token %v: %w", req.Data.ExternalAddress, err)
	}

	return server.OK(&progress), nil
}

// GetCommunityTokenPricing godoc
//
//	@Schemes
//	@Description	Returns pricing for the community token (per 1 = 1e18wei base)
//	@Tags			Tokens
//	@Produce		json
//	@Param			externalAddressOrViewType	path		string	true	"External address of the token"	example("0:9dbf3f196310fb4a1818f619a686b15e6ffa78d723e843973fcdc9125f15bc2f:")
//	@Param			type						query		string	true	"Buy or sell"					example("buy")
//	@Param			amount						query		int		false	"Amount of tokens to exchange (in wei)"
//	@Param			amountBNB					query		int		false	"Amount of BNB to exchange (in wei)"
//	@Param			amountUSD					query		float64	false	"Amount of USD to exchange (ex: 1.99)"
//	@Success		200							{object}	PriceResponse
//	@Failure		400							{object}	server.ResponseErrorBody	"if request parameters are invalid"
//	@Failure		401							{object}	server.ResponseErrorBody	"if auth token is missing or invalid"
//	@Failure		500							{object}	server.ResponseErrorBody
//	@Failure		504							{object}	server.ResponseErrorBody	"if request times out"
//	@Security		Nostr
//	@Security		XCom
//	@Router			/v1/community-tokens/{externalAddressOrViewType}/pricing [GET].
func (s *service) GetCommunityTokenPricing(ctx context.Context, req *server.Request[PricingRequest]) (*server.Response[PriceResponse], error) {
	tradeType := ta.TradeType(req.Data.Type)
	if tradeType != ta.TradeTypeBuy && tradeType != ta.TradeTypeSell {
		return nil, server.BadRequest(errors.Errorf("invalid type %v", tradeType), invalidPropertiesErrorCode)
	}
	if req.Data.Amount == nil && req.Data.AmountBNB == nil && req.Data.AmountUSD == 0 {
		return nil, server.BadRequest(errors.Errorf("one of amount/amountBNB/amountUSD required"), invalidPropertiesErrorCode)
	}
	if req.Data.Amount != nil && (req.Data.AmountBNB != nil || req.Data.AmountUSD != 0) {
		return nil, server.BadRequest(errors.Errorf("amount/amountBNB/amountUSD are mutually exclusive"), invalidPropertiesErrorCode)
	}
	if req.Data.AmountBNB != nil && (req.Data.Amount != nil || req.Data.AmountUSD != 0) {
		return nil, server.BadRequest(errors.Errorf("amount/amountBNB/amountUSD are mutually exclusive"), invalidPropertiesErrorCode)
	}
	if req.Data.AmountUSD != 0 && (req.Data.Amount != nil || req.Data.AmountBNB != nil) {
		return nil, server.BadRequest(errors.Errorf("amount/amountBNB/amountUSD are mutually exclusive"), invalidPropertiesErrorCode)
	}
	pricing, err := s.tokenAnalytics.GetTokenPricing(ctx, req.Data.ExternalAddress, tradeType, req.Data.Amount, req.Data.AmountBNB, req.Data.AmountUSD)
	if err != nil {
		return nil, fmt.Errorf("failed to get pricing for token %v: %w", req.Data.ExternalAddress, err)
	}
	r := &PriceResponse{
		FeeSponsorAddress:  pricing.FeeSponsorAddress,
		FeeSponsorId:       pricing.FeeSponsorId,
		Amount:             pricing.AmountInBase.String(),
		AmountBNB:          pricing.AmountInBNB.String(),
		AmountUSD:          pricing.AmountInUSD,
		IONPriceUSD:        pricing.IonPriceInUSD,
		BNBPriceUSD:        pricing.BNBPriceInUSD,
		CreatorTokenParams: pricing.CreatorTokenParams,
		StartTokenParams:   pricing.ContentTokenParams,
	}
	if r.StartTokenParams == nil {
		r.StartTokenParams = pricing.CreatorTokenParams
		r.CreatorTokenParams = nil
	}
	return server.OK(r), nil
}

// GetCommunityTokensOHLCV godoc
//
//	@Schemes
//	@Description	Get OHLCV (Open, High, Low, Close, Volume) data for a specific community token address (closed candles).
//	@Tags			Tokens
//	@Produce		json
//	@Param			externalAddressOrViewType	path		string	true	"External address"	example("0x1234...")
//	@Param			interval					query		string	true	"Time interval"		example("1m")
//	@Param			limit						query		string	true	"Limit"				example("10")
//	@Param			offset						query		string	true	"Offset"			example("0")
//	@Success		200							{array}		ta.OHLCV
//	@Failure		401							{object}	server.ResponseErrorBody	"if auth token is missing or invalid"
//	@Failure		500							{object}	server.ResponseErrorBody
//	@Failure		504							{object}	server.ResponseErrorBody	"if request times out"
//	@Security		Nostr
//	@Security		XCom
//	@Router			/v1/community-tokens/{externalAddressOrViewType}/ohlcv [GET].
func (s *service) GetCommunityTokensOHLCV(ctx context.Context, req *server.Request[GetOHLCVRequest]) (*server.Response[[]*ta.OHLCV], error) {
	interval := ta.Interval(req.Data.Interval)
	if err := interval.Validate(); err != nil {
		return nil, server.BadRequest(err, invalidPropertiesErrorCode)
	}
	now := time.Now().In(time.UTC)
	if req.Data.Limit == 0 {
		req.Data.Limit = uint64(interval.InitialBufferSize())
	}
	ohlcvs, err := s.tokenAnalytics.GetOHLVCHistory(ctx, now, req.Data.ExternalAddress, interval, req.Data.Limit, req.Data.Offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get OHLCV history for token %v: %w", req.Data.ExternalAddress, err)
	}
	return server.OK(&ohlcvs), nil
}

// SyncCommunityTokenExternalData godoc
//
//	@Schemes
//	@Description	Syncs external user and token information. At least one field must be provided. Requires authentication.
//	@Description	Special case: when externalAddressOrViewType is "twitterProfiles", updates the logged-in user's profile.
//	@Description	Otherwise, updates token information associated with the specified external address
//	@Tags			Tokens
//	@Accept			json
//	@Produce		json
//	@Param			externalAddressOrViewType	path	string				true	"Token external address or 'twitterProfiles' for logged-in user profile update"
//	@Param			body						body	ExternalDataRequest	true	"User and token information"
//	@Success		200							"OK - Data synced successfully"
//	@Failure		400							{object}	server.ResponseErrorBody	"if request body is invalid or all fields are empty"
//	@Failure		401							{object}	server.ResponseErrorBody	"if auth token is missing or invalid"
//	@Failure		409							{object}	server.ResponseErrorBody	"if duplicate data conflict occurs"
//	@Failure		500							{object}	server.ResponseErrorBody
//	@Failure		504							{object}	server.ResponseErrorBody	"if request times out"
//	@Security		Nostr
//	@Security		XCom
//	@Router			/v1/community-tokens/{externalAddressOrViewType}/external-data [PUT].
func (s *service) SyncCommunityTokenExternalData(ctx context.Context, req *server.Request[ExternalDataRequest]) (*server.Response[any], error) {
	if req.Data.ExternalAddress == "twitterProfiles" {
		hasUserData := req.Data.UserExternalAddress != "" || req.Data.UserUsername != "" ||
			req.Data.UserDisplayName != "" || req.Data.UserAvatar != "" || req.Data.UserBSCWalletAddress != ""
		if !hasUserData {
			return nil, server.BadRequest(errors.New("at least one user field must be provided"), invalidPropertiesErrorCode)
		}
		userExternalAddress := req.Data.UserExternalAddress
		if userExternalAddress == "" {
			userExternalAddress = req.Token.GetMasterPublicKey()
		}
		if err := s.tokenAnalytics.UpdateLoggedInUserProfile(
			ctx,
			req.Token.GetMasterPublicKey(),
			userExternalAddress,
			req.Data.UserUsername,
			req.Data.UserDisplayName,
			req.Data.UserAvatar,
			req.Data.UserVerified,
			req.Data.UserBSCWalletAddress,
		); err != nil {
			if errors.Is(err, ta.ErrDuplicate) {
				return nil, server.Conflict(err, "DATA_CONFLICT")
			}
			return nil, fmt.Errorf("failed to update user profile: %w", err)
		}
	} else {
		hasPostAuthorData := req.Data.PostAuthorExternalAddress != "" || req.Data.PostAuthorUsername != "" ||
			req.Data.PostAuthorDisplayName != "" || req.Data.PostAuthorAvatar != "" || req.Data.TokenImageUrl != ""
		if !hasPostAuthorData {
			return nil, server.BadRequest(errors.New("at least one post author or token field must be provided"), invalidPropertiesErrorCode)
		}

		if err := s.tokenAnalytics.UpdateTokenExternalData(
			ctx,
			req.Data.ExternalAddress,
			req.Data.PostAuthorExternalAddress,
			req.Data.PostAuthorUsername,
			req.Data.PostAuthorDisplayName,
			req.Data.PostAuthorAvatar,
			req.Data.PostAuthorVerified,
			req.Data.PostAuthorExternalAddress,
			req.Data.TokenImageUrl,
		); err != nil {
			if errors.Is(err, ta.ErrDuplicate) {
				return nil, server.Conflict(err, "DATA_CONFLICT")
			} else if errors.Is(err, ta.ErrTokenNotFound) {
				return nil, server.BadRequest(err, "TOKEN_NOT_FOUND")
			}
			return nil, fmt.Errorf("failed to update token external data: %w", err)
		}
	}

	return server.OK[any](), nil
}

// SuggestCreationDetails godoc
//
//	@Schemes
//	@Description	Suggests token creation details (ticker, name, picture) based on content and creator information
//	@Tags			Tokens
//	@Accept			json
//	@Produce		json
//	@Param			body	body		SuggestCreationDetailsRequest	true	"Content and creator information"
//	@Success		200		{object}	server.Response[SuggestCreationDetailsResponse]
//	@Success		202		{object}	server.Response[SuggestCreationDetailsResponse]
//	@Failure		400		{object}	server.ResponseErrorBody	"if request body is invalid"
//	@Failure		500		{object}	server.ResponseErrorBody
//	@Failure		504		{object}	server.ResponseErrorBody	"if request times out"
//	@Security		Nostr
//	@Security		XCom
//	@Router			/v1/community-tokens/suggest-creation-details [POST].
func (s *service) SuggestCreationDetails(ctx context.Context, req *server.Request[SuggestCreationDetailsRequest]) (*server.Response[SuggestCreationDetailsResponse], error) {
	const maxFrames = 30

	if strings.TrimSpace(req.Data.ContentID) == "" {
		return nil, server.BadRequest(errors.New("contentID is required"), invalidPropertiesErrorCode)
	}

	if current := len(req.Data.ContentImages) + len(req.Data.ContentVideoFrames); current > maxFrames {
		return nil, server.BadRequest(fmt.Errorf("total number of contentImages and contentVideoFrames cannot exceed %d (got %d)", maxFrames, current), invalidPropertiesErrorCode)
	}

	for _, img := range req.Data.ContentImages {
		err := ta.ValidateWebpImage(img)
		if err != nil {
			return nil, server.BadRequest(fmt.Errorf("invalid contentImages entry: %w", err), invalidPropertiesErrorCode)
		}
	}
	for _, frame := range req.Data.ContentVideoFrames {
		err := ta.ValidateWebpImage(frame)
		if err != nil {
			return nil, server.BadRequest(fmt.Errorf("invalid contentVideoFrames entry: %w", err), invalidPropertiesErrorCode)
		}
	}

	suggestion, err := s.tokenAnalytics.GenerateTokenSuggestion(ctx, req.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token suggestion: %w", err)
	}

	switch suggestion.Status {
	case ta.TokenDetailsGenerationStatusCompleted:
		return server.OK(suggestion), nil

	case ta.TokenDetailsGenerationStatusFailed:
		return nil, server.UnprocessableEntity(errors.New("generation failed"), "GENERATION_FAILED")
	}

	return server.Accepted(suggestion), nil
}

// StreamCommunityTokens godoc
//
//	@Schemes
//	@Description	Streams community tokens information for the given Ion Connect addresses.
//	@Tags			stream
//	@Produce		json
//	@Param			externalAddresses			query		[]string	true	"External addresses of the tokens"					example(0x1234...,0x5678...)
//	@Param			includeTopPlatformHolders	query		int			false	"Number of top platform holders to include (1-10)"	minimum(1)	maximum(10)	example(3)
//	@Success		200							{object}	ta.CommunityToken
//	@Failure		401							{object}	server.ResponseErrorBody	"if auth token is missing or invalid"
//	@Failure		500							{object}	server.ResponseErrorBody
//	@Failure		504							{object}	server.ResponseErrorBody	"if request times out"
//	@Security		Nostr
//	@Security		XCom
//	@Router			/v1sse/community-tokens [GET].
//	@Router			/v1ws/community-tokens [GET].
func (s *service) StreamCommunityTokens(ctx context.Context, req *server.Request[TokenInfoRequest]) (server.StreamEventEmitter[ta.CommunityToken], error) {
	if len(req.Data.ExternalAddresses) == 0 {
		return nil, server.BadRequest(errors.New("externalAddresses[] is required"), invalidPropertiesErrorCode)
	}
	if req.Data.IncludeTopPlatformHolders != nil {
		if *req.Data.IncludeTopPlatformHolders < 1 || *req.Data.IncludeTopPlatformHolders > 10 {
			return nil, server.BadRequest(errors.New("includeTopPlatformHolders must be between 1 and 10"), invalidPropertiesErrorCode)
		}
	}

	return func(ctx context.Context) (<-chan server.StreamEvent[ta.CommunityToken], error) {
		events := make(chan server.StreamEvent[ta.CommunityToken], 100)

		sendData := func() bool {
			tokens, err := s.tokenAnalytics.GetCommunityTokensByExternalAddresses(ctx, req.Data.ExternalAddresses, req.Token.GetMasterPublicKey(), req.Data.IncludeTopPlatformHolders, req.Data.Keyword, req.Data.Limit, req.Data.Offset)
			if err != nil {
				slog.ErrorContext(ctx, "failed to get community tokens for streaming", "error", err, "addresses", req.Data.ExternalAddresses)
				events <- server.StreamEvent[ta.CommunityToken]{
					Type: "error",
					Data: nil,
					Err:  err,
				}

				return false
			}
			for _, token := range tokens {
				events <- server.StreamEvent[ta.CommunityToken]{
					Type: "message",
					Data: token,
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
//	@Tags			stream
//	@Produce		json
//	@Param			externalAddressOrViewType	path		string	true	"View type (latest, featured, top, trending, or bondingCurveProgress)"	example("latest","featured","top","trending","bondingCurveProgress")
//	@Param			viewingSessionId			query		string	false	"Viewing session ID (required for top/trending/bondingCurveProgress)"	example("550e8400-e29b-41d4-a716-446655440000")
//	@Param			type						query		string	false	"Token type filter"														Enums(profile,post,video,article,anyPost,xcom)	example("profile")
//	@Success		200							{object}	ta.CommunityToken
//	@Failure		400							{object}	server.ResponseErrorBody
//	@Failure		401							{object}	server.ResponseErrorBody	"if auth token is missing or invalid"
//	@Failure		500							{object}	server.ResponseErrorBody
//	@Failure		504							{object}	server.ResponseErrorBody	"if request times out"
//	@Security		Nostr
//	@Security		XCom
//	@Router			/v1sse/community-tokens/{externalAddressOrViewType} [GET].
//	@Router			/v1ws/community-tokens/{externalAddressOrViewType} [GET].
func (s *service) StreamCommunityTokensByType(ctx context.Context, req *server.Request[TokenInfoStreamTypeAndSessionQuery]) (server.StreamEventEmitter[ta.CommunityToken], error) {
	if (req.Data.ViewType == ta.TokenTypeTop || req.Data.ViewType == ta.TokenTypeTrending || req.Data.ViewType == ta.TokenTypeBondingCurveProgress) && req.Data.ViewingSessionID == "" {
		return nil, server.BadRequest(errors.New("viewingSessionId is required for top, trending, and bondingCurveProgress types"), invalidPropertiesErrorCode)
	}
	limit := uint64(100)
	return func(ctx context.Context) (<-chan server.StreamEvent[ta.CommunityToken], error) {
		events := make(chan server.StreamEvent[ta.CommunityToken], limit)

		sendData := func() bool {
			var tokens []*ta.CommunityToken
			var err error
			if (req.Data.ViewType == ta.TokenTypeTop || req.Data.ViewType == ta.TokenTypeTrending || req.Data.ViewType == ta.TokenTypeBondingCurveProgress) && req.Data.ViewingSessionID != "" {
				tokens, err = s.tokenAnalytics.GetTokensFromViewingSession(ctx, req.Data.ViewType, req.Data.ViewingSessionID, "", limit, 0)
			} else {
				tokens, err = s.tokenAnalytics.GetCommunityTokensByType(ctx, req.Data.ViewType, req.Data.Type, "", limit, 0)
			}

			if err != nil {
				slog.ErrorContext(ctx, "failed to get community tokens for streaming", "error", err, "type", req.Data.Type, "sessionID", req.Data.ViewingSessionID)
				events <- server.StreamEvent[ta.CommunityToken]{
					Type: "error",
					Err:  err,
				}

				return false
			}

			for _, token := range tokens {
				events <- server.StreamEvent[ta.CommunityToken]{
					Type: "message",
					Data: token,
				}
			}

			slog.DebugContext(ctx, "sent community tokens update", "type", req.Data.Type, "sessionID", req.Data.ViewingSessionID, "count", len(tokens))

			return true
		}

		ticker := time.NewTicker(1 * time.Second)
		go func() {
			defer close(events)
			defer ticker.Stop()
			if !sendData() {
				slog.ErrorContext(ctx, "initial data send failed for community tokens stream", "type", req.Data.Type, "sessionID", req.Data.ViewingSessionID)
				return
			}

			for ctx.Err() == nil {
				select {
				case <-ctx.Done():
					slog.DebugContext(ctx, "community tokens stream context cancelled", "type", req.Data.Type, "sessionID", req.Data.ViewingSessionID)

					return

				case <-ticker.C:
					if !sendData() {
						slog.ErrorContext(ctx, "periodic data send failed for community tokens stream", "type", req.Data.Type, "sessionID", req.Data.ViewingSessionID)

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
//	@Tags			stream
//	@Produce		json
//	@Param			externalAddressOrViewType	path		string	true	"External address"			example("0x1234...")
//	@Param			limit						query		uint32	false	"Number of items to return"	example(10)
//	@Success		200							{object}	ta.TopHolderPosition
//	@Failure		401							{object}	server.ResponseErrorBody	"if auth token is missing or invalid"
//	@Failure		500							{object}	server.ResponseErrorBody
//	@Failure		504							{object}	server.ResponseErrorBody	"if request times out"
//	@Security		Nostr
//	@Security		XCom
//	@Router			/v1sse/community-tokens/{externalAddressOrViewType}/top-holders [GET].
//	@Router			/v1ws/community-tokens/{externalAddressOrViewType}/top-holders [GET].
func (s *service) StreamCommunityTokensTopHolders(ctx context.Context, req *server.Request[TopHoldersRequest]) (server.StreamEventEmitter[ta.TopHolderPosition], error) {
	ionConnectAddress := req.Data.ExternalAddress
	limit := req.Data.Limit
	if limit == 0 {
		limit = 10
	}
	if limit > 200 {
		limit = 200
	}

	return func(ctx context.Context) (<-chan server.StreamEvent[ta.TopHolderPosition], error) {
		ctx = context.WithValue(ctx, "token", req.Token)

		events := make(chan server.StreamEvent[ta.TopHolderPosition])
		go func() {
			defer close(events)

			holders, err := s.tokenAnalytics.GetTopHolders(ctx, ionConnectAddress, int64(limit))
			if err != nil {
				slog.ErrorContext(ctx, "failed to get initial top holders", "error", err)
				select {
				case <-ctx.Done():
					return
				case events <- server.StreamEvent[ta.TopHolderPosition]{
					Err:  fmt.Errorf("failed to get initial top holders: %w", err),
					Type: "error",
				}:
				}
				return
			}
			for _, holder := range holders {
				select {
				case <-ctx.Done():
					slog.DebugContext(ctx, "top holders stream cancelled during initial send")

					return
				case events <- server.StreamEvent[ta.TopHolderPosition]{Type: "message", Data: holder}:
				}
			}
			select {
			case <-ctx.Done():
				return
			case events <- server.StreamEvent[ta.TopHolderPosition]{Type: "eose", Data: nil}:
			}
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					slog.DebugContext(ctx, "top holders stream cancelled")

					return
				case <-ticker.C:
					holders, err := s.tokenAnalytics.GetTopHolders(ctx, ionConnectAddress, int64(limit))
					if err != nil {
						slog.ErrorContext(ctx, "failed to get top holders in ticker", "error", err)
						select {
						case <-ctx.Done():
							return
						case events <- server.StreamEvent[ta.TopHolderPosition]{
							Err:  err,
							Type: "error",
						}:
						}
						return
					}

					for _, holder := range holders {
						select {
						case <-ctx.Done():
							return
						case events <- server.StreamEvent[ta.TopHolderPosition]{Type: "message", Data: holder}:
						}
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
//	@Tags			stream
//	@Produce		json
//	@Param			externalAddressOrViewType	path		string	true	"External address"	example("0x1234...")
//	@Success		200							{object}	ta.Trade
//	@Failure		401							{object}	server.ResponseErrorBody	"if auth token is missing or invalid"
//	@Failure		500							{object}	server.ResponseErrorBody
//	@Failure		504							{object}	server.ResponseErrorBody	"if request times out"
//	@Security		Nostr
//	@Security		XCom
//	@Router			/v1sse/community-tokens/{externalAddressOrViewType}/latest-trades [GET].
//	@Router			/v1ws/community-tokens/{externalAddressOrViewType}/latest-trades [GET].
func (s *service) StreamCommunityTokensLatestTrades(ctx context.Context, req *server.Request[TradeRequest]) (server.StreamEventEmitter[ta.Trade], error) {
	return s.latestTradesStream(ctx, req.Data.ExternalAddress)
}

// StreamCommunityTokensTradingStats godoc
//
//	@Schemes
//	@Description	Streams trading statistics for a specific community token address.
//	@Tags			stream
//	@Produce		json
//	@Param			externalAddressOrViewType	path		string	true	"External address"	example("0x1234...")
//	@Success		200							{object}	ta.TradeStats
//	@Failure		401							{object}	server.ResponseErrorBody	"if auth token is missing or invalid"
//	@Failure		500							{object}	server.ResponseErrorBody
//	@Failure		504							{object}	server.ResponseErrorBody	"if request times out"
//	@Security		Nostr
//	@Security		XCom
//	@Router			/v1sse/community-tokens/{externalAddressOrViewType}/trading-stats [GET].
//	@Router			/v1ws/community-tokens/{externalAddressOrViewType}/trading-stats [GET].
func (s *service) StreamCommunityTokensTradingStats(ctx context.Context, req *server.Request[TradeRequest]) (server.StreamEventEmitter[ta.TradeStats], error) {
	return s.tradingStatsStream(ctx, req.Data.ExternalAddress)
}

// StreamCommunityTokensOHLCV godoc
//
//	@Schemes
//	@Description	Streams OHLCV (Open, High, Low, Close, Volume) data for a specific community token address.
//	@Tags			stream
//	@Produce		json
//	@Param			externalAddressOrViewType	path		string	true	"External address"	example("0x1234...")
//	@Param			interval					query		string	true	"Time interval"		example("1m")
//	@Success		200							{object}	ta.OHLCV
//	@Failure		401							{object}	server.ResponseErrorBody	"if auth token is missing or invalid"
//	@Failure		500							{object}	server.ResponseErrorBody
//	@Failure		504							{object}	server.ResponseErrorBody	"if request times out"
//	@Security		Nostr
//	@Security		XCom
//	@Router			/v1sse/community-tokens/{externalAddressOrViewType}/ohlcv [GET].
//	@Router			/v1ws/community-tokens/{externalAddressOrViewType}/ohlcv [GET].
func (s *service) StreamCommunityTokensOHLCV(ctx context.Context, req *server.Request[OHLCVRequest]) (server.StreamEventEmitter[ta.OHLCV], error) {
	return s.ohlcvStream(ctx, req.Data.ExternalAddress, req.Data.Interval)
}

func (s *service) ohlcvStream(ctx context.Context, ionContentAddress string, intervalStr string) (server.StreamEventEmitter[ta.OHLCV], error) {
	interval := ta.Interval(intervalStr)
	if err := interval.Validate(); err != nil {
		return nil, errors.Wrapf(err, "invalid interval")
	}
	now := time.Now().In(time.UTC)
	emitter, err := wrapIntoStream[ta.OHLCV](interval.InitialBufferSize(), func(addToStream func(t *ta.OHLCV, err error)) error {
		if err := s.tokenAnalytics.SubscribeOHLVC(ctx, now, ionContentAddress, interval, addToStream); err != nil {
			return errors.Wrapf(err, "failed to subscribe to OHLCV for %v", ionContentAddress)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return emitter, nil
}

// StreamCommunityTokenBondingCurveProgress godoc
//
//	@Schemes
//	@Description	Streams updates of bonding curve progress
//	@Tags			stream
//	@Produce		json
//	@Param			externalAddressOrViewType	path		string	true	"External address"	example("0x1234...")
//	@Success		200							{object}	ta.BondingCurveProgress
//	@Failure		401							{object}	server.ResponseErrorBody	"if auth token is missing or invalid"
//	@Failure		500							{object}	server.ResponseErrorBody
//	@Failure		504							{object}	server.ResponseErrorBody	"if request times out"
//	@Security		Nostr
//	@Security		XCom
//	@Router			/v1sse/community-tokens/{externalAddressOrViewType}/bondingCurveProgress [GET].
//	@Router			/v1ws/community-tokens/{externalAddressOrViewType}/bondingCurveProgress [GET].
func (s *service) StreamCommunityTokenBondingCurveProgress(ctx context.Context, req *server.Request[BondingCurveProgressRequest]) (server.StreamEventEmitter[ta.BondingCurveProgress], error) {
	emitter, err := wrapIntoStream[ta.BondingCurveProgress](100, func(addToStream func(t *ta.BondingCurveProgress, err error)) error {
		if err := s.tokenAnalytics.SubscribeBondingCurveProgress(ctx, req.Data.ExternalAddress, addToStream); err != nil {
			return errors.Wrapf(err, "failed to subscribe to bonding curve progress for %v", req.Data.ExternalAddress)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return emitter, nil
}

func wrapIntoStream[T any](initialBuffer int, impl func(addToStream func(t *T, err error)) error) (server.StreamEventEmitter[T], error) {
	events := make(chan server.StreamEvent[T], initialBuffer)
	addWithWrap := func(t *T, err error) {
		if err != nil {
			events <- server.StreamEvent[T]{
				Err:  err,
				Data: nil,
				Type: "error",
			}
			return
		}
		if t == nil && err == nil {
			events <- server.StreamEvent[T]{
				Type: "eose",
				Data: nil,
			}
			return
		}
		events <- server.StreamEvent[T]{
			Data: t,
			Type: "message",
		}
	}
	return func(ctx context.Context) (<-chan server.StreamEvent[T], error) {
		if err := impl(addWithWrap); err != nil {
			return nil, errors.Wrapf(err, "failed to call stream implementation")
		}
		return events, nil
	}, nil
}

func (s *service) tradingStatsStream(ctx context.Context, externalAddress string) (server.StreamEventEmitter[ta.TradeStats], error) {
	now := time.Now().In(time.UTC)
	emitter, err := wrapIntoStream[ta.TradeStats](100, func(addToStream func(t *ta.TradeStats, err error)) error {
		if err := s.tokenAnalytics.SubscribeTradingStats(ctx, now, externalAddress, addToStream); err != nil {
			return errors.Wrapf(err, "failed to subscribe to trading stats updates for  %v", externalAddress)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return emitter, nil
}

func (s *service) latestTradesStream(ctx context.Context, externalAddress string) (server.StreamEventEmitter[ta.Trade], error) {
	emitter, err := wrapIntoStream[ta.Trade](1, func(addToStream func(t *ta.Trade, err error)) error {
		if err := s.tokenAnalytics.SubscribeLatestTrades(ctx, externalAddress, addToStream); err != nil {
			return errors.Wrapf(err, "failed to subscribe to latest-trades updates for  %v", externalAddress)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return emitter, nil
}

// GetCommunityTokenAnalytics godoc
//
//	@Schemes
//	@Description	Returns aggregated analytics for community tokens.
//	@Tags			Analytics
//	@Produce		json
//	@Param			analyticsType	path		string					true	"Analytics type"	Enums(global)
//	@Param			interval		query		string					true	"Time interval"		Enums(24h, 7d, 30d)
//	@Success		200				{object}	TokenAnalyticsResponse	"Analytics data"
//	@Failure		400				{object}	server.ResponseErrorBody
//	@Router			/v1/community-token-analytics/{analyticsType} [get]
func (s *service) GetCommunityTokenAnalytics(_ context.Context, req *server.Request[TokenAnalyticsRequest]) (*server.Response[TokenAnalyticsResponse], error) {
	switch req.Data.AnalyticsType {
	case analyticsTypeGlobal:
	default:
		return nil, server.BadRequest(fmt.Errorf("unsupported analyticsType: %v", req.Data.AnalyticsType), invalidPropertiesErrorCode)
	}
	switch req.Data.Interval {
	case analyticsInterval24h, analyticsInterval7d, analyticsInterval30d:
	default:
		return nil, server.BadRequest(fmt.Errorf("unsupported interval: %v (expected %v, %v, or %v)",
			req.Data.Interval, analyticsInterval24h, analyticsInterval7d, analyticsInterval30d), invalidPropertiesErrorCode)
	}
	resp := &TokenAnalyticsResponse{
		Launched: uint64(rand.Intn(1000)),
		Migrated: uint64(rand.Intn(500)),
		Volume:   math.Round(rand.Float64()*100000*100) / 100,
	}

	return server.OK(resp), nil
}
