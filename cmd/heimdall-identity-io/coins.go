// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/coins"
	"github.com/ice-blockchain/heimdall/server"
)

func (s *service) setupCoinRoutes(router gin.IRoutes) {
	router.POST("/v1/coins", server.RootHandler(s.ImportCoin))
	router.GET("/v1/coins", server.RootHandler(s.GetAllCoins))
	router.GET("/v1/networks", server.RootHandler(s.GetAllNetworks))
	router.GET("/v1/users/:userIdOrMasterKey/coins", server.RootHandler(s.GetVersionedCoins))
	router.PATCH("/v1/sync-coins", server.RootHandler(s.SyncCoins))
	router.GET("/v1/users/:userIdOrMasterKey/coins/:symbolGroup", server.RootHandler(s.GetCoinsOfSymbolGroup))
	router.GET("/v2/coins", server.RootHandler(s.SearchCoins))
}

// ImportCoin godoc
//
//	@Schemes
//	@Description	Imports information about supported coin
//	@Tags			Coins
//	@Produce		json
//	@Param			Authorization	header		string			true	"Auth token from delegated relying party"	default(Bearer <Add token here>)
//	@Param			request			body		ImportCoinReq	true	"Request params"
//	@Success		200				{object}	Coin
//	@Failure		500				{object}	server.ErrorResponse
//	@Failure		400				{object}	server.ErrorResponse	"if invalid network provided"
//	@Failure		404				{object}	server.ErrorResponse	"if no such token exists"
//	@Failure		504				{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/coins [POST].
func (s *service) ImportCoin(
	ctx context.Context,
	req *server.Request[ImportCoinReq, Coin],
) (successResp *server.Response[Coin], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	mappedNetwork, err := validateNetwork(req.Data.Network)
	if err != nil {
		return nil, server.BadRequest(err, invalidPropertiesErrorCode)
	}
	var coin *Coin
	coin, err = s.coins.Import(ctx, mappedNetwork, strings.ToLower(req.Data.ContractAddress))
	if err != nil {
		switch {
		case errors.Is(err, coins.ErrNotFound):
			return nil, server.NotFound(err, notFound)
		default:
			return nil, server.Unexpected(err)
		}
	}

	return server.OK(coin), nil
}

// GetAllCoins godoc
//
//	@Schemes
//	@Description	Provides information about all the coins
//	@Tags			Coins
//	@Produce		json
//	@Param			X-API-Key	header		string	true	"API key"	default(bogus)
//	@Success		200			{object}	[]SymbolGroupWithCoins
//	@Failure		403			{object}	server.ErrorResponse	"if invalid X-API-Key provided"
//	@Failure		500			{object}	server.ErrorResponse
//	@Failure		504			{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/coins [GET].
func (s *service) GetAllCoins(
	ctx context.Context,
	req *server.Request[APIKey, []*SymbolGroupWithCoins],
) (successResp *server.Response[[]*SymbolGroupWithCoins], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	if !slices.Contains(s.cfg.APIKey, req.Data.APIKey) {
		return nil, server.Forbidden(errors.Errorf("invalid api key %v", req.Data.APIKey))
	}
	latestVersion, allCoins, err := s.coins.GetAllCoins(ctx)
	if err != nil {
		return nil, server.Unexpected(err)
	}
	return &server.Response[[]*SymbolGroupWithCoins]{Code: http.StatusOK, Data: &allCoins, Headers: map[string]string{"X-Version": fmt.Sprintf("%v", latestVersion)}}, nil
}

// GetAllNetworks godoc
//
//	@Schemes
//	@Description	Provides information about all the networks
//	@Tags			Coins
//	@Produce		json
//	@Param			X-API-Key	header		string	true	"API key"	default(bogus)
//	@Success		200			{object}	[]Network
//	@Failure		403			{object}	server.ErrorResponse	"if invalid X-API-Key provided"
//	@Failure		500			{object}	server.ErrorResponse	"if server fault"
//	@Failure		504			{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/networks [GET].
func (s *service) GetAllNetworks(
	_ context.Context,
	req *server.Request[APIKey, []*Network],
) (successResp *server.Response[[]*Network], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	if !slices.Contains(s.cfg.APIKey, req.Data.APIKey) {
		return nil, server.Forbidden(errors.Errorf("invalid api key %v", req.Data.APIKey))
	}
	allNetworks := s.coins.GetAllNetworks()
	return &server.Response[[]*Network]{Code: http.StatusOK, Data: &allNetworks}, nil
}

// GetVersionedCoins godoc
//
//	@Schemes
//	@Description	Provides a list of coins updated since version
//	@Tags			Coins
//	@Produce		json
//	@Param			version				query		string	false	"Version of configuration already presented on client"
//	@Param			userIdOrMasterKey	path		string	true	"ID of the user"
//	@Param			Authorization		header		string	true	"Auth token from delegated relying party"	default(Bearer <Add token here>)
//	@Success		200					{object}	VersionedCoins
//	@Success		204					"if known_version have been provided before"
//	@Failure		504					{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/users/{userIdOrMasterKey}/coins [GET].
func (s *service) GetVersionedCoins(
	ctx context.Context,
	req *server.Request[GetVersionedCoins, VersionedCoins],
) (successResp *server.Response[VersionedCoins], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	version, items, err := s.coins.GetVersionedCoins(ctx, req.Data.UserIDOrMasterKey, req.Data.Version)
	networks := s.coins.GetAllNetworks()
	if err != nil {
		switch {
		case errors.Is(err, coins.ErrNotChanged):
			return &server.Response[VersionedCoins]{Code: http.StatusNoContent}, nil
		default:
			return nil, server.Unexpected(err)
		}
	}

	return server.OK[VersionedCoins](&VersionedCoins{Version: version, Coins: items, Networks: networks}), nil
}

// SyncCoins godoc
//
//	@Schemes
//	@Description	Requests to sync / update coins from 3rdparty
//	@Tags			Coins
//	@Produce		json
//	@Param			symbolGroup		query		[]string	false	"Coins/tokens list to sync"
//	@Param			Authorization	header		string		true	"Auth token from delegated relying party"	default(Bearer <Add token here>)
//	@Success		200				{object}	[]Coin
//	@Failure		500				{object}	server.ErrorResponse
//	@Failure		504				{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/sync-coins [PATCH].
func (s *service) SyncCoins(
	ctx context.Context,
	req *server.Request[SyncCoinsReq, []*Coin],
) (successResp *server.Response[[]*Coin], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	items, err := s.coins.SyncCoins(ctx, req.Data.SymbolGroup)
	if err != nil {
		return nil, server.Unexpected(err)
	}

	return server.OK[[]*Coin](&items), nil
}

// GetCoinsOfSymbolGroup godoc
//
//	@Schemes
//	@Description	Returns all the user coins with symbol and wallet info (balances, etc)
//	@Tags			Coins
//	@Produce		json
//	@Param			symbolGroup			path		string	false	"symbolGroup to filter"
//	@Param			userIdOrMasterKey	path		string	false	"ID of the user"
//	@Param			Authorization		header		string	true	"Auth token from delegated relying party"	default(Bearer <Add token here>)
//	@Success		200					{object}	[]Coin
//	@Failure		500					{object}	server.ErrorResponse
//	@Failure		504					{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/users/{userIdOrMasterKey}/coins/{symbolGroup} [GET].
func (s *service) GetCoinsOfSymbolGroup(
	ctx context.Context,
	req *server.Request[GetCoinsOfSymbolGroupReq, []*CoinWithWalletInfo],
) (successResp *server.Response[[]*CoinWithWalletInfo], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	items, err := s.accounts.GetCoinsOfSymbolGroup(ctx, req.Data.UserIDOrMasterKey, strings.ToLower(req.Data.SymbolGroup))
	if err != nil {
		return nil, server.Unexpected(err)
	}

	return server.OK[[]*CoinWithWalletInfo](&items), nil
}

// SearchCoins godoc
//
//	@Schemes
//	@Description	Returns all coins matching by symbol the provided keyword
//	@Tags			Coins
//	@Produce		json
//	@Param			keyword			query		string	true	"keyword to filter"
//	@Param			limit			query		int		false	"limit (default 10)"
//	@Param			offset			query		int		false	"offset"
//	@Param			Authorization	header		string	true	"Auth token from delegated relying party"	default(Bearer <Add token here>)
//	@Success		200				{object}	[]Coin
//	@Failure		500				{object}	server.ErrorResponse
//	@Failure		504				{object}	server.ErrorResponse	"if request times out"
//	@Router			/v2/coins [GET].
func (s *service) SearchCoins(
	ctx context.Context,
	req *server.Request[SearchCoinsReq, []*Coin],
) (successResp *server.Response[[]*Coin], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	if req.Data.Limit == 0 {
		req.Data.Limit = 10
	}
	if req.Data.Limit > 200 {
		req.Data.Limit = 200
	}
	items, err := s.coins.Search(ctx, strings.ToLower(req.Data.Keyword), req.Data.Limit, req.Data.Offset)
	if err != nil {
		return nil, server.Unexpected(err)
	}

	return server.OK[[]*Coin](&items), nil
}

func validateNetwork(network string) (string, error) {
	return coins.MapNetworkToCoinGecko(network)
}
