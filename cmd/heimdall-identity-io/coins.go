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

	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/ice-blockchain/heimdall/coins"
	"github.com/ice-blockchain/heimdall/server"
)

func (s *service) setupCoinRoutes(router gin.IRoutes) {
	router.POST("/v1/coins", server.RootHandler(s.ImportCoin))
	router.GET("/v1/coins", server.RootHandler(s.GetAllCoins))
	router.GET("/v1/users/:userId/coins", server.RootHandler(s.GetVersionedCoins))
	router.PATCH("/v1/sync-coins", server.RootHandler(s.SyncCoins))
	router.GET("/v1/users/:userId/coins/:symbolGroup", server.RootHandler(s.GetCoinsOfSymbolGroup))
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
	userID := req.AuthenticatedUser.UserID()
	// Link new coin to user / populate user's wallet views with it.
	walletViews, err := s.accounts.GetWalletViews(ctx, userID)
	for _, wv := range walletViews {
		needUpdate := false
		if !slices.Contains(wv.SymbolGroups, coin.SymbolGroup) {
			wv.SymbolGroups = append(wv.SymbolGroups, coin.SymbolGroup)
			needUpdate = true
		}
		newCoins := append(wv.Coins, &accounts.CoinMapping{
			WalletID: nil,
			CoinID:   coin.ID,
		})
		if err = s.validateWalletView(ctx, newCoins, false); err == nil {
			wv.Coins = newCoins
			needUpdate = true
		}
		if needUpdate {
			if _, err = s.accounts.ModifyWalletView(ctx, userID, wv.Name, wv.Name, wv.Coins, wv.SymbolGroups); err != nil {
				return nil, server.Unexpected(err)
			}
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
	if req.Data.APIKey != s.cfg.APIKey {
		return nil, server.Forbidden(errors.Errorf("invalid api key %v", req.Data.APIKey))
	}
	latestVersion, allCoins, err := s.coins.GetAllCoins(ctx)
	if err != nil {
		return nil, server.Unexpected(err)
	}
	return &server.Response[[]*SymbolGroupWithCoins]{Code: http.StatusOK, Data: &allCoins, Headers: map[string]string{"X-Version": fmt.Sprintf("%v", latestVersion)}}, nil
}

// GetVersionedCoins godoc
//
//	@Schemes
//	@Description	Provides a list of coins updated since version
//	@Tags			Coins
//	@Produce		json
//	@Param			version			query		string	false	"Version of configuration already presented on client"
//	@Param			userId			path		string	true	"ID of the user"
//	@Param			Authorization	header		string	true	"Auth token from delegated relying party"	default(Bearer <Add token here>)
//	@Success		200				{object}	VersionedCoins
//	@Success		204				{object}	VersionedCoins			"if known_version have been provided before"
//	@Failure		504				{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/users/{userId}/coins [GET].
func (s *service) GetVersionedCoins(
	ctx context.Context,
	req *server.Request[GetVersionedCoins, VersionedCoins],
) (successResp *server.Response[VersionedCoins], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	version, items, err := s.coins.GetVersionedCoins(ctx, req.Data.UserID, req.Data.Version)
	if err != nil {
		switch {
		case errors.Is(err, coins.ErrNotChanged):
			return &server.Response[VersionedCoins]{Code: http.StatusNoContent}, nil
		default:
			return nil, server.Unexpected(err)
		}
	}

	return server.OK[VersionedCoins](&VersionedCoins{Version: version, Coins: items}), nil
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
//	@Param			symbolGroup		path		string	false	"symbolGroup to filter"
//	@Param			userId			path		string	false	"ID of the user"
//	@Param			Authorization	header		string	true	"Auth token from delegated relying party"	default(Bearer <Add token here>)
//	@Success		200				{object}	[]Coin
//	@Failure		500				{object}	server.ErrorResponse
//	@Failure		504				{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/users/{userId}/coins/{symbolGroup} [GET].
func (s *service) GetCoinsOfSymbolGroup(
	ctx context.Context,
	req *server.Request[GetCoinsOfSymbolGroupReq, []*CoinWithWalletInfo],
) (successResp *server.Response[[]*CoinWithWalletInfo], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	items, err := s.accounts.GetCoinsOfSymbolGroup(ctx, req.Data.UserID, strings.ToLower(req.Data.SymbolGroup))
	if err != nil {
		return nil, server.Unexpected(err)
	}

	return server.OK[[]*CoinWithWalletInfo](&items), nil
}

func validateNetwork(network string) (string, error) {
	return coins.MapNetworkToCoinGecko(network)
}
