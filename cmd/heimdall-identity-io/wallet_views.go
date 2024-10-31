// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/ice-blockchain/heimdall/server"
)

func (s *service) setupWalletViewsRoutes(router gin.IRoutes) {
	router.POST("/v1/users/:userId/wallet-views", server.RootHandler(s.CreateWalletView)).
		GET("/v1/wallet-configuration", server.RootHandler(s.AllAvailableCoins)).
		GET("/v1/users/:userId/wallet-views", server.RootHandler(s.GetWalletViews)).
		PUT("/v1/users/:userId/wallet-views/:walletViewName", server.RootHandler(s.ModifyWalletView)).
		DELETE("/v1/users/:userId/wallet-views/:walletViewName", server.RootHandler(s.DeleteWalletView))
}

// CreateWalletView godoc
//
//	@Schemes
//	@Description	Creates a list of coin / [wallet] for user to see on main wallet screen
//	@Tags			Wallets
//	@Produce		json
//	@Param			userId			path		string			true	"ID of the user"
//	@Param			Authorization	header		string			true	"Auth token from delegated relying party"	default(Bearer <Add token here>)
//	@Param			request			body		WalletViewReq	true	"Request params"
//	@Success		201				{object}	WalletView
//	@Failure		500				{object}	server.ErrorResponse
//	@Failure		400				{object}	server.ErrorResponse	"if validation of walletview failed"
//	@Failure		409				{object}	server.ErrorResponse	"if user already owns walletview with such name"
//	@Failure		504				{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/users/{userId}/wallet-views [POST].
func (s *service) CreateWalletView(
	ctx context.Context,
	req *server.Request[WalletViewReq, WalletView],
) (successResp *server.Response[WalletView], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	err := s.validateWalletView(req.Data.Items)
	if err != nil {
		return nil, server.BadRequest(err, invalidPropertiesErrorCode)
	}
	var view *WalletView
	view, err = s.accounts.CreateWalletView(ctx, req.Data.UserID, req.Data.Name, req.Data.Items)
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrDuplicate):
			return nil, server.Conflict(err, duplicate)
		case errors.Is(err, accounts.ErrNotFound):
			return nil, server.NotFound(err, userNotFound)
		default:
			return nil, server.Unexpected(err)
		}
	}

	return server.Created(view), nil
}

// GetWalletViews godoc
//
//	@Schemes
//	@Description	Lists all available wallet views for the user
//	@Tags			Wallets
//	@Produce		json
//	@Param			userId			path		string	true	"ID of the user"
//	@Param			Authorization	header		string	true	"Auth token from delegated relying party"	default(Bearer <Add token here>)
//	@Success		200				{object}	WalletViews
//	@Failure		500				{object}	server.ErrorResponse
//	@Failure		504				{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/users/{userId}/wallet-views [GET].
func (s *service) GetWalletViews(
	ctx context.Context,
	req *server.Request[GetWalletViewsReq, WalletViews],
) (successResp *server.Response[WalletViews], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	views, err := s.accounts.GetWalletViews(ctx, req.Data.UserID)
	if err != nil {
		switch {
		default:
			return nil, server.Unexpected(err)
		}
	}
	return server.OK(&views), nil
}

func (s *service) validateWalletView(items []*accounts.WalletViewItem) error {
	if len(items) == 0 {
		return errors.Errorf("invalid walletview, items cannot be empty")
	}
	dedupl := map[string]struct{}{}
	coins := map[string]struct{}{}
	_, allCoins, _ := s.accounts.AllSupportedCoins(nil)
	for _, coin := range allCoins {
		coins[coin.Coin] = struct{}{}
	}
	for _, i := range items {
		key := i.Coin
		if i.WalletID != nil {
			key += "/" + *i.WalletID
		}
		if _, has := dedupl[key]; has {
			return errors.Errorf("invalid walletview, %v is duplicated", key)
		}
		if _, validCoin := coins[i.Coin]; !validCoin {
			return errors.Errorf("invalid walletview, %v is unsupported", i.Coin)
		}
		dedupl[key] = struct{}{}
	}

	return nil
}

// AllAvailableCoins godoc
//
//	@Schemes
//	@Description	Provides a list of all available coins
//	@Tags			Wallets
//	@Produce		json
//	@Param			known_version	query		string	false	"Version of configuration already presented on client"
//	@Param			Authorization	header		string	true	"Auth token from delegated relying party"	default(Bearer <Add token here>)
//	@Success		200				{object}	WalletConfiguration
//	@Success		204				{object}	WalletConfiguration		"if known_version have been provided before"
//	@Failure		504				{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/wallet-configuration [GET].
func (s *service) AllAvailableCoins(
	_ context.Context,
	req *server.Request[AllAvailableCoinsReq, WalletConfiguration],
) (successResp *server.Response[WalletConfiguration], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	version, items, err := s.accounts.AllSupportedCoins(req.Data.KnownVersion)
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrNotChanged):
			return &server.Response[WalletConfiguration]{Code: http.StatusNoContent}, nil
		default:
			return nil, server.Unexpected(err)
		}
	}

	return server.OK[WalletConfiguration](&WalletConfiguration{Version: version, AvailableCoins: items}), nil
}

// DeleteWalletView godoc
//
//	@Schemes
//	@Description	Deletes wallet view for provided userId and name
//	@Tags			Wallets
//	@Produce		json
//	@Param			userId			path	string	true	"ID of the user"
//	@Param			walletViewName	path	string	true	"Name of wallet view"
//	@Param			Authorization	header	string	true	"Auth token from delegated relying party"	default(Bearer <Add token here>)
//	@Success		200				"OK - found and deleted"
//	@Success		204				"No Content - already deleted"
//	@Failure		500				{object}	server.ErrorResponse
//	@Failure		409				{object}	server.ErrorResponse	"if trying to delete last wallet view"
//	@Failure		504				{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/users/{userId}/wallet-views/{walletViewName} [DELETE].
func (s *service) DeleteWalletView(
	ctx context.Context,
	req *server.Request[WalletViewReference, any],
) (successResp *server.Response[any], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	err := s.accounts.DeleteWalletView(ctx, req.Data.UserID, req.Data.WalletViewName)
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrNotChanged):
			return server.NoContent(), nil
		case errors.Is(err, accounts.ErrDeleteLast):
			return nil, server.Conflict(err, lastEntry)
		default:
			return nil, server.Unexpected(err)
		}
	}

	return server.OK[any](), nil
}

// ModifyWalletView godoc
//
//	@Schemes
//	@Description	Modifies wallet view referenced in url
//	@Tags			Wallets
//	@Produce		json
//	@Param			userId			path		string			true	"ID of the user"
//	@Param			walletViewName	path		string			true	"Name of wallet view"
//	@Param			Authorization	header		string			true	"Auth token from delegated relying party"	default(Bearer <Add token here>)
//	@Param			request			body		WalletViewReq	true	"Request params"
//	@Success		200				{object}	WalletView		"Modified, updated view in response"
//	@Failure		500				{object}	server.ErrorResponse
//	@Failure		404				{object}	server.ErrorResponse	"if no such view exists"
//	@Failure		504				{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/users/{userId}/wallet-views/{walletViewName} [PUT].
func (s *service) ModifyWalletView(
	ctx context.Context,
	req *server.Request[ModifyWalletViewReq, WalletView],
) (successResp *server.Response[WalletView], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	err := s.validateWalletView(req.Data.Items)
	if err != nil {
		return nil, server.BadRequest(err, invalidPropertiesErrorCode)
	}
	view, err := s.accounts.ModifyWalletView(ctx, req.Data.WalletViewReference.UserID, req.Data.WalletViewReference.WalletViewName,
		req.Data.WalletViewReq.Name, req.Data.Items)
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrNotFound):
			return nil, server.NotFound(err, notFound)
		default:
			return nil, server.Unexpected(err)
		}
	}

	return server.OK[WalletView](view), nil
}
