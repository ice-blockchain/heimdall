// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/ice-blockchain/heimdall/server"
)

func (s *service) setupWalletViewsRoutes(router gin.IRoutes) {
	router.POST("/v1/users/:userIdOrMasterKey/wallet-views", server.RootHandler(s.CreateWalletView)).
		GET("/v1/users/:userIdOrMasterKey/wallet-views", server.RootHandler(s.GetWalletViews)).
		GET("/v1/users/:userIdOrMasterKey/wallet-views/:walletViewId", server.RootHandler(s.GetWalletView)).
		PUT("/v1/users/:userIdOrMasterKey/wallet-views/:walletViewId", server.RootHandler(s.ModifyWalletView)).
		DELETE("/v1/users/:userIdOrMasterKey/wallet-views/:walletViewId", server.RootHandler(s.DeleteWalletView))
}

// CreateWalletView godoc
//
//	@Schemes
//	@Description	Creates a list of coin / [wallet] for user to see on main wallet screen
//	@Tags			Wallets
//	@Produce		json
//	@Param			userIdOrMasterKey	path		string			true	"ID of the user"
//	@Param			Authorization		header		string			true	"Auth token from delegated relying party"	default(Bearer <Add token here>)
//	@Param			request				body		WalletViewReq	true	"Request params"
//	@Success		201					{object}	WalletView
//	@Failure		500					{object}	server.ErrorResponse
//	@Failure		400					{object}	server.ErrorResponse	"if validation of walletview failed"
//	@Failure		409					{object}	server.ErrorResponse	"if user already owns walletview with such name"
//	@Failure		504					{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/users/{userIdOrMasterKey}/wallet-views [POST].
func (s *service) CreateWalletView(
	ctx context.Context,
	req *server.Request[WalletViewReq, WalletView],
) (successResp *server.Response[WalletView], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	err := s.validateWalletView(ctx, req.Data.Items, req.Data.SymbolGroups, true)
	if err != nil {
		return nil, server.BadRequest(err, invalidPropertiesErrorCode)
	}
	var view *WalletView
	view, err = s.accounts.CreateWalletView(ctx, req.Data.UserIDOrMasterKey, req.Data.Name, req.Data.Items, req.Data.SymbolGroups)
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

// GetWalletView godoc
//
//	@Schemes
//	@Description	Get wallet view with extended information about coins (grouped)
//	@Tags			Wallets
//	@Produce		json
//	@Param			userIdOrMasterKey	path		string	true	"ID of the user"
//	@Param			walletViewId		path		string	true	"ID of wallet view"
//	@Param			paginationToken		query		string	false	"pagination token to continue from"
//	@Param			limit				query		string	false	"custom limit"
//	@Param			Authorization		header		string	true	"Auth token from delegated relying party"	default(Bearer <Add token here>)
//	@Success		200					{object}	WalletView
//	@Failure		500					{object}	server.ErrorResponse
//	@Failure		404					{object}	server.ErrorResponse	"if wallet view not found"
//	@Failure		504					{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/users/{userIdOrMasterKey}/wallet-views/{walletViewId} [GET].
func (s *service) GetWalletView(
	ctx context.Context,
	req *server.Request[GetWalletViewReq, WalletView],
) (successResp *server.Response[WalletView], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	if req.Data.Limit == 0 {
		req.Data.Limit = 100
	}
	view, nextPage, err := s.accounts.GetWalletView(withPagination(ctx, req.Data.PaginationToken, req.Data.Limit), req.Data.UserIDOrMasterKey, req.Data.WalletViewID)
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrNotFound):
			return nil, server.NotFound(err, notFound)
		default:
			return nil, server.Unexpected(err)
		}
	}
	if nextPage != nil {
		return &server.Response[WalletView]{Code: http.StatusOK, Data: view, Headers: map[string]string{"X-Next-Page": fmt.Sprintf("%v", *nextPage)}}, nil
	}
	return server.OK(view), nil
}

// GetWalletViews godoc
//
//	@Schemes
//	@Description	Lists all available wallet views for the user
//	@Tags			Wallets
//	@Produce		json
//	@Param			userIdOrMasterKey	path		string	true	"ID of the user"
//	@Param			Authorization		header		string	true	"Auth token from delegated relying party"	default(Bearer <Add token here>)
//	@Success		200					{object}	WalletViews
//	@Failure		500					{object}	server.ErrorResponse
//	@Failure		504					{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/users/{userIdOrMasterKey}/wallet-views [GET].
func (s *service) GetWalletViews(
	ctx context.Context,
	req *server.Request[GetWalletViewsReq, WalletViews],
) (successResp *server.Response[WalletViews], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	views, err := s.accounts.GetWalletViews(ctx, req.Data.UserIDOrMasterKey)
	if err != nil {
		switch {
		default:
			return nil, server.Unexpected(err)
		}
	}
	return server.OK(&views), nil
}

func (s *service) validateWalletView(ctx context.Context, items []*accounts.CoinMapping, symbolGroups []string, verifyCoins bool) error {
	dedupl := map[string]struct{}{}
	coins := map[string]struct{}{}
	if verifyCoins {
		_, allCoins, _ := s.coins.GetVersionedCoins(ctx, "", nil)
		for _, coin := range allCoins {
			coins[coin.ID] = struct{}{}
		}
	}
	for _, i := range items {
		key := i.CoinID
		if i.WalletID != nil {
			key += "/" + *i.WalletID
		}
		if _, has := dedupl[key]; has {
			return errors.Wrapf(accounts.ErrDuplicate, "invalid walletview, %v is duplicated", key)
		}
		if _, validCoin := coins[i.CoinID]; !validCoin && verifyCoins {
			return errors.Errorf("invalid walletview, %v is unsupported", i.CoinID)
		}
		dedupl[key] = struct{}{}
	}
	deduplSG := map[string]struct{}{}
	for _, sg := range symbolGroups {
		if _, has := deduplSG[sg]; has {
			return errors.Wrapf(accounts.ErrDuplicate, "invalid walletview, %v is duplicated", sg)
		}
		deduplSG[sg] = struct{}{}
	}

	return nil
}

// DeleteWalletView godoc
//
//	@Schemes
//	@Description	Deletes wallet view for provided userId and name
//	@Tags			Wallets
//	@Produce		json
//	@Param			userIdOrMasterKey	path	string	true	"ID of the user"
//	@Param			walletViewId		path	string	true	"ID of wallet view"
//	@Param			Authorization		header	string	true	"Auth token from delegated relying party"	default(Bearer <Add token here>)
//	@Success		200					"OK - found and deleted"
//	@Success		204					"No Content - already deleted"
//	@Failure		500					{object}	server.ErrorResponse
//	@Failure		409					{object}	server.ErrorResponse	"if trying to delete last wallet view"
//	@Failure		504					{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/users/{userIdOrMasterKey}/wallet-views/{walletViewId} [DELETE].
func (s *service) DeleteWalletView(
	ctx context.Context,
	req *server.Request[WalletViewReference, any],
) (successResp *server.Response[any], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	err := s.accounts.DeleteWalletView(ctx, req.Data.UserIDOrMasterKey, req.Data.WalletViewID)
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
//	@Param			userIdOrMasterKey	path		string			true	"ID of the user"
//	@Param			walletViewId		path		string			true	"ID of wallet view"
//	@Param			Authorization		header		string			true	"Auth token from delegated relying party"	default(Bearer <Add token here>)
//	@Param			request				body		WalletViewReq	true	"Request params"
//	@Success		200					{object}	WalletView		"Modified, updated view in response"
//	@Failure		500					{object}	server.ErrorResponse
//	@Failure		404					{object}	server.ErrorResponse	"if no such view exists"
//	@Failure		504					{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/users/{userIdOrMasterKey}/wallet-views/{walletViewId} [PUT].
func (s *service) ModifyWalletView(
	ctx context.Context,
	req *server.Request[ModifyWalletViewReq, WalletView],
) (successResp *server.Response[WalletView], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	err := s.validateWalletView(ctx, req.Data.Items, req.Data.SymbolGroups, true)
	if err != nil {
		if errors.Is(err, accounts.ErrDuplicate) {
			return nil, server.Conflict(err, duplicate)
		}
		return nil, server.BadRequest(err, invalidPropertiesErrorCode)
	}
	view, err := s.accounts.ModifyWalletView(ctx, req.Data.WalletViewReference.UserIDOrMasterKey, req.Data.WalletViewReference.WalletViewID,
		req.Data.WalletViewReq.Name, req.Data.Items, req.Data.SymbolGroups)
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

func withPagination(ctx context.Context, token string, limit uint) context.Context {
	ctx = context.WithValue(ctx, "paginationToken", token)
	ctx = context.WithValue(ctx, "paginationLimit", limit)
	return ctx
}
