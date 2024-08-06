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

func (s *service) setupUserRoutes(router gin.IRoutes) {
	router.POST("v1/users/:userId/ion-connect-relays", server.RootHandler(s.UserRelays)).
		GET("v1/users/:userId/ion-connect-indexers", server.RootHandler(s.UserIndexers)).
		GET("auth/users/:userId", server.RootHandler(s.GetUser))
}

// UserRelays godoc
//
//	@Schemes
//	@Description	Assigns relay list for the user based on his followee list
//	@Tags			Users
//	@Produce		json
//	@Param			userId			path		string		true	"ID of the user"
//	@Param			Authorization	header		string		true	"Dfns token"	default(Bearer <Add token here>)
//	@Param			request			body		RelaysReq	true	"Request params"
//	@Success		200				{object}	Relays
//	@Failure		500				{object}	server.ErrorResponse
//	@Failure		504				{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/users/{userId}/ion-connect-relays [POST].
func (s *service) UserRelays(
	ctx context.Context,
	req *server.Request[RelaysReq, Relays],
) (successResp *server.Response[Relays], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	relays, err := s.accounts.GetIONRelays(ctx, req.Data.UserID, req.Data.FolloweeList)
	if err != nil {
		switch {
		default:
			return nil, server.Unexpected(err)
		}
	}
	return server.OK(&Relays{IONConnectRelays: relays}), nil
}

// UserIndexers godoc
//
//	@Schemes
//	@Description	Returns indexers list for the user
//	@Tags			Users
//	@Produce		json
//	@Param			userId			path		string	true	"ID of the user"
//	@Param			Authorization	header		string	true	"Dfns token"	default(Bearer <Add token here>)
//	@Success		200				{object}	Relays
//	@Failure		500				{object}	server.ErrorResponse
//	@Failure		504				{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/users/{userId}/ion-connect-indexers [GET].
func (s *service) UserIndexers(
	ctx context.Context,
	req *server.Request[IndexersReq, Indexers],
) (successResp *server.Response[Indexers], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	indexers, err := s.accounts.GetIONIndexers(ctx, req.Data.UserID)
	if err != nil {
		switch {
		default:
			return nil, server.Unexpected(err)
		}
	}
	return server.OK(&Indexers{IONConnectIndexers: indexers}), nil
}

// GetUser godoc
//
//	@Schemes
//	@Description	Initiates recovery process with dfns
//	@Tags			Users
//	@Produce		json
//	@Param			userId			path		string	true	"ID of the user"
//	@Param			Authorization	header		string	true	"Dfns token"	default(Bearer <Add token here>)
//	@Param			X-DFNS-APPID	header		string	true	"Dfns app id"	default(ap-...)
//	@Success		200				{object}	User
//	@Failure		500				{object}	dfnsErrorResponse
//	@Failure		504				{object}	server.ErrorResponse	"if request times out"
//	@Router			/auth/users/{userId} [GET].
func (s *service) GetUser(
	ctx context.Context,
	req *server.Request[GetUserReq, User],
) (successResp *server.Response[User], errorResp *server.ErrResponse[*dfnsErrorResponse]) {
	ctx = context.WithValue(ctx, accounts.DfnsAuthorizationHeaderCtxValue, req.Data.Authorization)
	ctx = context.WithValue(ctx, accounts.DfnsAppIDHeaderCtxValue, req.Data.AppID)
	usr, err := s.accounts.GetUser(ctx, req.Data.UserID)
	if err != nil {
		switch {
		default:
			if dfnsErr := accounts.ParseErrAsDfnsInternalErr(err); dfnsErr != nil {
				var dfnsParsedErr *accounts.DfnsErr
				if errors.As(dfnsErr, &dfnsParsedErr) {
					return nil, buildDfnsErrorResponse(dfnsParsedErr.HTTPStatus, err, dfnsParsedErr.Message)
				}
			}
			return nil, buildDfnsErrorResponse(http.StatusInternalServerError, err, "")
		}
	}
	return server.OK[User](&User{User: usr}), nil
}
