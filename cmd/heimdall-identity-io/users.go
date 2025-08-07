// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts"
	relaymanagement "github.com/ice-blockchain/heimdall/relay-management"
	"github.com/ice-blockchain/heimdall/server"
)

func (s *service) setupUserRoutes(router gin.IRoutes) {
	router.PATCH("v1/users/:userIdOrMasterKey/ion-connect-relays", server.RootHandler(s.GetOrAssignIONConnectRelays)).
		GET("v1/users/:userIdOrMasterKey/ion-connect-indexers", server.RootHandler(s.UserIndexers)).
		GET("auth/users/:userIdOrMasterKey", server.RootHandler(s.GetUser)).
		DELETE("auth/users/:userId", server.RootHandler(s.DeleteUser)).
		GET("v1/config/:configName", server.RootHandler(s.GetConfig)).
		POST("v1/users/get-content-creators", server.RootHandler(s.GetContentCreators)).
		GET("v1/users/ion-connect-relays", server.RootHandler(s.GetIONConnectRelays)).
		GET("v1/users/:userIdOrMasterKey/verified-badge", server.RootHandler(s.GetVerifiedBadge)).
		GET("v1/users/:userIdOrMasterKey/all-available-ion-connect-relays", server.RootHandler(s.GetAllIONConnectRelays))
}

// GetOrAssignIONConnectRelays godoc
//
//	@Schemes
//	@Description	Assigns relay list for the user based on his followee list
//	@Tags			Users
//	@Produce		json
//	@Param			userIdOrMasterKey	path		string		true	"ID of the user"
//	@Param			Authorization		header		string		true	"Auth token from delegated relying party"	default(Bearer <Add token here>)
//	@Param			request				body		RelaysReq	true	"Request params"
//	@Success		200					{object}	Relays
//	@Failure		500					{object}	server.ErrorResponse
//	@Failure		504					{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/users/{userIdOrMasterKey}/ion-connect-relays [PATCH].
func (s *service) GetOrAssignIONConnectRelays(
	ctx context.Context,
	req *server.Request[RelaysReq, Relays],
) (successResp *server.Response[Relays], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	relays, err := s.accounts.GetOrAssignIONConnectRelays(ctx, req.Data.UserIDOrMasterKey, req.Data.FolloweeList)
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrInvalidFollowees):
			return nil, server.BadRequest(err, invalidFollowees)
		default:
			return nil, server.Unexpected(err)
		}
	}
	return server.OK(&Relays{IONConnectRelays: relays}), nil
}

// GetIONConnectRelays godoc
//
//	@Schemes
//	@Description	Returns the relay list for each provided user master pubkey
//	@Tags			Users
//	@Produce		json
//	@Param			masterPubkey	query		[]string	true	"master pubkeys to get the ion connect relays for"
//	@Param			Authorization	header		string		true	"Auth token from delegated relying party"	default(Bearer <Add token here>)
//	@Success		200				{array}		accounts.LiteUser
//	@Failure		404				{object}	server.ErrorResponse	"if none of the users found"
//	@Failure		500				{object}	server.ErrorResponse
//	@Failure		504				{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/users/ion-connect-relays [GET].
func (s *service) GetIONConnectRelays(
	ctx context.Context,
	req *server.Request[GetBatchRelaysReq, []*accounts.LiteUser],
) (*server.Response[[]*accounts.LiteUser], *server.ErrResponse[*server.ErrorResponse]) {
	relays, err := s.accounts.GetIONConnectRelaysForUsers(ctx, req.Data.MasterPubkeys)
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrNotFound):
			return nil, server.NotFound(err, notFound)
		default:
			return nil, server.Unexpected(err)
		}
	}

	return server.OK(&relays), nil
}

// GetAllConnectRelays godoc
//
//	@Schemes
//	@Description	Gets list of all available relays
//	@Tags			Users
//	@Produce		json
//	@Param			userIdOrMasterKey	path		string	true	"ID of the user"
//	@Param			Authorization		header		string	true	"Auth token from delegated relying party"	default(Bearer <Add token here>)
//	@Param			ion-connect-relay	query		string	true	"Current relay"
//	@Success		200					{object}	Relays
//	@Failure		422					{object}	server.ErrorResponse	"if unknown relay passed"
//	@Failure		500					{object}	server.ErrorResponse
//	@Failure		504					{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/users/{userIdOrMasterKey}/all-available-ion-connect-relays [GET].
func (s *service) GetAllIONConnectRelays(
	ctx context.Context,
	req *server.Request[AllRelaysReq, Relays],
) (successResp *server.Response[Relays], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	relays, err := s.relays.GetAllIONConnectRelays(ctx, req.Data.IONConnectRelay)
	if err != nil {
		switch {
		case errors.Is(err, relaymanagement.ErrNoRelays):
			return nil, server.UnprocessableEntity(err, wrongRelay)
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
//	@Param			userIdOrMasterKey	path		string	true	"ID of the user"
//	@Param			Authorization		header		string	true	"Auth token"	default(Bearer <Add token here>)
//	@Success		200					{object}	Relays
//	@Failure		500					{object}	server.ErrorResponse
//	@Failure		504					{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/users/{userIdOrMasterKey}/ion-connect-indexers [GET].
func (s *service) UserIndexers(
	ctx context.Context,
	req *server.Request[IndexersReq, Indexers],
) (successResp *server.Response[Indexers], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	indexers, err := s.accounts.GetIONConnectIndexerRelays(ctx, req.Data.UserIDOrMasterKey)
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
//	@Description	Returns current user state
//	@Tags			Users
//	@Produce		json
//	@Param			userIdOrMasterKey	path		string	true	"ID of the user or his master key (hex)"
//	@Param			Authorization		header		string	true	"Auth token from delegated RP"	default(Bearer <Add token here>)
//	@Param			X-Client-ID			header		string	true	"App ID"						default(ap-)
//	@Success		200					{object}	User
//	@Failure		404					{object}	delegatedErrorResponse	"if user not found"
//	@Failure		500					{object}	delegatedErrorResponse
//	@Failure		504					{object}	server.ErrorResponse	"if request times out"
//	@Router			/auth/users/{userIdOrMasterKey} [GET].
func (s *service) GetUser(
	ctx context.Context,
	req *server.Request[GetUserReq, User],
) (successResp *server.Response[User], errorResp *server.ErrResponse[*delegatedErrorResponse]) {
	ctx = context.WithValue(ctx, accounts.AuthorizationHeaderCtxValue, req.Data.Authorization)
	ctx = context.WithValue(ctx, accounts.AppIDHeaderCtxValue, req.Data.ClientID)

	usr, err := s.accounts.GetUser(ctx, req.Data.UserIDOrMasterKey)
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrNotFound):
			return nil, buildDelegatedErrorResponse(http.StatusNotFound, err, "User not found")
		default:
			if delegatedErr := accounts.ParseErrAsDelegatedInternalErr(err); delegatedErr != nil {
				var delegatedParsedErr *accounts.DelegatedRelyingPartyErr
				if errors.As(delegatedErr, &delegatedParsedErr) {
					return nil, buildDelegatedErrorResponse(delegatedParsedErr.HTTPStatus, err, delegatedParsedErr.Message)
				}
			}
			return nil, buildDelegatedErrorResponse(http.StatusInternalServerError, err, "")
		}
	}
	return server.OK[User](&User{User: usr}), nil
}

// DeleteUser godoc
//
//	@Schemes
//	@Description	Deletes user account
//	@Tags			Users
//	@Produce		json
//	@Param			userId			path	string	true	"ID of the user"
//	@Param			Authorization	header	string	true	"Auth token from delegated RP"	default(Bearer <Add token here>)
//	@Param			X-Client-ID		header	string	true	"App ID"						default(ap-)
//	@Param			X-Useraction	header	string	true	"User's signature"				default(<signature>)
//	@Success		200				"Found and deleted"
//	@Failure		204				"Already deleted"
//	@Failure		401				{object}	server.ErrorResponse	"if not authorized"
//	@Failure		403				{object}	server.ErrorResponse	"not allowed"
//	@Failure		500				{object}	server.ErrorResponse
//	@Failure		504				{object}	server.ErrorResponse	"if request times out"
//	@Router			/auth/users/{userId} [DELETE].
func (s *service) DeleteUser(
	ctx context.Context,
	req *server.Request[DeleteUserReq, any],
) (successResp *server.Response[any], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	ctx = context.WithValue(ctx, accounts.AuthorizationHeaderCtxValue, req.Data.Authorization)
	ctx = context.WithValue(ctx, accounts.AppIDHeaderCtxValue, req.Data.ClientID)
	ctx = withSignature(ctx, req.Data.UserSignature)

	err := s.accounts.DeleteUser(ctx, req.Data.UserID)
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrNotChanged):
			return server.NoContent(), nil
		case errors.Is(err, accounts.ErrInvalidUserSignature):
			return nil, server.ForbiddenWithCode(err, invalidUserSignature)
		default:
			return nil, server.Unexpected(err)
		}
	}
	return server.OK[any](), nil
}

// GetConfig godoc
//
//	@Schemes
//	@Description
//	@Tags		Config
//	@Produce	json
//	@Param		configName	path		string	true	"Name of the configuration to read"
//	@Param		version		query		uint8	false	"The version of that specific config, if applicable"
//	@Success	200			{object}	any		"Configuration value"
//	@Success	204			"OK, no content, meaning there isn't a newer version of that config"
//	@Failure	404			{object}	server.ErrorResponse	"if invalid configName passed"
//	@Failure	504			{object}	server.ErrorResponse	"if request times out"
//	@Router		/v1/config/{configName} [GET].
func (s *service) GetConfig(
	_ context.Context,
	req *server.Request[GetConfig, any],
) (successResp *server.Response[any], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	getConfig, validConfigName := allValidConfigNames[req.Data.ConfigName]
	if !validConfigName {
		return nil, server.NotFound(errors.Errorf("invalid configName %v", req.Data.ConfigName), notFound)
	}
	resp, vers := getConfig(s.cfg)
	if vers > Version(0) && req.Data.Version == nil {
		return nil, server.UnprocessableEntity(errors.Errorf("version required for %v", req.Data.ConfigName), invalidPropertiesErrorCode)
	}
	if vers > Version(0) && req.Data.Version != nil && vers <= *req.Data.Version {
		return server.NoContent(), nil
	}
	if vers > Version(0) {
		return &server.Response[any]{Code: http.StatusOK, Data: &resp, Headers: map[string]string{"X-Version": fmt.Sprint(vers)}}, nil
	}

	return server.OK[any](&resp), nil
}

// GetContentCreators godoc
//
//	@Schemes
//	@Description	Returns content creators from the database
//	@Tags			Users
//	@Produce		json
//	@Param			limit					query		uint64					true	"Number of content creators to return"
//	@Param			excludeMasterPubKeys	body		GetContentCreatorsReq	false	"Master public key of the users to exclude"
//	@Param			Authorization			header		string					true	"Auth token"	default(Bearer <Add token here>)
//	@Success		200						{object}	[]LiteUser
//	@Failure		400						{object}	server.ErrorResponse	"if limit not provided"
//	@Failure		500						{object}	server.ErrorResponse
//	@Router			/v1/users/get-content-creators [POST]
func (s *service) GetContentCreators(
	ctx context.Context,
	req *server.Request[GetContentCreatorsReq, []*accounts.LiteUser],
) (successResp *server.Response[[]*accounts.LiteUser], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	creators, err := s.accounts.GetContentCreators(ctx, req.Data.Limit, req.Data.ExcludeMasterPubKeys)
	if err != nil {
		return nil, server.Unexpected(errors.Wrap(err, "failed to get content creators"))
	}

	return server.OK(&creators), nil
}

// GetVerifiedBadge godoc
//
//	@Schemes
//	@Description	Checks if a user is verified and returns badge events if they are
//	@Tags			Users
//	@Produce		json
//	@Param			userIdOrMasterKey	path		string	true	"Master public key of the user"
//	@Param			Authorization		header		string	true	"Auth token"	default(Bearer <Add token here>)
//	@Success		200					{object}	VerifiedBadgeEvents
//	@Success		204					"User is not verified"
//	@Failure		404					{object}	server.ErrorResponse	"if user not found"
//	@Failure		500					{object}	server.ErrorResponse
//	@Router			/v1/users/{userIdOrMasterKey}/verified-badge [GET]
func (s *service) GetVerifiedBadge(
	ctx context.Context,
	req *server.Request[GetVerifiedBadgeReq, VerifiedBadgeEvents],
) (successResp *server.Response[VerifiedBadgeEvents], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	if _, err := server.Auth(ctx).VerifyToken(ctx, req.Data.Authorization); err != nil {
		return nil, server.Unauthorized(err)
	}
	isVerified, events, err := s.accounts.IsUserVerified(ctx, req.Data.UserIDOrMasterKey)
	if err != nil {
		if errors.Is(err, accounts.ErrNotFound) {
			return nil, server.NotFound(errors.Wrap(err, "failed to check verification status"), notFound)
		}
		return nil, server.Unexpected(errors.Wrap(err, "failed to check verification status"))
	}
	if !isVerified {
		return &server.Response[VerifiedBadgeEvents]{Code: http.StatusNoContent}, nil
	}

	return server.OK(&VerifiedBadgeEvents{Events: events}), nil
}

// EarlyAccessAvailable godoc
//
//	@Schemes
//	@Description	Checks email availability for early access
//	@Tags			Register
//	@Produce		json
//	@Param			email	query	string	true	"User's email"
//	@Success		200		"If email is valid for early access"
//	@Failure		403		{object}	server.ErrorResponse	"if registrations disabled"
//	@Failure		404		{object}	server.ErrorResponse	"if email is not valid for early access"
//	@Failure		409		{object}	server.ErrorResponse	"if email exceeded number of allowed registrations"
//	@Failure		500		{object}	server.ErrorResponse
//	@Router			/v1/early-access-users [GET]
func (s *service) EarlyAccessAvailable(
	ctx context.Context,
	req *server.Request[EarlyAccessCheck, any],
) (successResp *server.Response[any], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	err := s.accounts.VerifyEarlyAccess(ctx, req.Data.Email)
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrEmailNotAllowedForEarlyAccess):
			return nil, server.NotFound(err, invalidEmail)
		case errors.Is(err, accounts.ErrRegistrationsDisabled):
			return nil, server.ForbiddenWithCode(err, registrationsDisabled)
		case errors.Is(err, accounts.ErrEmailUsed):
			return nil, server.Conflict(err, emailUsed)
		default:
			return nil, server.Unexpected(errors.Wrap(err, "failed check early access email availability"))
		}
	}

	return server.OK[any](), nil
}
