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
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/terror"
)

type (
	delegatedErrorResponse struct {
		err   error          `json:"-"`
		Error errMessage     `json:"error"`
		Data  map[string]any `json:"data,omitempty"`
	}
	errMessage struct {
		Message string `json:"message"`
	}
)

func (d *delegatedErrorResponse) InternalErr() error {
	return d.err
}
func buildDelegatedErrorResponse(status int, err error, code string, data ...map[string]any) *server.ErrResponse[*delegatedErrorResponse] {
	msg := err.Error()
	if len(code) > 0 {
		msg = code
	}

	resp := &server.ErrResponse[*delegatedErrorResponse]{
		Data:    &delegatedErrorResponse{Error: errMessage{Message: msg}, err: err},
		Headers: nil,
		Code:    status,
	}
	if len(data) > 0 {
		resp.Data.Data = data[0]
	}
	return resp
}

func (s *service) setupDelegatedRPProxyRoutes(router *server.Router) {
	router.NoRoute(s.proxyToDelegatedRP(true))
	router.NoMethod(s.proxyToDelegatedRP(true))
	router.
		POST("auth/recover/user/delegated", server.RootHandler(s.StartDelegatedRecovery)).
		POST("/auth/login/delegated", s.proxyToDelegatedRP(false)).
		POST("/v1/webhooks/dfns/events", server.RootHandler(s.EventWebhookFromDelegatedRP)).
		GET("/.well-known/apple-app-site-association", server.RootHandler(s.AppleAppSiteAssociation)).
		GET("/.well-known/assetlinks.json", server.RootHandler(s.AssetLinks))

}

func (s *service) proxyToDelegatedRP(allowUnauthorized bool) func(*gin.Context) {
	return func(ginCtx *gin.Context) {
		ctx, cancel := context.WithTimeout(ginCtx.Request.Context(), proxyTimeout)
		defer cancel()
		if _, err := server.Authorize(ctx, ginCtx, allowUnauthorized); err != nil {
			ginCtx.JSON(err.Code, &delegatedErrorResponse{Error: errMessage{Message: err.Data.Code}, err: err.Data.InternalErr()})
			return
		}
		s.accounts.ProxyDelegatedRelyingParty(ctx, ginCtx.Writer, ginCtx.Request)
	}
}

func (s *service) AppleAppSiteAssociation(
	ctx context.Context,
	req *server.Request[AppAssociationReq, string],
) (successResp *server.Response[string], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	if s.cfg.AppleAppSiteAssociation == "" {
		return nil, server.NotFound(errors.New("not found"), "NOT_FOUND")
	}

	return server.Raw("application/json", []byte(s.cfg.AppleAppSiteAssociation)), nil
}
func (s *service) AssetLinks(
	ctx context.Context,
	req *server.Request[AppAssociationReq, string],
) (successResp *server.Response[string], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	if s.cfg.AssetLinks == "" {
		return nil, server.NotFound(errors.New("not found"), "NOT_FOUND")
	}

	return server.Raw("application/json", []byte(s.cfg.AssetLinks)), nil
}

// StartDelegatedRecovery godoc
//
//	@Schemes
//	@Description	Initiates recovery process with delegated RP
//	@Tags			Recovery
//	@Produce		json
//	@Param			request		body		StartDelegatedRecoveryReq	true	"Request params"
//	@Param			X-Client-ID	header		string						true	"App ID"	default(ap-)
//	@Success		200			{object}	StartDelegatedRecoveryResp
//	@Failure		400			{object}	server.ErrorResponse	"if invalid 2FA code is provided"
//	@Failure		403			{object}	server.ErrorResponse	"if 2FA required"
//	@Failure		500			{object}	server.ErrorResponse
//	@Failure		504			{object}	server.ErrorResponse	"if request times out"
//	@Router			/auth/recover/user/delegated [POST].
func (s *service) StartDelegatedRecovery(
	ctx context.Context,
	req *server.Request[StartDelegatedRecoveryReq, StartDelegatedRecoveryResp],
) (successResp *server.Response[StartDelegatedRecoveryResp], errorResp *server.ErrResponse[*delegatedErrorResponse]) {
	if err := req.Data.validate(); err != nil {
		return nil, buildDelegatedErrorResponse(http.StatusBadRequest, errors.Wrapf(err, "invalid 2fa option provided"), invalidPropertiesErrorCode)
	}
	resp, err := s.accounts.StartDelegatedRecovery(withAppID(ctx, req.Data.ClientID), req.Data.Username, req.Data.CredentialID, req.Data.TwoFAVerificationCodes)
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrNoPending2FA):
			return nil, buildDelegatedErrorResponse(http.StatusBadRequest, err, twoFANoPendingCode)
		case errors.Is(err, accounts.Err2FAExpired):
			return nil, buildDelegatedErrorResponse(http.StatusBadRequest, err, twoFAExpiredCode)
		case errors.Is(err, accounts.Err2FAInvalidCode):
			return nil, buildDelegatedErrorResponse(http.StatusBadRequest, err, twoFAInvalidCode)
		case errors.Is(err, accounts.ErrUserNotFound):
			return nil, buildDelegatedErrorResponse(http.StatusNotFound, err, userNotFound)
		case errors.Is(err, accounts.Err2FARequired):
			if tErr := terror.As(err); tErr != nil {
				return nil, buildDelegatedErrorResponse(http.StatusForbidden, err, twoFARequired, tErr.Data)
			}
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
	return server.OK[StartDelegatedRecoveryResp](resp), nil
}

func withAppID(ctx context.Context, appID string) context.Context {
	return context.WithValue(ctx, accounts.AppIDHeaderCtxValue, appID)
}

func (r *StartDelegatedRecoveryReq) validate() error {
	for reqOpt := range r.TwoFAVerificationCodes {
		ok := false
		for _, opt := range accounts.AllTwoFAOptions {
			if reqOpt == opt {
				ok = true
				break
			}
		}
		if !ok {
			return errors.Errorf("invalid 2fa option: %v", reqOpt)
		}
	}
	return nil
}

func (s *service) EventWebhookFromDelegatedRP(
	ctx context.Context,
	req *server.Request[WebhookData, WebhookResp],
) (successResp *server.Response[WebhookResp], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	log.Info(fmt.Sprintf("Webhook call for %v %+v", req.Data.Kind, req.Data.Data))
	return server.OK[WebhookResp](&WebhookResp{}), nil
}
