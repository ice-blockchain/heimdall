// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/ice-blockchain/heimdall/server"
	"github.com/ice-blockchain/wintr/terror"
)

type (
	dfnsErrorResponse struct {
		err   error          `json:"-"`
		Error errMessage     `json:"error"`
		Data  map[string]any `json:"data,omitempty"`
	}
	errMessage struct {
		Message string `json:"message"`
	}
)

func (d *dfnsErrorResponse) InternalErr() error {
	return d.err
}
func buildDfnsErrorResponse(status int, err error, code string, data ...map[string]any) *server.ErrResponse[*dfnsErrorResponse] {
	msg := err.Error()
	if len(code) > 0 {
		msg = code
	}

	resp := &server.ErrResponse[*dfnsErrorResponse]{
		Data:    &dfnsErrorResponse{Error: errMessage{Message: msg}, err: err},
		Headers: nil,
		Code:    status,
	}
	if len(data) > 0 {
		resp.Data.Data = data[0]
	}
	return resp
}

func (s *service) setupDfnsProxyRoutes(router gin.IRoutes) {
	for _, endpoint := range s.cfg.ProxyDfnsEndpoints {
		router = router.Handle(endpoint.Method, endpoint.Endpoint, s.proxyDfns())
	}
	router.POST("auth/recover/user/delegated", server.RootHandler(s.StartDelegatedRecovery))
}

func (s *service) proxyDfns() func(*gin.Context) {
	return func(ginCtx *gin.Context) {
		ctx, cancel := context.WithTimeout(ginCtx.Request.Context(), proxyTimeout)
		defer cancel()
		s.accounts.ProxyDfnsCall(ctx, ginCtx.Writer, ginCtx.Request)
	}
}

// StartDelegatedRecovery godoc
//
//	@Schemes
//	@Description	Initiates recovery process with dfns
//	@Tags			Recovery
//	@Produce		json
//	@Param			request	body		StartDelegatedRecoveryReq	true	"Request params"
//	@Success		200		{object}	StartDelegatedRecoveryResp
//	@Failure		400		{object}	server.ErrorResponse	"if invalid 2FA code is provided"
//	@Failure		403		{object}	server.ErrorResponse	"if 2FA required"
//	@Failure		500		{object}	server.ErrorResponse
//	@Failure		504		{object}	server.ErrorResponse	"if request times out"
//	@Router			/auth/recover/user/delegated [POST].
func (s *service) StartDelegatedRecovery(
	ctx context.Context,
	req *server.Request[StartDelegatedRecoveryReq, StartDelegatedRecoveryResp],
) (successResp *server.Response[StartDelegatedRecoveryResp], errorResp *server.ErrResponse[*dfnsErrorResponse]) {
	if err := req.Data.validate(); err != nil {
		return nil, buildDfnsErrorResponse(http.StatusBadRequest, errors.Wrapf(err, "invalid 2fa option provided"), invalidPropertiesErrorCode)
	}

	_, err := s.accounts.StartDelegatedRecovery(ctx, req.Data.Username, req.Data.TwoFAVerificationCodes, req.Data.Username, req.Data.CredentialID)
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrNoPending2FA):
			return nil, buildDfnsErrorResponse(http.StatusBadRequest, err, twoFANoPendingCode)
		case errors.Is(err, accounts.Err2FAExpired):
			return nil, buildDfnsErrorResponse(http.StatusBadRequest, err, twoFAExpiredCode)
		case errors.Is(err, accounts.Err2FAInvalidCode):
			return nil, buildDfnsErrorResponse(http.StatusBadRequest, err, twoFAInvalidCode)
		case errors.Is(err, accounts.Err2FARequired):
			if tErr := terror.As(err); tErr != nil {
				return nil, buildDfnsErrorResponse(http.StatusForbidden, err, twoFARequired, tErr.Data)
			}
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
	return server.OK[StartDelegatedRecoveryResp](nil), nil
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
