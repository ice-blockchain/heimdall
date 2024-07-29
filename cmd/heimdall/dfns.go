// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/ice-blockchain/heimdall/server"
	"github.com/pkg/errors"
)

type (
	dfnsErrorResponse struct {
		Error errMessage `json:"error"`
	}
	errMessage struct {
		Message string `json:"message"`
	}
)

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

func (s *service) StartDelegatedRecovery(
	ctx context.Context,
	req *server.Request[StartDelegatedRecoveryReq, StartDelegatedRecoveryResp],
) (successResp *server.Response[StartDelegatedRecoveryResp], errorResp *server.Response[server.ErrorResponse]) {
	if err := req.Data.validate(); err != nil {
		return nil, server.UnprocessableEntity(errors.Wrapf(err, "invalid 2fa option provided"), invalidPropertiesErrorCode)
	}
	return server.OK[StartDelegatedRecoveryResp](nil), nil
}

func (r *StartDelegatedRecoveryReq) validate() error {
	for _, reqOpt := range r.TwoFAVerificationCodes {
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
