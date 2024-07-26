// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"github.com/gin-gonic/gin"
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
}

func (s *service) proxyDfns() func(*gin.Context) {
	return func(ginCtx *gin.Context) {
		ctx, cancel := context.WithTimeout(ginCtx.Request.Context(), proxyTimeout)
		defer cancel()
		s.accounts.ProxyDfnsCall(ctx, ginCtx.Writer, ginCtx.Request)
	}
}
