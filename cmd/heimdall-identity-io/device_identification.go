// SPDX-License-Identifier: ice License 1.0

package main

import (
	"fmt"
	"net/http"
	"strings"
	stdlibtime "time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/server"
	"github.com/ice-blockchain/wintr/log"
)

func (s *service) setupDeviceIdentificationRoutes(r *server.Router) {
	r.GET("v1/device-identification-agent", s.ProxyAgentDownload)
	r.POST("v1/device-identifications", s.ProxyIdentificationReq)
	r.GET("v1/device-identifications/* randomStrings", s.ProxyBrowserCache)
}

func (s *service) ProxyIdentificationReq(ginCtx *gin.Context) {
	status, resp, headers, err := s.deviceIdentificationProxy.ProxyIdentification(ginCtx)
	if err != nil {
		proxyError(ginCtx, err)
		return
	}
	for k, v := range headers {
		ginCtx.Header(k, v[0])
	}
	ginCtx.Data(status, headers.Get("Content-Type"), resp)
}

func (s *service) ProxyBrowserCache(ginCtx *gin.Context) {
	if true {
		ginCtx.JSON(http.StatusForbidden, map[string]string{
			"error": "disabled",
		})
		return
	}
	status, resp, headers, err := s.deviceIdentificationProxy.ProxyBrowserCache(ginCtx, strings.TrimLeft(ginCtx.Request.URL.Path, "/v1/device-identifications/"))
	if err != nil {
		proxyError(ginCtx, err)
		return
	}
	for k, v := range headers {
		ginCtx.Header(k, v[0])
	}
	ginCtx.Data(status, headers.Get("Content-Type"), resp)
}
func (s *service) ProxyAgentDownload(ginCtx *gin.Context) {
	if true {
		ginCtx.Data(http.StatusForbidden, "application/javascript", []byte("//disabled"))
		return
	}
	status, resp, headers, err := s.deviceIdentificationProxy.ProxyAgentDownload(ginCtx)
	if err != nil {
		proxyError(ginCtx, err, status)
		return
	}
	for k, v := range headers {
		ginCtx.Header(k, v[0])
	}
	ginCtx.Data(status, headers.Get("Content-Type"), resp)
}

func proxyError(ginCtx *gin.Context, err error, status ...int) {
	requestID := fmt.Sprintf("%v.%v", stdlibtime.Now().Unix(), uuid.NewString()[:6])
	log.Error(errors.Wrapf(err, "proxy request to device identification service failed, requestID %v", requestID))
	origin := ginCtx.Request.Header.Get("Origin")
	if origin == "" {
		origin = ginCtx.Request.Host
	}
	ginCtx.Header("'Access-Control-Allow-Origin'", origin)
	ginCtx.Header("Access-Control-Allow-Credentials", "true")
	statusCode := http.StatusInternalServerError
	if len(status) > 0 {
		statusCode = status[0]
	}
	ginCtx.JSON(statusCode,
		struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
			Products  map[string]any `json:"products"`
			V         string         `json:"v"`
			RequestID string         `json:"requestId"`
		}{
			V:         "2",
			RequestID: requestID,
			Error: struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			}{
				Code:    "IntegrationFailed",
				Message: fmt.Sprintf("oops, error occured for requestID: %v", requestID),
			},
			Products: map[string]any{},
		},
	)
}
