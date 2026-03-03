// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"strings"
	stdlibtime "time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/ice-blockchain/heimdall/server"
	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/subzero/validation"
	"github.com/ice-blockchain/wintr/log"
)

func (s *service) setupDeviceIdentificationRoutes(r *server.Router) {
	r.GET("v1/device-identification-agent", s.ProxyAgentDownload)
	r.POST("v1/device-identifications", s.ProxyIdentificationReq)
	r.GET("v1/device-identifications/* randomStrings", s.ProxyBrowserCache)
	r.POST("v1/device-identification-proofs", server.RootHandler(s.DeviceIdentificationProofs))
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

func mustRandomString(length int) string {
	bytes := make([]byte, length)
	_, _ = rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)[:length]
}

func proxyError(ginCtx *gin.Context, err error, status ...int) {
	requestID := fmt.Sprintf("%v.%v", stdlibtime.Now().Unix(), mustRandomString(6))
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

// DeviceIdentificationProofs
//
//	@Schemes
//	@Description	Process event of linking new device (kind 21750 => 10100)
//	@Tags			Register
//	@Accept			json
//	@Produce		json
//	@Param			Authorization	header		string							true	"Authorization token"
//	@Param			request			body		DeviceIdentificationEventReq	true	"Event with new linked device (kind 21750 => 10100)"
//	@Success		200				{array}		model.Event						"Badges"
//	@Failure		403				{object}	server.ErrorResponse			"if master key of event does not belong to user"
//	@Failure		404				{object}	server.ErrorResponse			"if invalid device key provided with the event"
//	@Failure		422				{object}	server.ErrorResponse			"if invalid events provided"
//	@Failure		500				{object}	server.ErrorResponse
//	@Failure		504				{object}	server.ErrorResponse	"if request times out"
//	@Router			/v1/device-identification-proofs [POST].
func (s *service) DeviceIdentificationProofs(
	ctx context.Context,
	req *server.Request[DeviceIdentificationEventReq, []*model.Event],
) (*server.Response[[]*model.Event], *server.ErrResponse[*server.ErrorResponse]) {
	attestationEvent, err := s.validateDeviceEvent(ctx, req.Data.Event)
	if err != nil {
		return nil, server.UnprocessableEntity(err, invalidPropertiesErrorCode)
	}
	proofs, err := s.accounts.DeviceIdentificationProofs(ctx, attestationEvent, req.Data.Event.PubKey)
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrNotFound):
			return nil, server.NotFound(err, notFound)
		case errors.Is(err, accounts.ErrUnauthorized):
			return nil, server.Forbidden(err)
		default:
			return nil, server.Unexpected(err)
		}
	}

	return server.OK(&proofs), nil
}

func (s *service) validateDeviceEvent(ctx context.Context, device *model.Event) (attestationEvent *model.Event, err error) {
	attestationAddr, attestationEvent, err := model.ParseEphemeralEmbeddingEventRef(device)
	if err != nil {
		return nil, errors.Wrapf(err, "malformed 21750")
	}
	if !slices.Contains(attestationAddr, attestationEvent.Address()) {
		return nil, errors.Wrapf(err, "21750 does not point to attestation event")
	}
	if err = s.validation.Validate(ctx, []*model.Event{device}, validation.RuleWithSkipDeviceIdentificationProofEventsVerify()); err != nil {
		return nil, errors.Wrapf(err, "invalid 21750")
	}
	if err = s.validation.Validate(ctx, []*model.Event{attestationEvent}, validation.RuleWithSkipDeviceIdentificationProofEventsVerify()); err != nil {
		return nil, errors.Wrapf(err, "invalid attestation")
	}
	if attestationEvent.PubKey != device.GetMasterPublicKey() {
		return nil, errors.Wrapf(err, "device master %v does not match attestation", device.GetMasterPublicKey())
	}
	for i := len(attestationEvent.Tags) - 1; i >= 0; i-- {
		pTag := attestationEvent.Tags[i]
		if pTag.Key() != model.TagAttestationName {
			continue
		}
		action, _, _, err := model.ParseAttestationString(pTag[model.TagAttestationValueIndexAction])
		if err != nil {
			return nil, errors.Wrapf(err, "malformed attestation: %v", pTag[model.TagAttestationValueIndexAction])
		}
		if action != model.CustomIONAttestationKindActive {
			continue
		}
		pubkey := pTag[model.TagAttestationValueIndexPubkey]

		if pubkey != device.PubKey {
			return nil, errors.Wrapf(err, "last active device: %v does not match with 21750 signed key %v", pubkey, device.PubKey)
		}
		break
	}
	return attestationEvent, nil
}
