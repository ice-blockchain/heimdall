// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-openapi/spec"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/ice-blockchain/heimdall/cmd/heimdall/api"
	"github.com/ice-blockchain/heimdall/server"
	"github.com/ice-blockchain/wintr/log"
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
	var swagger spec.Swagger
	log.Panic(errors.Wrap(swagger.UnmarshalJSON([]byte(api.SwaggerInfo.ReadDoc())), "failed to extend swagger with dfns endpoints"))
	for _, endpoint := range s.cfg.ProxyDfnsEndpoints {
		router = router.Handle(endpoint.Method, endpoint.Endpoint, s.proxyDfns())
		swProp := swaggerProp(endpoint.Method, swaggerOp(endpoint))
		swagger.Paths.Paths[endpoint.Endpoint] = spec.PathItem{
			PathItemProps: swProp,
		}
	}
	swagger.Definitions["DfnsProxyData"] = spec.Schema{SchemaProps: spec.SchemaProps{Type: spec.StringOrArray([]string{"object"}), AdditionalProperties: &spec.SchemaOrBool{Schema: &spec.Schema{}}}}
	b, err := swagger.MarshalJSON()
	log.Panic(errors.Wrapf(err, "failed to extend swagger with dfns endpoints"))
	api.SwaggerInfo.SwaggerTemplate = string(b)
	router.POST("auth/recover/user/delegated", server.RootHandler(s.StartDelegatedRecovery)).
		POST("/auth/action/init", s.proxyDfns()).
		POST("/auth/action", s.proxyDfns()).
		POST("/auth/registration/delegated", server.RootHandler(s.StartDelegatedRegistration)).
		POST("/v1/webhooks/dfns/events", server.RootHandler(s.DfnsEventWebhook))
}

func swaggerProp(method string, op *spec.Operation) spec.PathItemProps {
	switch strings.ToUpper(method) {
	case "GET":
		return spec.PathItemProps{Get: op}
	case "PUT":
		return spec.PathItemProps{Put: op}
	case "POST":
		return spec.PathItemProps{Post: op}
	case "DELETE":
		return spec.PathItemProps{Delete: op}
	case "PATCH":
		return spec.PathItemProps{Patch: op}
	default:
		return spec.PathItemProps{}
	}
}

func swaggerOp(endpoint *dfnsEndpoint) *spec.Operation {
	params := []spec.Parameter{
		spec.Parameter{ParamProps: spec.ParamProps{Name: "X-DFNS-APPID", In: "header", Required: false}},
		spec.Parameter{ParamProps: spec.ParamProps{Name: "Authorization", In: "header", Required: false}},
		spec.Parameter{ParamProps: spec.ParamProps{Name: "X-DFNS-USERACTION", In: "header", Required: false}},
	}
	if strings.Contains(endpoint.Endpoint, ":") {
		parts := strings.Split(endpoint.Endpoint, "/")
		for _, p := range parts {
			if strings.HasPrefix(p, ":") {
				endpoint.Endpoint = strings.ReplaceAll(endpoint.Endpoint, p, fmt.Sprintf("{%v}", p[1:]))
				params = append(params, spec.Parameter{ParamProps: spec.ParamProps{Name: p[1:], In: "path", Required: true}})
			}
		}
	}
	if endpoint.Method != "GET" {
		body := spec.BodyParam("request", &spec.Schema{SchemaProps: spec.SchemaProps{Ref: spec.MustCreateRef("#/definitions/DfnsProxyData")}})
		params = append(params, *body)
	}

	return &spec.Operation{
		OperationProps: spec.OperationProps{
			Description:  "Refer to DFNS api",
			Consumes:     []string{"application/json"},
			Produces:     []string{"application/json"},
			Schemes:      nil,
			Tags:         []string{endpoint.Tag},
			Summary:      "Refer to DFNS api",
			ExternalDocs: nil,
			ID:           "",
			Deprecated:   false,
			Security:     nil,
			Parameters:   params,
			Responses: &spec.Responses{
				ResponsesProps: spec.ResponsesProps{
					StatusCodeResponses: map[int]spec.Response{
						200: spec.Response{
							ResponseProps: spec.ResponseProps{
								Schema: &spec.Schema{SchemaProps: spec.SchemaProps{Ref: spec.MustCreateRef("#/definitions/DfnsProxyData")}},
							},
						},
					},
				},
			},
		},
	}
}

func (s *service) proxyDfns() func(*gin.Context) {
	return func(ginCtx *gin.Context) {
		ctx, cancel := context.WithTimeout(ginCtx.Request.Context(), proxyTimeout)
		defer cancel()
		s.accounts.ProxyDfnsCall(ctx, ginCtx.Writer, ginCtx.Request)
	}
}

// StartDelegatedRegistration godoc
//
//	@Schemes
//	@Description	Initiates registration process with dfns
//	@Tags			Login
//	@Produce		json
//	@Param			X-DFNS-APPID	header		string							true	"Dfns app id"	default(ap-...)
//	@Param			request			body		StartDelegatedRegistrationReq	true	"Request params"
//	@Success		200				{object}	StartDelegatedRecoveryResp
func (s *service) StartDelegatedRegistration(
	ctx context.Context,
	req *server.Request[StartDelegatedRegistrationReq, StartDelegatedRegistrationResp],
) (successResp *server.Response[StartDelegatedRegistrationResp], errorResp *server.ErrResponse[*dfnsErrorResponse]) {
	resp, err := s.accounts.StartDelegatedRegistration(ctx, req.Data.Email, req.Data.Kind)
	if err != nil {
		if dfnsErr := accounts.ParseErrAsDfnsInternalErr(err); dfnsErr != nil {
			var dfnsParsedErr *accounts.DfnsErr
			if errors.As(dfnsErr, &dfnsParsedErr) {
				return nil, buildDfnsErrorResponse(dfnsParsedErr.HTTPStatus, err, dfnsParsedErr.Message)
			}
		}
		return nil, buildDfnsErrorResponse(http.StatusInternalServerError, err, "")
	}
	return server.OK[StartDelegatedRegistrationResp](&StartDelegatedRegistrationResp{resp}), nil
}

// StartDelegatedRecovery godoc
//
//	@Schemes
//	@Description	Initiates recovery process with dfns
//	@Tags			Recovery
//	@Produce		json
//	@Param			X-DFNS-APPID	header		string						true	"Dfns app id"	default(ap-...)
//	@Param			request			body		StartDelegatedRecoveryReq	true	"Request params"
//	@Success		200				{object}	StartDelegatedRecoveryResp
//	@Failure		400				{object}	server.ErrorResponse	"if invalid 2FA code is provided"
//	@Failure		403				{object}	server.ErrorResponse	"if 2FA required"
//	@Failure		500				{object}	server.ErrorResponse
//	@Failure		504				{object}	server.ErrorResponse	"if request times out"
//	@Router			/auth/recover/user/delegated [POST].
func (s *service) StartDelegatedRecovery(
	ctx context.Context,
	req *server.Request[StartDelegatedRecoveryReq, StartDelegatedRecoveryResp],
) (successResp *server.Response[StartDelegatedRecoveryResp], errorResp *server.ErrResponse[*dfnsErrorResponse]) {
	if err := req.Data.validate(); err != nil {
		return nil, buildDfnsErrorResponse(http.StatusBadRequest, errors.Wrapf(err, "invalid 2fa option provided"), invalidPropertiesErrorCode)
	}
	ctx = context.WithValue(ctx, accounts.DfnsAppIDHeaderCtxValue, req.Data.AppID)
	resp, err := s.accounts.StartDelegatedRecovery(ctx, req.Data.Username, req.Data.CredentialID, req.Data.TwoFAVerificationCodes)
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
	return server.OK[StartDelegatedRecoveryResp](&StartDelegatedRecoveryResp{resp}), nil
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

func (s *service) DfnsEventWebhook(
	ctx context.Context,
	req *server.Request[WebhookData, WebhookResp],
) (successResp *server.Response[WebhookResp], errorResp *server.ErrResponse[*server.ErrorResponse]) {
	log.Info("Webhook call for %v %v", req.Data.Kind, req.Data.Kind)
	return server.OK[WebhookResp](&WebhookResp{}), nil
}
