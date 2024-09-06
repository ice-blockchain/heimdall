// SPDX-License-Identifier: ice License 1.0

package server

import (
	"bytes"
	"context"
	encJson "encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/goccy/go-reflect"
	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/wintr/auth"
	"github.com/ice-blockchain/wintr/log"
)

//nolint:gochecknoinits // Because we want to set it up globally.
func init() {
	if err := os.Setenv("TZ", ""); err != nil {
		log.Panic(err)
	}
}

//nolint:funlen // .
func RootHandler[REQ, RESP any, ERR InternalErr[ERRSTR], ERRSTR any](handleRequest func(context.Context, *Request[REQ, RESP]) (*Response[RESP], *ErrResponse[ERR])) func(*gin.Context) {
	return func(ginCtx *gin.Context) {
		ctx, cancel := context.WithTimeout(ginCtx.Request.Context(), cfg.DefaultEndpointTimeout)
		defer cancel()
		if ginCtx.Request.Proto != "HTTP/2.0" {
			log.Warn(fmt.Sprintf("suboptimal http version used for %[1]T", new(REQ)), "expected", "HTTP/2.0", "actual", ginCtx.Request.Proto)
		}
		req := new(Request[REQ, RESP]).init(ginCtx)
		if err := req.processRequest(); err != nil {
			log.Error(errors.Wrap(err.Data.InternalErr(), "endpoint processing failed"), fmt.Sprintf("%[1]T", req.Data), req, "Response", err)
			ginCtx.JSON(err.Code, err.Data)

			return
		}
		var err *ErrResponse[*ErrorResponse]
		if req.AuthenticatedUser, err = Authorize(ctx, ginCtx, req.allowUnauthorized); err != nil {
			log.Error(errors.Wrap(err.Data.InternalErr(), "endpoint authentication failed"), fmt.Sprintf("%[1]T", req.Data), req, "Response", err)
			ginCtx.JSON(err.Code, err.Data)

			return
		}
		reqCtx := context.WithValue(ctx, clientIPCtxValueKey, ginCtx.ClientIP()) //nolint:staticcheck,revive // .
		success, failure := handleRequest(reqCtx, req)
		if failure != nil {
			log.Error(errors.Wrap((failure.Data).InternalErr(), "endpoint failed"), fmt.Sprintf("%[1]T", req.Data), req, "Response", failure)
			ginCtx.JSON(processErrorResponse[REQ, RESP, ERR, ERRSTR](ctx, req, failure))

			return
		}
		for k, v := range success.Headers {
			ginCtx.Header(k, v)
		}
		if success.Data != nil {
			ginCtx.JSON(success.Code, success.Data)
		} else if success.Raw != nil {
			ginCtx.Data(success.Code, success.ContentType, success.Raw)
		} else {
			ginCtx.Status(success.Code)
		}
	}
}

func (req *Request[REQ, RESP]) init(ginCtx *gin.Context) *Request[REQ, RESP] {
	req.Data = new(REQ)
	req.ClientIP = net.ParseIP(ginCtx.ClientIP())
	req.ginCtx = ginCtx

	return req
}

//nolint:funlen,gocognit,revive // Alot of usecases.
func (req *Request[REQ, RESP]) processTags() {
	elem := reflect.TypeOf(req.Data).Elem()
	if elem.Kind() != reflect.Struct {
		log.Panic("request data's have to be structs")
	}
	const enabled = "true"
	fieldCount := elem.NumField()
	req.requiredFields = make([]string, 0, fieldCount)
	req.bindings = make(map[requestBinding]struct{}, 5) //nolint:mnd,gomnd // They're 5 possible values.
	for i := range fieldCount {
		field := elem.Field(i)
		tag := field.Tag
		if tag.Get("required") == enabled {
			req.requiredFields = append(req.requiredFields, field.Name)
		}
		if tag.Get("allowUnauthorized") == enabled {
			req.allowUnauthorized = true
		}
		if tag.Get("allowForbiddenGet") == enabled {
			req.allowForbiddenGet = true
		}
		if tag.Get("allowForbiddenWriteOperation") == enabled {
			req.allowForbiddenWriteOperation = true
		}
		if jsonTag := tag.Get("json"); jsonTag != "" && jsonTag != "-" {
			req.bindings[json] = struct{}{}
		}
		if tag.Get("uri") != "" {
			req.bindings[uri] = struct{}{}
		}
		if tag.Get("header") != "" {
			req.bindings[header] = struct{}{}
		}
		if tag.Get("form") != "" {
			if tag.Get("formMultipart") == "" {
				req.bindings[query] = struct{}{}
			}
		}
		if tag.Get("formMultipart") != "" {
			req.bindings[formMultipart] = struct{}{}
		}
	}
}

func (req *Request[REQ, RESP]) processRequest() *ErrResponse[*ErrorResponse] {
	req.processTags()
	var errs []error
	for b := range req.bindings {
		switch b {
		case json:
			errs = append(errs, req.ginCtx.ShouldBindJSON(req.Data))
		case uri:
			errs = append(errs, req.ginCtx.ShouldBindUri(req.Data))
		case query:
			errs = append(errs, req.ginCtx.ShouldBindQuery(req.Data))
		case header:
			errs = append(errs, req.ginCtx.ShouldBindHeader(req.Data))
		case formMultipart:
			errs = append(errs, req.ginCtx.ShouldBindWith(req.Data, binding.FormMultipart))
		}
	}
	if err := multierror.Append(nil, errs...).ErrorOrNil(); err != nil {
		return UnprocessableEntity(errors.Wrapf(err, "binding failed"), "STRUCTURE_VALIDATION_FAILED")
	}

	return req.validate()
}

func (req *Request[REQ, RESP]) validate() *ErrResponse[*ErrorResponse] {
	if len(req.requiredFields) == 0 {
		return nil
	}
	value := reflect.ValueOf(req.Data).Elem()
	requiredFields := make([]string, 0, len(req.requiredFields))
	for _, field := range req.requiredFields {
		if value.FieldByName(field).IsZero() {
			requiredFields = append(requiredFields, field)
		}
	}
	if len(requiredFields) == 0 {
		return nil
	}

	return UnprocessableEntity(errors.Errorf("properties `%v` are required", strings.Join(requiredFields, ",")), "MISSING_PROPERTIES")
}

func tryToExtractUserFromDynamicJSON(req *http.Request) (userID string, username string, err error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return "", "", errors.Wrapf(err, "couldn't read request body at %v", req.URL.Path)
	}
	defer req.Body.Close()

	req.Body = io.NopCloser(bytes.NewReader(body))
	if len(body) == 0 {
		return "", "", nil
	}
	var vals map[string]any
	if err = encJson.Unmarshal(body, &vals); err != nil {
		return "", "", errors.Wrapf(err, "failed to decode %v as json at %v", string(body), req.URL.Path)
	}
	if userIDInterface, hasUserID := vals["userId"]; hasUserID {
		userID = userIDInterface.(string)
	}
	if usernameInterface, hasUsername := vals["username"]; hasUsername {
		username = usernameInterface.(string)
	}
	if emailInterface, hasEmail := vals["email"]; hasEmail {
		username = emailInterface.(string)
	}
	return userID, username, nil
}

//nolint:gocyclo,revive,cyclop,gocognit // .
func Authorize(ctx context.Context, ginCtx *gin.Context, allowUnauthorized bool) (authUser Token, errResp *ErrResponse[*ErrorResponse]) {
	userID := strings.Trim(ginCtx.GetString("userId"), " ")
	if userID == "" {
		userID = strings.Trim(ginCtx.Param("userId"), " ")
	}
	username := strings.Trim(ginCtx.GetString("username"), " ")
	if userID == "" && username == "" && !allowUnauthorized {
		var err error
		if userID, username, err = tryToExtractUserFromDynamicJSON(ginCtx.Request); err != nil {
			return nil, Unauthorized(err)
		}
	}
	if allowUnauthorized {
		defer func() {
			errResp = nil
		}()
	}

	authToken := strings.TrimPrefix(ginCtx.GetHeader("Authorization"), "Bearer ")
	token, err := Auth(ctx).VerifyToken(ctx, authToken)
	if err != nil {
		if errors.Is(err, auth.ErrForbidden) {
			return nil, Forbidden(err)
		}

		return nil, Unauthorized(err)
	}
	if userID != "" && token.UserID() != userID {
		return nil, Forbidden(errors.Errorf("operation not allowed. param>%v!=token>%v", userID, token.UserID()))
	}
	if username != "" && token.Username() != username {
		return nil, Forbidden(errors.Errorf("operation not allowed, mismatched username. param>%v!=token>%v", username, token.Username()))
	}

	return token, nil
}

func processErrorResponse[REQ, RESP any, ERR InternalErr[ERRSTR], ERRSTR any](ctx context.Context, req *Request[REQ, RESP], failure *ErrResponse[ERR]) (int, any) {
	err := (failure.Data).InternalErr()
	if errors.Is(err, req.ginCtx.Request.Context().Err()) {
		return http.StatusServiceUnavailable, &ErrorResponse{Error: "service is shutting down"}
	}
	if errors.Is(err, ctx.Err()) {
		return http.StatusGatewayTimeout, &ErrorResponse{Error: "request timed out"}
	}
	if failure.Code <= 0 {
		return http.StatusInternalServerError, &ErrorResponse{Error: "oops, something went wrong"}
	}

	return failure.Code, failure.Data
}
