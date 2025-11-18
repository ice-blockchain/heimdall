// SPDX-License-Identifier: ice License 1.0

package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

type (
	Request[REQ any] struct {
		Data              *REQ
		Context           *gin.Context
		bindings          map[requestDataBinding]struct{}
		requiredFields    []string
		allowUnauthorized bool
	}
	Response[RESP any] struct {
		Data        *RESP
		Headers     map[string]string
		ContentType string
		Raw         []byte
		Code        int
	}
	ResponseError Response[ResponseErrorBody]

	RequestHandler[REQ any, RESP any] func(context.Context, *Request[REQ]) (*Response[RESP], error)

	ResponseErrorBody struct {
		Err          error  `json:"-" swaggerignore:"true"`
		ErrorMessage string `json:"error"          example:"something is missing"`
		Code         string `json:"code,omitempty" example:"SOMETHING_NOT_FOUND"`
	}
	requestDataBinding uint8
)

const (
	bindingJSON requestDataBinding = iota
	bindingURI
	bindingQuery
	bindingHeader
	bindingFormMultipart
)

var (
	_ error = &ResponseError{}

	ErrCodeRequestBindFailed       = "STRUCTURE_VALIDATION_FAILED"
	ErrCodeRequestValidationFailed = "MISSING_PROPERTIES"
	ErrCodeServerInternal          = "INTERNAL_SERVER_ERROR"
)

func Error(err error, errCode string, httpCode int) *ResponseError {
	resp := ResponseError{
		Data: &ResponseErrorBody{
			Err:          err,
			ErrorMessage: err.Error(),
			Code:         errCode,
		},
		Code: httpCode,
	}
	return &resp
}

func OK[RESP any](responses ...*RESP) *Response[RESP] {
	var resp *RESP
	if len(responses) == 1 {
		resp = responses[0]
	}

	return &Response[RESP]{Code: http.StatusOK, Data: resp}
}

func Raw(contentType string, responses ...[]byte) *Response[string] {
	var resp []byte
	if len(responses) == 1 {
		resp = responses[0]
	}

	return &Response[string]{Code: http.StatusOK, ContentType: contentType, Raw: resp}
}

func RootHandler[REQ, RESP any](fn RequestHandler[REQ, RESP]) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var req Request[REQ]

		bindErr := req.parse(ctx).bind()
		if bindErr != nil {
			Error(fmt.Errorf("request binding failed: %w", bindErr), ErrCodeRequestBindFailed, http.StatusUnprocessableEntity).
				render(ctx)
			return
		}

		validationErr := req.validate()
		if validationErr != nil {
			Error(fmt.Errorf("request validation failed: %w", validationErr), ErrCodeRequestValidationFailed, http.StatusUnprocessableEntity).
				render(ctx)
			return
		}

		resp, respErr := fn(ctx, &req)
		if respErr != nil {
			var respErrTyped *ResponseError
			if errors.As(respErr, &respErrTyped) {
				respErrTyped.render(ctx)
				return
			}

			respErrTyped = Error(respErr, ErrCodeServerInternal, http.StatusInternalServerError)
			respErrTyped.render(ctx)
			return
		}

		if resp == nil {
			slog.WarnContext(ctx, "handler returned nil response without error",
				"path", ctx.FullPath(),
				"method", ctx.Request.Method,
			)
			ctx.Status(http.StatusNoContent)
			return
		}

		resp.render(ctx)
	}
}

func (r *Request[REQ]) parse(ctx *gin.Context) *Request[REQ] {
	r.Context = ctx
	r.bindings = make(map[requestDataBinding]struct{}, 5)
	r.Data = new(REQ)

	elem := reflect.TypeOf(r.Data).Elem()
	if elem.Kind() != reflect.Struct {
		slog.ErrorContext(ctx, "request data is not a struct", "type", fmt.Sprintf("%T", r.Data))
		panic("request data is not a struct")
	}

	const enabled = "true"
	fieldCount := elem.NumField()
	for i := range fieldCount {
		field := elem.Field(i)
		tag := field.Tag
		if tag.Get("required") == enabled {
			r.requiredFields = append(r.requiredFields, field.Name)
		}
		if tag.Get("allowUnauthorized") == enabled {
			r.allowUnauthorized = true
		}
		if jsonTag := tag.Get("json"); jsonTag != "" && jsonTag != "-" {
			r.bindings[bindingJSON] = struct{}{}
		}
		if tag.Get("uri") != "" {
			r.bindings[bindingURI] = struct{}{}
		}
		if tag.Get("header") != "" {
			r.bindings[bindingHeader] = struct{}{}
		}
		if tag.Get("form") != "" {
			if tag.Get("formMultipart") == "" {
				r.bindings[bindingFormMultipart] = struct{}{}
			}
		}
		if tag.Get("formMultipart") != "" {
			r.bindings[bindingFormMultipart] = struct{}{}
		}
	}

	return r
}

func (r *Request[REQ]) bind() error {
	var errs []error

	for b := range r.bindings {
		switch b {
		case bindingJSON:
			errs = append(errs, r.Context.ShouldBindJSON(r.Data))
		case bindingURI:
			errs = append(errs, r.Context.ShouldBindUri(r.Data))
		case bindingQuery:
			errs = append(errs, r.Context.ShouldBindQuery(r.Data))
		case bindingHeader:
			errs = append(errs, r.Context.ShouldBindHeader(r.Data))
		case bindingFormMultipart:
			errs = append(errs, r.Context.ShouldBindWith(r.Data, binding.FormMultipart))
		default:
			panic("unknown binding type: " + strconv.Itoa(int(b)))
		}
	}

	return errors.Join(errs...)
}

func (r *Request[REQ]) validate() error {
	if len(r.requiredFields) == 0 || r.Data == nil {
		return nil
	}

	var requiredFields []string
	value := reflect.ValueOf(r.Data).Elem()
	for _, field := range r.requiredFields {
		if value.FieldByName(field).IsZero() {
			requiredFields = append(requiredFields, field)
		}
	}
	if len(requiredFields) == 0 {
		return nil
	}

	return fmt.Errorf("one or more required fields are missing or empty: %s", strings.Join(requiredFields, ", "))
}

func (r *ResponseError) Unwrap() error {
	return r.Data.Err
}

func (r *ResponseError) Error() string {
	return r.Data.ErrorMessage
}

func (r *ResponseError) render(ctx *gin.Context) {
	ctx.Error(r.Data.Err)

	httpCode := r.Code
	if httpCode == 0 {
		switch {
		case errors.Is(r.Data.Err, ctx.Err()):
			httpCode = http.StatusGatewayTimeout
		default:
			httpCode = http.StatusInternalServerError
		}
	}

	ctx.AbortWithStatusJSON(httpCode, r.Data)
}

func (r *Response[RESP]) render(ctx *gin.Context) {
	var httpCode int

	for k, v := range r.Headers {
		ctx.Header(k, v)
	}

	httpCode = r.Code
	if httpCode == 0 {
		httpCode = http.StatusOK
	}

	if r.Data != nil {
		ctx.JSON(httpCode, r.Data)
	} else if r.Raw != nil {
		ctx.Data(httpCode, r.ContentType, r.Raw)
	} else {
		ctx.Status(httpCode)
	}
}
