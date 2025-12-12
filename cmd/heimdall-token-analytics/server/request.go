// SPDX-License-Identifier: ice License 1.0

package server

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/sse"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	"github.com/ice-blockchain/heimdall/cmd/heimdall-token-analytics/server/websocket"
)

type (
	Request[REQ any] struct {
		Data    *REQ                 // The request data payload.
		Context *gin.Context         // The Gin context for the request.
		Token   Token                // Optional authentication token information.
		WS      websocket.Connection // Optional websocket connection stream, if applicable.

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

	RequestHandlerFunc[REQ any, RESP any] func(context.Context, *Request[REQ]) (*Response[RESP], error)

	StreamEvent[T any] struct {
		Err  error  // Optional error associated with the event.
		Data *T     // Data payload of the event.
		Type string // Event type, e.g., "message", "update", "error", etc.
		ID   string // Optional event ID for reconnection purposes.
	}

	StreamEventEmitter[RESP any]     func(context.Context) (<-chan StreamEvent[RESP], error)
	StreamHandlerFunc[REQ, RESP any] func(context.Context, *Request[REQ]) (StreamEventEmitter[RESP], error)

	WebsocketEvent[RESP any]            = StreamEvent[RESP]
	WebsocketEventEmitter[RESP any]     func(context.Context, websocket.AsyncRead) (<-chan WebsocketEvent[RESP], error)
	WebsocketHandlerFunc[REQ, RESP any] func(context.Context, *Request[REQ]) (WebsocketEventEmitter[RESP], error)

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
	_               error = &ResponseError{}
	errAuthRequired       = errors.New("authentication required")

	ErrCodeRequestBindFailed         = "STRUCTURE_VALIDATION_FAILED"
	ErrCodeRequestValidationFailed   = "MISSING_PROPERTIES"
	ErrCodeServerInternal            = "INTERNAL_SERVER_ERROR"
	ErrCodeServerWebsocketReadFailed = "WEBSOCKET_READ_FAILED"
)

func bindAndValidate[REQ any](ctx *gin.Context, r *Request[REQ]) (ok bool) {
	bindErr := r.parse(ctx).bind()
	if bindErr != nil {
		Error(fmt.Errorf("request binding failed: %w", bindErr), ErrCodeRequestBindFailed, http.StatusUnprocessableEntity).
			render(ctx)
		return false
	}

	validationErr := r.validate()
	if validationErr != nil {
		Error(fmt.Errorf("request validation failed: %w", validationErr), ErrCodeRequestValidationFailed, http.StatusUnprocessableEntity).
			render(ctx)
		return false
	}

	if authIsEnabled(ctx) {
		if (r.Token == nil || r.Token.GetMasterPublicKey() == "") && !r.allowUnauthorized {
			Forbidden(errAuthRequired).render(ctx)
			return false
		}
	}

	return true
}

func handleRequestError(ctx *gin.Context, err error) {
	var respErrTyped *ResponseError

	if !errors.As(err, &respErrTyped) {
		respErrTyped = Error(err, ErrCodeServerInternal, http.StatusInternalServerError)
	}

	respErrTyped.render(ctx)
}

func RootHandler[REQ, RESP any](fn RequestHandlerFunc[REQ, RESP]) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var req Request[REQ]

		if !bindAndValidate(ctx, &req) {
			return
		}

		resp, respErr := fn(ctx, &req)
		if respErr != nil {
			handleRequestError(ctx, respErr)
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

func StreamMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Cache-Control", "no-cache")
		c.Writer.Header().Set("Connection", "keep-alive")
		c.Writer.Header().Set("Transfer-Encoding", "chunked")
		c.Next()
	}
}

func Stream2WebsocketHandler[REQ, RESP any](fn StreamHandlerFunc[REQ, RESP]) WebsocketHandlerFunc[REQ, RESP] {
	return func(ctx context.Context, req *Request[REQ]) (WebsocketEventEmitter[RESP], error) {
		emitter, err := fn(ctx, req)
		if err != nil {
			return nil, err
		}

		if emitter == nil {
			return nil, nil
		}

		return func(ctx context.Context, _ websocket.AsyncRead) (<-chan WebsocketEvent[RESP], error) {
			return emitter(ctx)
		}, nil
	}
}

func WebsocketHandler[REQ, RESP any](fn WebsocketHandlerFunc[REQ, RESP]) gin.HandlerFunc {
	const pingInterval = 30 * time.Second
	return func(ctx *gin.Context) {
		var req Request[REQ]

		if !bindAndValidate(ctx, &req) {
			return
		}

		var err error
		req.WS, err = websocket.Upgrade(ctx.Writer, ctx.Request, &websocket.Config{
			WriteTimeout: time.Second * 30,
			ReadTimeout:  time.Second * 30,
		})
		if err != nil {
			handleRequestError(ctx, fmt.Errorf("websocket upgrade error: %w", err))
			return
		}
		defer req.WS.Close()

		emitter, respErr := fn(ctx, &req)
		if respErr != nil {
			ctx.Error(fmt.Errorf("websocket handler error: %w", respErr))
			// Do not send HTTP response as the websocket is already upgraded.
			return
		}

		if emitter == nil {
			slog.WarnContext(ctx, "websocket handler returned nil emitter without error",
				"path", ctx.FullPath(),
				"method", ctx.Request.Method,
			)
			return
		}

		// We use only async reader, without writer here, as we control writing below.
		go req.WS.Reader(ctx)

		pinger := time.NewTicker(pingInterval)
		defer pinger.Stop()
		var lastEvent time.Time

		source, err := emitter(ctx, req.WS)
		for ctx.Err() == nil {
			select {
			case <-ctx.Done():
				return

			case <-req.WS.Done():
				return

			case <-pinger.C:
				if lastEvent.IsZero() || time.Since(lastEvent) >= pingInterval {
					if err := req.WS.Ping(); err != nil {
						slog.DebugContext(ctx, "websocket ping error", "error", err)
					}
				}

			case event, ok := <-source:
				if !ok {
					return
				}

				if event.Err != nil {
					errResp := ResponseErrorBody{
						Err:          event.Err,
						ErrorMessage: event.Err.Error(),
						Code:         ErrCodeServerWebsocketReadFailed,
					}

					ctx.Error(fmt.Errorf("websocket event error: %w", event.Err))
					websocket.WriteJSONMessage(req.WS, &errResp)
					return
				}

				writeErr := websocket.WriteJSONMessage(req.WS, event.Data)
				if writeErr != nil {
					ctx.Error(fmt.Errorf("websocket write message error: %w", writeErr))
					return
				}
				lastEvent = time.Now()
			}
		}
	}
}

func StreamHandler[REQ, RESP any](fn StreamHandlerFunc[REQ, RESP]) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var req Request[REQ]

		if !bindAndValidate(ctx, &req) {
			return
		}

		emitter, respErr := fn(ctx.Request.Context(), &req)
		if respErr != nil {
			handleRequestError(ctx, respErr)
			return
		}

		if emitter == nil {
			slog.WarnContext(ctx, "stream handler returned nil emitter without error",
				"path", ctx.FullPath(),
				"method", ctx.Request.Method,
			)
			ctx.Status(http.StatusNoContent)
			return
		}

		source, err := emitter(ctx)
		if err != nil {
			respErrTyped := Error(fmt.Errorf("emitter failed: %w", err), ErrCodeServerInternal, http.StatusInternalServerError)
			respErrTyped.render(ctx)
			return
		}

		ctx.Stream(func(io.Writer) (keepOpen bool) {
			select {
			case <-ctx.Request.Context().Done():
				return false

			case <-ctx.Done():
				return false

			case event, ok := <-source:
				if !ok {
					return false
				}

				if event.Err != nil {
					ctx.Error(fmt.Errorf("stream event error: %w", event.Err))
					ctx.SSEvent(cmp.Or(event.Type, "error"), event.Err.Error())
					return false
				}

				ctx.Render(-1, sse.Event{
					Event: event.Type,
					Id:    event.ID,
					Data:  event.Data,
				})
			}
			return true
		})
	}
}

func (r *Request[REQ]) parse(ctx *gin.Context) *Request[REQ] {
	r.Context = ctx
	r.bindings = make(map[requestDataBinding]struct{}, 5)
	r.Data = new(REQ)
	r.Token = authGetToken(ctx)

	elem := reflect.TypeOf(r.Data).Elem()
	if elem.Kind() != reflect.Struct {
		slog.ErrorContext(ctx, "request data is not a struct", "type", fmt.Sprintf("%T", r.Data))
		panic("request data is not a struct")
	}
	r.parseStruct(elem)

	return r
}

func (r *Request[REQ]) parseStruct(elem reflect.Type) {
	const enabled = "true"
	fieldCount := elem.NumField()
	for i := range fieldCount {
		field := elem.Field(i)
		tag := field.Tag
		if tag.Get("required") == enabled {
			r.requiredFields = append(r.requiredFields, field.Name)
		}
		if field.Anonymous && field.Type.Kind() == reflect.Struct {
			var m NoAuthRequired
			r.allowUnauthorized = r.allowUnauthorized || field.Type == reflect.TypeOf(m)
			r.parseStruct(field.Type)
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
				r.bindings[bindingQuery] = struct{}{}
			}
		}
		if tag.Get("formMultipart") != "" {
			r.bindings[bindingFormMultipart] = struct{}{}
		}
	}
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
