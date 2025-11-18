// SPDX-License-Identifier: ice License 1.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func helperNewRouter(t *testing.T) *gin.Engine {
	t.Helper()

	return newServer(&Config{Debug: true}).Router
}

func helperUnmarshalResponse[T any](t *testing.T, resp *httptest.ResponseRecorder) *Response[T] {
	t.Helper()

	var result Response[T]
	result.Data = new(T)
	result.Code = resp.Code

	err := json.Unmarshal(resp.Body.Bytes(), result.Data)
	require.NoError(t, err, "failed to unmarshal response: %s", resp.Body.String())

	return &result
}

func helperDoRequest[T any](t *testing.T, handler http.Handler, method, path string, body io.Reader) *Response[T] {
	t.Helper()

	w := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(t.Context(), method, path, body)
	require.NoError(t, err, "failed to create request")

	handler.ServeHTTP(w, req)

	return helperUnmarshalResponse[T](t, w)
}

func TestRequestHandler(t *testing.T) {
	t.Parallel()

	type RequestTestStruct struct {
		Foo string
	}

	testErrNative := errors.New("test error")
	testErrInternal := errors.New("test internal error")

	r := helperNewRouter(t)
	r.GET("/native_error", RootHandler(func(ctx context.Context, r *Request[RequestTestStruct]) (*Response[RequestTestStruct], error) {
		return nil, Error(testErrNative, "TEST_ERROR_CODE", 499)
	}))
	r.GET("/internal_error", RootHandler(func(ctx context.Context, r *Request[RequestTestStruct]) (*Response[RequestTestStruct], error) {
		return nil, testErrInternal
	}))
	r.GET("/ok", RootHandler(func(ctx context.Context, r *Request[RequestTestStruct]) (*Response[RequestTestStruct], error) {
		return OK(&RequestTestStruct{Foo: "bar"}), nil
	}))

	t.Run("Native", func(t *testing.T) {
		resp := helperDoRequest[ResponseErrorBody](t, r, http.MethodGet, "/native_error", http.NoBody)
		require.Equal(t, 499, resp.Code)
		require.Equal(t, "TEST_ERROR_CODE", resp.Data.Code)
		require.Equal(t, testErrNative.Error(), resp.Data.ErrorMessage)
	})
	t.Run("Internal", func(t *testing.T) {
		resp := helperDoRequest[ResponseErrorBody](t, r, http.MethodGet, "/internal_error", http.NoBody)
		require.Equal(t, http.StatusInternalServerError, resp.Code)
		require.Equal(t, ErrCodeServerInternal, resp.Data.Code)
		require.Equal(t, testErrInternal.Error(), resp.Data.ErrorMessage)
	})
	t.Run("OK", func(t *testing.T) {
		resp := helperDoRequest[RequestTestStruct](t, r, http.MethodGet, "/ok", http.NoBody)
		require.Equal(t, http.StatusOK, resp.Code)
		require.Equal(t, "bar", resp.Data.Foo)
	})
}
