// SPDX-License-Identifier: ice License 1.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gin-contrib/sse"
	"github.com/gin-gonic/gin"
	wsClient "github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/heimdall/cmd/heimdall-token-analytics/server/websocket"
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

	if resp.Body.Len() > 0 {
		err := json.Unmarshal(resp.Body.Bytes(), result.Data)
		require.NoError(t, err, "failed to unmarshal response: %s", resp.Body.String())
	}

	return &result
}

func helperDoRequest[T any](t *testing.T, handler http.Handler, method, path string, body io.Reader) *Response[T] {
	t.Helper()

	return helperDoRequestWithAuth[T](t, handler, "", method, path, body)
}

func helperDoRequestWithAuth[T any](t *testing.T, handler http.Handler, token, method, path string, body io.Reader) *Response[T] {
	t.Helper()

	w := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(t.Context(), method, path, body)
	if token != "" {
		req.Header.Set(authHeaderName, token)
	}
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

func TestRequestBinding(t *testing.T) {
	t.Parallel()

	type RequestTestStruct struct {
		Foo  []string `form:"foo"  required:"true"`
		Item string   `uri:"item"  required:"true"`
	}

	r := helperNewRouter(t)
	var (
		ExpectedItem = "my_item"
		ExpectedFoo  = []string{"a", "b", "c"}
	)
	r.GET("/ok/:item", RootHandler(func(ctx context.Context, r *Request[RequestTestStruct]) (*Response[int], error) {
		var answer int = 42
		require.NotNil(t, r.Data)
		require.Equal(t, ExpectedItem, r.Data.Item)
		require.ElementsMatch(t, ExpectedFoo, r.Data.Foo)
		return OK(&answer), nil
	}))

	t.Run("OK", func(t *testing.T) {
		resp := helperDoRequest[int](t, r, http.MethodGet, "/ok/"+ExpectedItem+"?foo=a&foo=b&foo=c", http.NoBody)
		require.Equal(t, http.StatusOK, resp.Code)
		require.NotNil(t, resp.Data)
		require.Equal(t, 42, *resp.Data)
	})
	t.Run("Error", func(t *testing.T) {
		resp := helperDoRequest[ResponseErrorBody](t, r, http.MethodGet, "/ok/"+ExpectedItem, http.NoBody)
		require.Equal(t, http.StatusUnprocessableEntity, resp.Code)
	})
}

type TestResponseRecorder struct {
	*httptest.ResponseRecorder
	closeChannel chan bool
}

func (r *TestResponseRecorder) CloseNotify() <-chan bool {
	return r.closeChannel
}

func newTestResponseRecorder() *TestResponseRecorder {
	return &TestResponseRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		closeChannel:     make(chan bool, 1),
	}
}

func TestRequestStreamEvents(t *testing.T) {
	t.Parallel()

	type RequestTestStruct struct {
		Start int `form:"start"  required:"true"`
	}

	type EventPayload struct {
		Value int `json:"value"`
	}

	const eventCount = 5
	errSim := errors.New("simulated stream error")

	r := helperNewRouter(t)
	r.GET("/stream", StreamMiddleware(), StreamHandler(func(ctx context.Context, r *Request[RequestTestStruct]) (StreamEventEmitter[EventPayload], error) {
		require.NotNil(t, r.Data)

		return func(ctx context.Context) (<-chan StreamEvent[EventPayload], error) {
			events := make(chan StreamEvent[EventPayload], eventCount)
			go func() {
				defer func() {
					t.Logf("closing stream events")
					close(events)
				}()

				t.Logf("starting to emit stream events from %d", r.Data.Start)
				for i := range eventCount {
					if r.Data.Start == 42 && i == 2 {
						t.Logf("emitting error event")
						events <- StreamEvent[EventPayload]{
							Err: errSim,
						}
						return
					}
					select {
					case <-ctx.Done():
						t.Logf("stream context done: %v", ctx.Err())
						return

					case <-time.After(50 * time.Millisecond):
						select {
						case events <- StreamEvent[EventPayload]{
							Type: "message",
							ID:   fmt.Sprintf("id_%d", r.Data.Start+i),
							Data: &EventPayload{Value: r.Data.Start + i},
						}:
							t.Logf("stream event sent: %d", r.Data.Start+i)

						default:
							t.Logf("stream event dropped: %d", r.Data.Start+i)
							return
						}
					}
				}
			}()
			return events, nil
		}, nil
	}))

	t.Run("Stream all events", func(t *testing.T) {
		const idxStart = 10
		rr := newTestResponseRecorder()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "/stream?start="+strconv.Itoa(idxStart), http.NoBody)
		require.NoError(t, err)

		r.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		require.Equal(t, sse.ContentType, rr.Header().Get("Content-Type"))

		events, err := sse.Decode(rr.Body)
		require.NoError(t, err)
		require.Len(t, events, eventCount)

		for i, event := range events {
			require.Equal(t, "message", event.Event)
			require.Equal(t, fmt.Sprintf("id_%d", idxStart+i), event.Id)
			require.IsType(t, "", event.Data)

			var payload EventPayload
			err := json.Unmarshal([]byte(event.Data.(string)), &payload)
			require.NoError(t, err)
			require.Equal(t, idxStart+i, payload.Value)
		}
	})
	t.Run("Error during events stream", func(t *testing.T) {
		const idxStart = 42
		rr := newTestResponseRecorder()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "/stream?start="+strconv.Itoa(idxStart), http.NoBody)
		require.NoError(t, err)

		r.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		require.Equal(t, sse.ContentType, rr.Header().Get("Content-Type"))

		events, err := sse.Decode(rr.Body)
		require.NoError(t, err)
		require.Len(t, events, 3) // 2 normal events + 1 error event.

		for i, event := range events[:2] {
			require.Equal(t, "message", event.Event)
			require.Equal(t, fmt.Sprintf("id_%d", idxStart+i), event.Id)
			require.IsType(t, "", event.Data)

			var payload EventPayload
			err := json.Unmarshal([]byte(event.Data.(string)), &payload)
			require.NoError(t, err)
			require.Equal(t, idxStart+i, payload.Value)
		}

		require.Equal(t, "error", events[2].Event)
		require.EqualValues(t, events[2].Data, errSim.Error())
	})
}

func TestRequestParseAuth(t *testing.T) {
	t.Parallel()

	t.Run("Parse with no auth required", func(t *testing.T) {
		type RequestTestStruct struct {
			NoAuthRequired
			Foo string `form:"foo" required:"true"`
		}

		var req Request[RequestTestStruct]

		req.parse(nil)

		require.True(t, req.allowUnauthorized)
		require.Contains(t, req.bindings, bindingQuery)
		require.Equal(t, []string{"Foo"}, req.requiredFields)
	})
	t.Run("Parse regular", func(t *testing.T) {
		type RequestTestStruct struct {
			Foo int `form:"foo" required:"true"`
		}

		var req Request[RequestTestStruct]

		req.parse(nil)

		require.False(t, req.allowUnauthorized)
		require.Contains(t, req.bindings, bindingQuery)
		require.Equal(t, []string{"Foo"}, req.requiredFields)
	})
}

func TestRequestWebsocketReadWrite(t *testing.T) {
	t.Parallel()

	type RequestTestStruct struct {
		Foo int `form:"foo"`
	}

	type EventPayload struct {
		Msg string `json:"msg"`
	}

	var wg sync.WaitGroup
	r := helperNewRouter(t)
	r.GET("/ws", WebsocketHandler(func(ctx context.Context, r *Request[RequestTestStruct]) (WebsocketEventEmitter[EventPayload], error) {
		require.NotNil(t, r.Data)

		return func(ctx context.Context, ws websocket.AsyncRead) (<-chan WebsocketEvent[EventPayload], error) {
			events := make(chan WebsocketEvent[EventPayload], 1)
			wg.Go(func() {
				defer close(events)

				for ctx.Err() == nil {
					select {
					case <-ctx.Done():
						t.Logf("websocket context done: %v", ctx.Err())
						return

					case <-ws.Done():
						t.Logf("websocket connection closed")
						return

					case msg, ok := <-ws.ReadQ():
						require.True(t, ok)
						t.Logf("received websocket message: %q", string(msg.Data))
						select {
						case events <- WebsocketEvent[EventPayload]{
							Data: &EventPayload{Msg: string(msg.Data)},
						}:
							t.Logf("websocket event sent: %q", string(msg.Data))

						default:
							t.Logf("websocket event dropped: %q", string(msg.Data))
							return
						}
					}
				}
			})
			return events, nil
		}, nil
	}))

	testServer := httptest.NewServer(r)

	d := wsClient.Dialer{}
	wsURL := "ws" + strings.TrimPrefix(testServer.URL, "http") + "/ws"
	conn, _, err := d.DialContext(t.Context(), wsURL, nil)
	require.NoError(t, err)
	require.NotNil(t, conn)

	t.Run("Read and Write", func(t *testing.T) {
		const eventCount = 7

		for i := range eventCount {
			payload := fmt.Sprintf("hello-%d", i)
			require.NoError(t, conn.WriteMessage(wsClient.TextMessage, []byte(payload)))

			_, recvBack, err := conn.ReadMessage()
			t.Logf("received back message: %s", string(recvBack))
			require.NoError(t, err)

			var event EventPayload
			err = json.Unmarshal(recvBack, &event)
			require.NoError(t, err)
			require.Equal(t, payload, event.Msg)
		}
	})

	require.NoError(t, conn.Close())
	testServer.Close()
	wg.Wait()
}

func TestRequestSameHandlerStreamWebsocket(t *testing.T) {
	t.Parallel()

	type RequestTestStruct struct {
		Start int `form:"start" required:"true"`
	}

	type EventPayload struct {
		Msg   string `json:"msg"`
		Value int    `json:"magic"`
	}

	var wg sync.WaitGroup

	const eventCount = 4
	serverStreamHandler := func(ctx context.Context, r *Request[RequestTestStruct]) (StreamEventEmitter[EventPayload], error) {
		require.NotNil(t, r.Data)

		return func(ctx context.Context) (<-chan StreamEvent[EventPayload], error) {
			events := make(chan StreamEvent[EventPayload], eventCount)
			go func() {
				defer func() {
					t.Logf("closing stream events")
					close(events)
				}()

				t.Logf("starting to emit stream events from %d", r.Data.Start)
				for i := range eventCount {
					select {
					case <-ctx.Done():
						t.Logf("stream context done: %v", ctx.Err())
						return

					case <-time.After(50 * time.Millisecond):
						select {
						case events <- StreamEvent[EventPayload]{
							Type: "message",
							ID:   fmt.Sprintf("id_%d", r.Data.Start+i),
							Data: &EventPayload{Value: r.Data.Start + i},
						}:
							t.Logf("stream event sent: %d", r.Data.Start+i)

						default:
							t.Logf("stream event dropped: %d", r.Data.Start+i)
							return
						}
					}
				}
			}()
			return events, nil
		}, nil
	}

	r := helperNewRouter(t)
	r.GET("/stream", StreamMiddleware(), StreamHandler(serverStreamHandler))
	r.GET("/ws", WebsocketHandler(Stream2WebsocketHandler(serverStreamHandler)))

	testServer := httptest.NewServer(r)

	t.Run("Websocket", func(t *testing.T) {
		d := wsClient.Dialer{}
		wsURL := "ws" + strings.TrimPrefix(testServer.URL, "http") + "/ws?start=100"
		conn, _, err := d.DialContext(t.Context(), wsURL, nil)
		require.NoError(t, err)
		require.NotNil(t, conn)

		for i := range eventCount {
			_, recvBack, err := conn.ReadMessage()
			t.Logf("received back message: %s", string(recvBack))
			require.NoError(t, err)

			var event EventPayload
			err = json.Unmarshal(recvBack, &event)
			require.NoError(t, err)
			require.EqualValues(t, 100+i, event.Value)
		}

		require.NoError(t, conn.Close())
	})
	t.Run("Stream", func(t *testing.T) {
		rr := newTestResponseRecorder()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "/stream?start=200", http.NoBody)
		require.NoError(t, err)

		r.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		require.Equal(t, sse.ContentType, rr.Header().Get("Content-Type"))

		events, err := sse.Decode(rr.Body)
		require.NoError(t, err)
		require.Len(t, events, eventCount)

		for i, event := range events {
			require.IsType(t, "", event.Data)

			var payload EventPayload
			err := json.Unmarshal([]byte(event.Data.(string)), &payload)
			require.NoError(t, err)
			require.EqualValues(t, 200+i, payload.Value)
		}
	})

	testServer.Close()
	wg.Wait()
}

func TestRequestStreamPing(t *testing.T) {
	t.Parallel()

	type RequestTestStruct struct {
		Dummy string `form:"dummy" required:"false"`
	}

	type EventPayload struct {
		Value int `json:"value"`
	}

	synctest.Test(t, func(t *testing.T) {
		const pingCount = 2
		r := helperNewRouter(t)

		r.GET("/stream-no-events", StreamMiddleware(), StreamHandler(func(ctx context.Context, r *Request[RequestTestStruct]) (StreamEventEmitter[EventPayload], error) {
			require.NotNil(t, r.Data)

			return func(ctx context.Context) (<-chan StreamEvent[EventPayload], error) {
				events := make(chan StreamEvent[EventPayload])
				return events, nil
			}, nil
		}))

		rr := newTestResponseRecorder()
		ctx, cancel := context.WithTimeout(t.Context(), (defaultPingInterval*pingCount)+10*time.Second)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "/stream-no-events", http.NoBody)
		require.NoError(t, err)

		r.ServeHTTP(rr, req)
		cancel()
		require.Equal(t, http.StatusOK, rr.Code)

		events, err := sse.Decode(rr.Body)
		require.NoError(t, err)
		require.Len(t, events, pingCount)

		for _, event := range events {
			require.Equal(t, "ping", event.Event)
			require.Equal(t, "ping", event.Data)
		}
	})
}
