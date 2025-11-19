// SPDX-License-Identifier: ice License 1.0

package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	h2ec "github.com/ice-blockchain/go/src/net/http"
	"github.com/ice-blockchain/heimdall/cmd/heimdall-token-analytics/server/cert"
	"github.com/ice-blockchain/heimdall/cmd/heimdall-token-analytics/server/websocket"
)

var (
	testTLSConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	testInsecureClientHTTP1 = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: testTLSConfig,
		},
	}
	testInsecureClientHTTP2 = &h2ec.Client{
		Transport: &h2ec.Http2Transport{
			TLSClientConfig: testTLSConfig,
		},
	}
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)

	code := m.Run()

	testInsecureClientHTTP1.Transport.(*http.Transport).CloseIdleConnections()
	testInsecureClientHTTP2.Transport.(*h2ec.Http2Transport).CloseIdleConnections()

	if code == 0 {
		err := goleak.Find()
		if err != nil {
			fmt.Fprintf(os.Stderr, "goleak detected:\n%v\n", err)
			code = 1
		}
	}
	os.Exit(code)
}

func helperNewServer(t *testing.T, port uint32) *httpServer {
	t.Helper()

	srv := newServer(&Config{
		Debug: true,
		Port:  port,
		TLS:   cert.MustGenerateTLSConfigSelfSigned("test.local"),
	})
	require.NotNil(t, srv)

	return srv
}

type dummyWebsocketHandler struct {
	onMessage func(req []byte, err error) (resp []byte)
	testingT  testing.TB
}

func (d *dummyWebsocketHandler) HandleWS(ctx context.Context, stream websocket.ReaderWriter) {
	d.testingT.Helper()

	for ctx.Err() == nil {
		t, msgBytes, err := stream.ReadMessage()
		if err != nil {
			d.testingT.Logf("read message error: %v", err)
			d.onMessage(nil, err)
			break
		}
		d.testingT.Logf("received message: %s with opcode %v", string(msgBytes), t)
		if len(msgBytes) > 0 && t == websocket.MessageTypeText {
			resp := d.onMessage(msgBytes, err)
			if len(resp) > 0 {
				d.testingT.Logf("sending response: %s", string(resp))
				err = stream.WriteMessage(ctx, websocket.MessageTypeText, resp)
				require.NoError(d.testingT, err)
			}
		}
	}
}

func helperNewWebsocketHandler(t *testing.T, onMessage func([]byte, error) []byte) WebsocketHandler {
	t.Helper()

	return &dummyWebsocketHandler{
		onMessage: onMessage,
		testingT:  t,
	}
}

func helperNewWebsocketServerHandler(t *testing.T, ctx context.Context, srv Server, received chan<- string) {
	t.Helper()

	helperNewWebsocketServerHandlerWithPath(t, ctx, srv, "/", received)
}

func helperNewWebsocketServerHandlerWithPath(t *testing.T, ctx context.Context, srv Server, path string, received chan<- string) {
	t.Helper()

	srv.MustListenAndServe(ctx, func(i Router) {
		i.Websocket(path, nil, helperNewWebsocketHandler(t, func(msg []byte, err error) []byte {
			if msg == nil && err != nil {
				msg = []byte("error: " + err.Error())
			}
			select {
			case received <- string(msg):
			default:
				t.Fatal("failed to proxy message")
			}
			return msg
		}))
	})
}

func TestServerListenClose(t *testing.T) {
	t.Parallel()

	srv := helperNewServer(t, 0)

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(t.Context())

	wg.Go(func() {
		srv.MustListenAndServe(ctx, func(i Router) {
			i.GET("/health", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})
		})
	})

	t.Run("HTTP1", func(t *testing.T) {
		resp, err := testInsecureClientHTTP1.Get("https://localhost:" + strconv.Itoa(helperServerWaitForTCPPort(t, srv)) + "/health")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("HTTP2", func(t *testing.T) {
		resp, err := testInsecureClientHTTP2.Get("https://localhost:" + strconv.Itoa(helperServerWaitForTCPPort(t, srv)) + "/health")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	cancel()
	wg.Wait()
}

func helperServerWaitForTCPPort(t *testing.T, srv *httpServer) int {
	t.Helper()

	for {
		v := atomic.LoadUint32(&srv.Config.Port)
		if v != 0 {
			return int(v)
		}
		time.Sleep(time.Millisecond * 100)
	}
}
