// SPDX-License-Identifier: ice License 1.0

package server

import (
	"context"
	"strconv"
	"sync"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
)

func TestServerHandleWebsocketHTTP1(t *testing.T) {
	t.Parallel()

	srv := helperNewServer(t, 0)

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(t.Context())

	received := make(chan string, 1)
	wg.Go(func() { helperNewWebsocketServerHandler(t, ctx, srv, received) })

	d := websocket.Dialer{
		EnableCompression: true,
		TLSClientConfig:   testTLSConfig,
	}
	wsURL := "wss://localhost:" + strconv.Itoa(helperServerWaitForTCPPort(t, srv)) + "/"
	conn, _, err := d.DialContext(ctx, wsURL, nil)
	require.NoError(t, err)
	require.NotNil(t, conn)

	const payload = "hello-http1"
	require.NoError(t, conn.WriteMessage(websocket.TextMessage, []byte(payload)))

	got := <-received
	require.Equal(t, payload, got)

	_, recvBack, err := conn.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, payload, string(recvBack))

	require.NoError(t, conn.Close())

	cancel()
	wg.Wait()
}
