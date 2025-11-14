// SPDX-License-Identifier: ice License 1.0

package server

import (
	"context"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/heimdall/token-analytics/server/websocket"
	"github.com/ice-blockchain/heimdall/token-analytics/server/websocket/fixture"
)

func TestServerHandleWebsocketHTTP2(t *testing.T) {
	t.Parallel()

	srv := helperNewServer(t, 0)

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(t.Context())

	received := make(chan string, 1)
	wg.Go(func() { helperNewWebsocketServerHandler(t, ctx, srv, received) })

	wsURL := "wss://localhost:" + strconv.Itoa(helperServerWaitForTCPPort(t, srv)) + "/"

	conn, err := fixture.NewWebsocketClientHTTP2(ctx, testInsecureClientHTTP2, wsURL)
	require.NoError(t, err)
	require.NotNil(t, conn)

	const payload = "hello-http2"
	require.NoError(t, conn.WriteMessage(ctx, websocket.MessageTypeText, []byte(payload)))

	got := <-received
	require.Equal(t, payload, got)

	_, recvBack, err := conn.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, payload, string(recvBack))

	require.NoError(t, conn.Close())

	cancel()
	wg.Wait()
}
