// SPDX-License-Identifier: ice License 1.0

package fixture

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	h2ec "github.com/ice-blockchain/go/src/net/http"
	"github.com/ice-blockchain/heimdall/cmd/heimdall-token-analytics/server/websocket"
)

type (
	h2WebsocketClient struct {
		conn         net.Conn
		closeChannel chan struct{}
		closeMx      sync.Mutex
		closed       bool
	}
	h2Stream struct {
		w    *io.PipeWriter
		resp *h2ec.Response
	}
)

func newH2Stream(w *io.PipeWriter, resp *h2ec.Response) *h2Stream {
	return &h2Stream{
		w:    w,
		resp: resp,
	}
}

func (s *h2Stream) Read(p []byte) (n int, err error) {
	return s.resp.Body.Read(p)
}

func (s *h2Stream) Write(p []byte) (n int, err error) {
	return s.w.Write(p)
}

func (s *h2Stream) WriteByte(p byte) (err error) {
	n, err := s.w.Write([]byte{p})
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("expected 1 written byte got %v", n)
	}
	return nil
}

func (s *h2Stream) Close() error {
	return errors.Join(s.w.Close(), s.resp.Body.Close())
}

func (s *h2Stream) LocalAddr() net.Addr {
	return nil
}

func (s *h2Stream) RemoteAddr() net.Addr {
	return nil
}

func (s *h2Stream) SetDeadline(t time.Time) error {
	return nil
}

func (s *h2Stream) SetReadDeadline(t time.Time) error {
	return nil
}

func (s *h2Stream) SetWriteDeadline(t time.Time) error {
	return nil
}

func newH2WebsocketClient(_ context.Context, conn net.Conn) *h2WebsocketClient {
	return &h2WebsocketClient{
		conn:         conn,
		closeChannel: make(chan struct{}, 1),
	}
}

func (w *h2WebsocketClient) WriteMessage(messageType int, data []byte) error {
	var err error
	w.closeMx.Lock()
	if w.closed {
		w.closeMx.Unlock()
		return nil
	}
	w.closeMx.Unlock()

	wErr := wsutil.WriteClientMessage(w.conn, ws.OpCode(messageType), data)
	if isConnClosedErr(wErr) {
		wErr = nil
	}
	if err = errors.Join(err, wErr); err != nil {
		return fmt.Errorf("failed to write data to websocket: %w", err)
	}

	if flusher, ok := w.conn.(http.Flusher); ok {
		flusher.Flush()
	}
	return nil
}

func (w *h2WebsocketClient) Writer(ctx context.Context) {
	<-ctx.Done()
}

func (w *h2WebsocketClient) Reader(ctx context.Context) {
	<-ctx.Done()
}

func (w *h2WebsocketClient) ReadMessage() (messageType int, p []byte, err error) {
	msgBytes, typ, err := wsutil.ReadServerData(w.conn)
	if err != nil {
		return int(typ), msgBytes, err
	}
	if typ == ws.OpPing {
		err = wsutil.WriteClientMessage(w.conn, ws.OpPong, nil)
		if err == nil {
			return w.ReadMessage()
		}

		return int(typ), msgBytes, err
	}

	return int(typ), msgBytes, err
}

func (w *h2WebsocketClient) Close() error {
	w.closeMx.Lock()
	if w.closed {
		w.closeMx.Unlock()

		return nil
	}
	w.closed = true
	close(w.closeChannel)
	w.closeMx.Unlock()
	wErr := wsutil.WriteClientMessage(w.conn, ws.OpClose, ws.NewCloseFrameBody(ws.StatusNormalClosure, ""))
	err := w.conn.Close()

	return errors.Join(wErr, err)
}

func (c *h2WebsocketClient) Metadata() websocket.Metadata {
	slog.Error("meta data not implemented for http2 websocket client fixture")
	return nil
}

func (c *h2WebsocketClient) Done() <-chan struct{} {
	return c.closeChannel
}

func (c *h2WebsocketClient) WriteQ() chan<- websocket.Frame {
	slog.Error("write q not implemented for http2 websocket client fixture")
	return nil
}

func (c *h2WebsocketClient) ReadQ() <-chan websocket.Frame {
	slog.Error("read q not implemented for http2 websocket client fixture")
	return nil
}

func NewWebsocketClientHTTP2(ctx context.Context, httpClient *h2ec.Client, urlStr string) (websocket.Connection, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse url %q: %w", urlStr, err)
	}

	switch u.Scheme {
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	case "http", "https":
	default:
		return nil, fmt.Errorf("unsupported url scheme %q", u.Scheme)
	}

	h := http.Header{}
	h.Set("Sec-Websocket-Version", "13")
	bodyr, bodyw := io.Pipe()
	req := &h2ec.Request{
		Method: http.MethodConnect,
		Header: h2ec.Header(h),
		Proto:  "websocket",
		Host:   u.Host,
		URL:    u,
		Body:   bodyr,
	}
	req = req.WithContext(ctx)

	rsp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform http2 websocket upgrade request: %w", err)
	}

	if rsp.StatusCode < 200 || rsp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status code: %d", rsp.StatusCode)
	}

	c := newH2WebsocketClient(ctx, newH2Stream(bodyw, rsp))
	go func() {
		defer c.Close()
		c.Writer(ctx)
	}()

	return c, nil
}

func isConnClosedErr(err error) bool {
	return err != nil &&
		(errors.Is(err, syscall.EPIPE) ||
			errors.Is(err, syscall.ECONNRESET) ||
			errors.Is(err, h2ec.Http2errClientDisconnected) ||
			errors.Is(err, h2ec.Http2errStreamClosed) ||
			errors.Is(err, io.ErrClosedPipe) ||
			strings.Contains(err.Error(), "convert stream error 386759528") ||
			strings.Contains(err.Error(), "use of closed network connection"))
}
