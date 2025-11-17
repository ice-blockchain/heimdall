// SPDX-License-Identifier: ice License 1.0

package websocket

import (
	"bytes"
	"compress/flate"
	"context"
	"io"
	"iter"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsflate"
	"github.com/gobwas/ws/wsutil"

	h2ec "github.com/ice-blockchain/go/src/net/http"
)

type (
	Handler interface {
		HandleWS(ctx context.Context, stream Connection)
	}
	Reader interface {
		Metadata() MetaData
		ReadMessage() (messageType int, p []byte, err error)
	}
	Writer interface {
		Metadata() MetaData
		WriteMessage(ctx context.Context, messageType int, data []byte) error
	}
	ReaderWriter interface {
		Reader
		Writer
	}

	MetaData interface {
		Set(key string, value any)
		Get(key string) (value any, exists bool)
		Range() iter.Seq2[string, any]
		Delete(key string) (oldValue any, loaded bool)
		Clear()
	}
	Connection interface {
		Writer
		Reader
		io.Closer

		Write(ctx context.Context)
	}
	Config struct {
		handshake    ws.Handshake
		WriteTimeout time.Duration
		ReadTimeout  time.Duration
	}

	connection struct {
		conn         net.Conn
		wrErr        error
		out          chan wsWrite
		closeChannel chan struct{}
		framer       func(int, []byte) (ws.Frame, error)
		metadataHander
		writeTimeout time.Duration
		readTimeout  time.Duration
		wrErrMx      sync.Mutex
		closed       atomic.Bool
	}

	wsWrite struct {
		data   []byte
		opCode int
	}
)

const (
	// Text message.
	MessageTypeText = int(ws.OpText)

	// Binary message.
	MessageTypeBinary = int(ws.OpBinary)

	// Buffer up to 50 messages before WriteMessage calls start to block.
	websocketWriteBufferSize = 50
	// Compress messages larger than this threshold.
	websocketCompressThresholdBytes = 256
	// Interval between pings to the client to keep the connection alive.
	websocketPingInterval = time.Minute
)

func newConnection(ctx context.Context, conn net.Conn, conf *Config) *connection {
	wt := &connection{
		conn:         conn,
		closeChannel: make(chan struct{}, 1),
		out:          make(chan wsWrite, websocketWriteBufferSize),
		readTimeout:  conf.ReadTimeout,
		writeTimeout: conf.WriteTimeout,
		framer: func(opCode int, data []byte) (ws.Frame, error) {
			return ws.NewFrame(ws.OpCode(opCode), true, data), nil
		},
	}

	wt.initExtensions(conf.handshake)

	return wt
}

func (w *connection) initCompression() {
	w.framer = func(opCode int, data []byte) (ws.Frame, error) {
		frame := ws.NewFrame(ws.OpCode(opCode), true, data)
		if (opCode == MessageTypeText || opCode == MessageTypeBinary) && len(data) > websocketCompressThresholdBytes {
			return compressFrame(frame)
		}
		return frame, nil
	}
}

func (w *connection) initExtensions(handshake ws.Handshake) {
	var hasCompression bool

	for _, ext := range handshake.Extensions {
		if bytes.Equal(ext.Name, wsflate.ExtensionNameBytes) {
			hasCompression = true
		}
	}

	if hasCompression {
		w.initCompression()
	}
}

func (w *connection) writeMessageToWebsocket(messageType int, data []byte) (err error) {
	if w.Closed() {
		return nil
	}

	select {
	case <-w.closeChannel:
		return nil
	default:
		frame, err := w.framer(messageType, data)
		if err != nil {
			return errors.Wrap(err, "failed to create websocket frame")
		}

		if w.writeTimeout > 0 {
			err = w.conn.SetWriteDeadline(time.Now().Add(w.writeTimeout))
		}
		wErr := ws.WriteFrame(w.conn, frame)
		w.wrErrMx.Lock()
		w.wrErr = wErr
		w.wrErrMx.Unlock()
		if isConnClosedErr(wErr) {
			wErr = nil
		}

		if err = errors.Join(err, wErr); err != nil {
			return errors.Wrap(err, "failed to write data to websocket")
		}

		if flusher, ok := w.conn.(http.Flusher); ok {
			flusher.Flush()
		}

		return nil
	}
}

func (w *connection) WriteMessage(ctx context.Context, messageType int, data []byte) error {
	select {
	case <-w.closeChannel:
		return nil

	case <-ctx.Done():
		return ctx.Err()

	default:
		w.wrErrMx.Lock()
		if isConnClosedErr(w.wrErr) {
			w.wrErrMx.Unlock()
			return w.Close()
		}
		w.wrErrMx.Unlock()
		select {
		case w.out <- wsWrite{
			opCode: messageType,
			data:   data,
		}:
		case <-ctx.Done():
			return errors.Wrapf(ctx.Err(), "cannot write message type %d with size %d to websocket",
				messageType, len(data))
		}
	}

	return nil
}

// Write listens on the out channel and writes messages to the websocket connection.
// It's lanched as a separate goroutine from the server's HandleWS method.
func (w *connection) Write(ctx context.Context) {
	pingTicker := time.NewTicker(websocketPingInterval)
	defer pingTicker.Stop()

	for ctx.Err() == nil {
		select {
		case <-w.closeChannel:
			return

		case <-ctx.Done():
			return

		case <-pingTicker.C:
			select {
			case w.out <- wsWrite{
				opCode: int(ws.OpPing),
				data:   nil,
			}:
			default:
				// If the out channel is full, we skip sending the ping to avoid blocking.
			}

		case msg := <-w.out:
			if isConnClosedErr(w.wrErr) {
				return
			}

			if err := w.writeMessageToWebsocket(msg.opCode, msg.data); err != nil {
				slog.ErrorContext(ctx, "failed to write message to websocket", "error", err)
			}
		}
	}
}

func (w *connection) readFrame() ([]byte, ws.OpCode, error) {
	const want = ws.OpText | ws.OpBinary
	var msg wsflate.MessageState
	controlHandler := wsutil.ControlFrameHandler(w.conn, ws.StateServerSide)
	rd := wsutil.Reader{
		Source:         w.conn,
		State:          ws.StateServerSide | ws.StateExtended,
		OnIntermediate: controlHandler,
		Extensions: []wsutil.RecvExtension{
			&msg,
		},
	}
	for !w.closed.Load() {
		hdr, err := rd.NextFrame()
		if err != nil {
			return nil, 0, err
		}
		if hdr.OpCode.IsControl() {
			if err := controlHandler(hdr, &rd); err != nil {
				return nil, 0, err
			}
			continue // Continue to the next frame if control frame is received.
		}
		if hdr.OpCode&want == 0 {
			if err := rd.Discard(); err != nil {
				return nil, 0, err
			}
			continue // Continue to the next frame if the received frame is not of the expected type.
		}

		var payloadReader io.Reader = &rd
		if msg.IsCompressed() {
			payloadReader = wsflate.NewReader(&rd, func(r io.Reader) wsflate.Decompressor {
				return flate.NewReader(r)
			})
		}

		bts, err := io.ReadAll(payloadReader)

		return bts, hdr.OpCode, err
	}

	return nil, 0, errors.New("websocket connection closed")
}

func (w *connection) ReadMessage() (messageType int, p []byte, err error) {
	if w.readTimeout > 0 {
		_ = w.conn.SetReadDeadline(time.Now().Add(w.readTimeout))
	}
	msgBytes, typ, err := w.readFrame()
	if err != nil {
		return int(typ), msgBytes, err
	}
	if typ == ws.OpPing {
		_, err = w.conn.Write(ws.CompiledPong)
		if err == nil {
			return w.ReadMessage()
		}

		return int(typ), msgBytes, err
	}

	return int(typ), msgBytes, err
}

func (w *connection) Closed() bool {
	return w.closed.Load()
}

func (w *connection) Close() error {
	if w.closed.Load() {
		return nil
	}

	if !w.closed.CompareAndSwap(false, true) {
		return nil
	}

	close(w.closeChannel)

	var wErr error
	if w.wrErr == nil || !isConnClosedErr(w.wrErr) {
		_, wErr = w.conn.Write(ws.CompiledCloseNormalClosure)
		if wErr != nil && isConnClosedErr(wErr) {
			wErr = nil
		}
	}
	clErr := w.conn.Close()
	if clErr != nil && isConnClosedErr(clErr) {
		clErr = nil
	}

	return errors.Join(wErr, clErr)
}

func isConnClosedErr(err error) bool {
	return err != nil &&
		(errors.Is(err, syscall.EPIPE) ||
			errors.Is(err, syscall.ECONNRESET) ||
			errors.Is(err, h2ec.Http2errClientDisconnected) ||
			errors.Is(err, h2ec.Http2errStreamClosed) ||
			strings.Contains(err.Error(), "convert stream error 386759528") ||
			strings.Contains(err.Error(), "canceled by remote with error code 256") ||
			strings.Contains(err.Error(), "use of closed network connection"))
}
