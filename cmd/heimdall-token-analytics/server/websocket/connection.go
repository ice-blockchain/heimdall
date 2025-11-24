// SPDX-License-Identifier: ice License 1.0

package websocket

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsflate"
	"github.com/gobwas/ws/wsutil"

	h2ec "github.com/ice-blockchain/go/src/net/http"
)

type (
	Metadata interface {
		Set(key string, value any)
		Get(key string) (value any, exists bool)
		Range() iter.Seq2[string, any]
		Delete(key string) (oldValue any, loaded bool)
		Clear()
	}
	AsyncRead interface {
		Metadata() Metadata
		ReadQ() <-chan Frame
		Done() <-chan struct{}
	}
	AsyncWrite interface {
		Metadata() Metadata
		WriteQ() chan<- Frame
		Done() <-chan struct{}
	}
	AsyncReadWrite interface {
		AsyncRead
		AsyncWrite
		io.Closer
	}
	Connection interface {
		AsyncReadWrite

		Writer(ctx context.Context)
		Reader(ctx context.Context)

		// WriteMessage writes a single message with the given message type and data to the websocket connection.
		// It does not use internal channels and buffers.
		WriteMessage(messageType int, data []byte) (err error)

		// ReadMessage reads a single message from the websocket connection.
		// It does not use internal channels and buffers.
		ReadMessage() (messageType int, p []byte, err error)
	}
	Frame struct {
		Type int    // MessageTypeText or MessageTypeBinary.
		Data []byte // Payload data.
		Err  error  // Error encountered while reading/writing the frame.
	}
	Config struct {
		handshake    ws.Handshake  // Handshake information from the upgrade request.
		WriteTimeout time.Duration // Write timeout duration.
		ReadTimeout  time.Duration // Read timeout duration.
	}

	framer     func(int, []byte) (ws.Frame, error)
	connection struct {
		conn           net.Conn      // Underlying websocket connection.
		wrErr          error         // Last write error.
		out            chan Frame    // Outgoing message channel.
		in             chan Frame    // Incoming message channel.
		closeChannel   chan struct{} // Channel to signal closure.
		framer         framer        // Function to create frames, with compression if needed.
		metadataHander Metadata      // Metadata storage.
		writeTimeout   time.Duration // Write timeout duration.
		readTimeout    time.Duration // Read timeout duration.
		wrErrMx        sync.Mutex    // Mutex to protect wrErr.
		closed         atomic.Bool   // Indicates if the connection is closed.
	}
)

const (
	// Text message.
	MessageTypeText = int(ws.OpText)

	// Binary message.
	MessageTypeBinary = int(ws.OpBinary)

	// Buffer up to 50 messages before reader/writer goroutines block.
	websocketChanBufferSize = 50
	// Compress messages larger than this threshold.
	websocketCompressThresholdBytes = 256
	// Interval between pings to the client to keep the connection alive.
	websocketPingInterval = time.Minute
)

func newConnection(_ context.Context, conn net.Conn, conf *Config) *connection {
	wt := &connection{
		conn:         conn,
		closeChannel: make(chan struct{}, 1),
		out:          make(chan Frame, websocketChanBufferSize),
		in:           make(chan Frame, websocketChanBufferSize),
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

func (w *connection) Done() <-chan struct{} {
	return w.closeChannel
}

func (w *connection) WriteMessage(messageType int, data []byte) (err error) {
	select {
	case <-w.closeChannel:
		return nil
	default:
		frame, err := w.framer(messageType, data)
		if err != nil {
			return fmt.Errorf("failed to create websocket frame: %w", err)
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
			return fmt.Errorf("websocket write failed: %w", err)
		}

		if flusher, ok := w.conn.(http.Flusher); ok {
			flusher.Flush()
		}

		return nil
	}
}

// Writer listens on the out channel and writes messages to the websocket connection.
// It's lanched as a separate goroutine from the server's HandleWS method.
func (w *connection) Writer(ctx context.Context) {
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
			case w.out <- Frame{
				Type: int(ws.OpPing),
			}:
			default:
				// If the out channel is full, we skip sending the ping to avoid blocking.
			}

		case msg := <-w.out:
			if isConnClosedErr(w.wrErr) {
				return
			}

			if err := w.WriteMessage(msg.Type, msg.Data); err != nil {
				slog.ErrorContext(ctx, "failed to write message to websocket", "error", err)
			}
		}
	}
}

// Reader listens on the websocket connection and reads messages into the in channel.
// It's lanched as a separate goroutine from the server's HandleWS method.
func (w *connection) Reader(ctx context.Context) {
	for ctx.Err() == nil {
		msgType, msgBytes, err := w.ReadMessage()
		select {
		case <-w.closeChannel:
			return

		case <-ctx.Done():
			return

		case w.in <- Frame{
			Type: msgType,
			Data: msgBytes,
			Err:  err,
		}:
		}

		if isConnClosedErr(err) {
			return
		}
	}
}

func (w *connection) ReadQ() <-chan Frame {
	return w.in
}

func (w *connection) WriteQ() chan<- Frame {
	return w.out
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

func (w *connection) Metadata() Metadata {
	return w.metadataHander
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

func WriteJSONMessage(conn Connection, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("json marshal error: %w", err)
	}
	return conn.WriteMessage(MessageTypeText, data)
}
