// SPDX-License-Identifier: ice License 1.0

package websocket

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"log/slog"
	"net"
	"net/http"

	"github.com/cockroachdb/errors"
	"github.com/gobwas/httphead"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsflate"
)

type (
	h2Upgrader struct {
		Protocol  func(string) bool
		Extension func(httphead.Option) bool
		Negotiate func(httphead.Option) (httphead.Option, error)
	}
)

const (
	headerSecVersionCanonical    = "Sec-Websocket-Version"
	headerSecProtocolCanonical   = "Sec-Websocket-Protocol"
	headerSecExtensionsCanonical = "Sec-Websocket-Extensions"
	headerSecKeyCanonical        = "Sec-Websocket-Key"
	headerSecAcceptCanonical     = "Sec-Websocket-Accept"
)

var (
	ErrBadProtocol     = errors.New(":protocol must be websocket")
	ErrHijack          = errors.New("http.ResponseWriter does not support hijack")
	ErrUpgradeInternal = errors.New("internal error during upgrade")
)

func newH2Upgrader() *h2Upgrader {
	e := wsflate.Extension{
		Parameters: wsflate.DefaultParameters,
	}
	return &h2Upgrader{
		Negotiate: e.Negotiate,
	}
}

func (u *h2Upgrader) Upgrade(req *http.Request, writer http.ResponseWriter) (conn net.Conn, rw *bufio.ReadWriter, hs ws.Handshake, err error) {
	if req.Proto != "websocket" {
		writer.WriteHeader(http.StatusBadRequest)
		return nil, nil, hs, ErrBadProtocol
	}

	switch w := writer.(type) {
	case http.Hijacker:
		conn, rw, err = w.Hijack()

	default:
		err = ErrHijack
		slog.ErrorContext(req.Context(), "failed to hijack connection for websocket over http2", "error", err)
		writer.WriteHeader(http.StatusInternalServerError)
	}

	if err != nil {
		return nil, nil, hs, errors.Wrap(err, "failed to hijack http2")
	}

	hs, err = u.syncWSProtocols(req)
	if err != nil {
		return nil, nil, hs, errors.Wrap(err, "failed to sync ws protocol and extensions")
	}

	nonce := req.Header.Get(headerSecKeyCanonical)
	if nonce != "" {
		writer.Header().Add(headerSecAcceptCanonical, calcAcceptFromNonce(nonce))
	}

	writer.Header().Add(headerSecProtocolCanonical, hs.Protocol)
	writer.Header().Add(headerSecVersionCanonical, "13")
	writer.WriteHeader(http.StatusOK)

	flusher, ok := writer.(http.Flusher)
	if ok {
		flusher.Flush()
	}

	return conn, rw, hs, err
}

func calcAcceptFromNonce(nonce string) string {
	var keyGUID = []byte("258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

	h := sha1.New()
	h.Write([]byte(nonce))
	h.Write(keyGUID)

	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func strSelectProtocol(h string, check func(string) bool) (ret string, ok bool) {
	ok = httphead.ScanTokens([]byte(h), func(v []byte) bool {
		if check(string(v)) {
			ret = string(v)

			return false
		}

		return true
	})

	return ret, ok
}

func btsSelectExtensions(header []byte, selected []httphead.Option, check func(httphead.Option) bool) ([]httphead.Option, bool) {
	s := httphead.OptionSelector{
		Flags: httphead.SelectCopy,
		Check: check,
	}

	return s.Select(header, selected)
}

func negotiateMaybe(in httphead.Option, dest []httphead.Option, f func(httphead.Option) (httphead.Option, error)) ([]httphead.Option, error) {
	if in.Size() == 0 {
		return dest, nil
	}
	opt, err := f(in)
	if err != nil {
		return nil, err
	}
	if opt.Size() > 0 {
		dest = append(dest, opt)
	}

	return dest, nil
}

func negotiateExtensions(
	h []byte, dest []httphead.Option,
	extensionsFunc func(httphead.Option) (httphead.Option, error),
) (_ []httphead.Option, err error) {
	index := -1
	var current httphead.Option
	ok := httphead.ScanOptions(h, func(idx int, name, attr, val []byte) httphead.Control {
		if idx != index {
			dest, err = negotiateMaybe(current, dest, extensionsFunc) //nolint:revive // .
			if err != nil {
				return httphead.ControlBreak
			}
			index = idx
			current = httphead.Option{Name: name}
		}
		if attr != nil {
			current.Parameters.Set(attr, val)
		}

		return httphead.ControlContinue
	})
	if !ok {
		return nil, ws.ErrMalformedRequest
	}

	return negotiateMaybe(current, dest, extensionsFunc)
}

func (u *h2Upgrader) syncWSProtocols(req *http.Request) (hs ws.Handshake, err error) {
	if check := u.Protocol; check != nil {
		ps := req.Header[headerSecProtocolCanonical]
		for i := 0; hs.Protocol == "" && err == nil && i < len(ps); i++ {
			var ok bool
			hs.Protocol, ok = strSelectProtocol(ps[i], check)
			if !ok {
				err = ws.ErrMalformedRequest
			}
		}
	}
	if f := u.Negotiate; err == nil && f != nil {
		for _, h := range req.Header[headerSecExtensionsCanonical] {
			hs.Extensions, err = negotiateExtensions([]byte(h), hs.Extensions, f)
			if err != nil {
				break
			}
		}
	}
	if check := u.Extension; err == nil && check != nil && u.Negotiate == nil {
		xs := req.Header[headerSecExtensionsCanonical]
		for i := 0; err == nil && i < len(xs); i++ {
			var ok bool
			hs.Extensions, ok = btsSelectExtensions([]byte(xs[i]), hs.Extensions, check)
			if !ok {
				err = ws.ErrMalformedRequest
			}
		}
	}

	return hs, err
}

func Upgrade(writer http.ResponseWriter, req *http.Request, conf *Config) (Connection, error) {
	var conn net.Conn
	var hs ws.Handshake
	var err error

	h2Upgrader := newH2Upgrader()
	if req.Method == http.MethodConnect && req.Proto == "websocket" {
		conn, _, hs, err = h2Upgrader.Upgrade(req, writer)
	} else {
		conn, _, hs, err = ws.HTTPUpgrader{
			Negotiate: h2Upgrader.Negotiate,
			Protocol:  h2Upgrader.Protocol,
			Extension: h2Upgrader.Extension,
		}.Upgrade(req, writer)
	}

	if err != nil {
		return nil, errors.Wrapf(err, "failed to upgrade to websocket over http1/2: %v, upgrade: %v", req.Proto, req.Header.Get("Upgrade"))
	}

	if conn == nil { // Should never happen.
		slog.ErrorContext(req.Context(), "failed to upgrade to websocket: no net.Conn returned",
			"proto", req.Proto,
			"upgrade", req.Header.Get("Upgrade"),
			"method", req.Method,
			"remote_addr", req.RemoteAddr,
		)
		return nil, ErrUpgradeInternal
	}

	if conf == nil {
		conf = &Config{}
	}
	conf.handshake = hs

	return newConnection(req.Context(), conn, conf), nil
}
