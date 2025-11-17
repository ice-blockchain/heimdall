// SPDX-License-Identifier: ice License 1.0

package server

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/gin-gonic/gin"

	h2ec "github.com/ice-blockchain/go/src/net/http"
	"github.com/ice-blockchain/heimdall/token-analytics/server/websocket"
)

type (
	WebsocketHandler interface {
		HandleWS(ctx context.Context, stream websocket.ReaderWriter)
	}
	Router interface {
		gin.IRoutes
		Websocket(path string, httpHandler http.HandlerFunc, wsHandler WebsocketHandler)
	}
	Server interface {
		MustListenAndServe(ctx context.Context, attachRoutes func(Router))
	}
	Config struct {
		TLS   *tls.Config `yaml:"-"`
		Port  uint32      `yaml:"port-tcp"`
		Debug bool        `yaml:"debug"`
	}

	httpServer struct {
		Router *gin.Engine
		Config *Config
	}
	httpRouter struct {
		*gin.Engine
	}
)

func New(conf *Config) Server {
	return newServer(conf)
}

func loggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		c.Next()

		dur := time.Since(start)
		if raw != "" {
			path = path + "?" + raw
		}

		logArgs := []any{
			"proto", c.Request.Proto,
			"timestamp", start.Format("2006/01/02 - 15:04:05.999999999"),
			"status", c.Writer.Status(),
			"duration", dur,
			"client_ip", c.ClientIP(),
			"method", c.Request.Method,
			"path", path,
			"body_size", c.Writer.Size(),
		}

		if errorStr := c.Errors.ByType(gin.ErrorTypePrivate).String(); errorStr != "" {
			logArgs = append(logArgs, "error", errorStr)
		}

		slog.InfoContext(c, "request processed", logArgs...)
	}
}

func newServer(conf *Config) *httpServer {
	var server httpServer

	if !conf.Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	server.Config = conf
	server.Router = gin.New()
	server.Router.Use(gin.Recovery(), loggerMiddleware())
	server.Router.RemoteIPHeaders = []string{"cf-connecting-ip", "X-Real-IP", "X-Forwarded-For"}
	server.Router.TrustedPlatform = gin.PlatformCloudflare
	server.Router.HandleMethodNotAllowed = true
	server.Router.RedirectFixedPath = true
	server.Router.RemoveExtraSlash = true
	server.Router.UseRawPath = true

	return &server
}

func (s *httpServer) ListenHTTP(ctx context.Context, ch chan<- error) error {
	var srv h2ec.Server

	for _, proto := range []string{"h2", "http/1.1"} {
		if !slices.Contains(s.Config.TLS.NextProtos, proto) {
			s.Config.TLS.NextProtos = append(s.Config.TLS.NextProtos, proto)
		}
	}

	srv.Addr = ":" + strconv.Itoa(int(s.Config.Port))
	srv.Handler = s.Router.Handler()
	srv.TLSConfig = s.Config.TLS
	srv.BaseContext = func(l net.Listener) context.Context {
		return ctx
	}

	context.AfterFunc(ctx, func() {
		slog.InfoContext(ctx, "shutting down http/tcp server ...")
		ch <- srv.Shutdown(context.WithoutCancel(ctx))
	})

	l, err := tls.Listen("tcp", srv.Addr, srv.TLSConfig)
	if err != nil {
		return errors.Wrap(err, "failed to start tcp listener")
	}
	defer l.Close()

	if s.Config.Port == 0 {
		atomic.StoreUint32(&s.Config.Port, uint32(l.Addr().(*net.TCPAddr).Port))
		slog.WarnContext(ctx, "http/tcp: assigned dynamic tcp port", "port", s.Config.Port)
	}

	slog.InfoContext(ctx, "starting http/tcp server", "port", s.Config.Port)

	if err := srv.Serve(l); err != nil && !errors.IsAny(err, h2ec.ErrServerClosed, io.EOF, context.Canceled) {
		return errors.Wrap(err, "failed to start http2/tcp server")
	}

	return nil
}

func (s *httpServer) MustListenAndServe(ctx context.Context, attachRoutes func(Router)) {
	var wg sync.WaitGroup

	attachRoutes(&httpRouter{s.Router})

	done := make(chan error, 1)

	wg.Go(func() {
		if err := s.ListenHTTP(ctx, done); err != nil {
			slog.ErrorContext(ctx, "http server failed", "error", err)
			panic(err)
		}
	})
	wg.Wait()

	err := <-done
	if err != nil {
		slog.ErrorContext(ctx, "server shutdown with error", "error", err)
	}
}

func (r *httpRouter) Websocket(path string, httpHandler http.HandlerFunc, wsHandler WebsocketHandler) {
	r.Any(path, func(c *gin.Context) {
		var wsocket websocket.Connection
		var err error

		if c.Request.Header.Get("Upgrade") == "websocket" || (c.Request.Method == http.MethodConnect && c.Request.Proto == "websocket") {
			wsocket, err = websocket.Upgrade(c.Writer, c.Request, &websocket.Config{
				WriteTimeout: time.Second * 30,
				ReadTimeout:  time.Second * 30,
			})
		}

		if err != nil {
			slog.ErrorContext(c.Request.Context(), "failed to upgrade to websocket", "error", err, "remote_addr", c.ClientIP())
			c.Writer.WriteHeader(http.StatusBadRequest)
			return
		}

		if wsocket != nil {
			go func() {
				defer func() {
					if clErr := wsocket.Close(); clErr != nil {
						slog.ErrorContext(c, "failed to close websocket connection", "error", clErr, "remote_addr", c.ClientIP())
					}
				}()
				go wsocket.Write(c)
				wsHandler.HandleWS(c, wsocket)
			}()

			return
		}

		if httpHandler != nil {
			httpHandler.ServeHTTP(c.Writer, c.Request)
			return
		}

		c.Writer.WriteHeader(http.StatusMethodNotAllowed)
	})
}
