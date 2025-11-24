// SPDX-License-Identifier: ice License 1.0

package server

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/gin-gonic/gin"

	h2ec "github.com/ice-blockchain/go/src/net/http"
)

type (
	Server interface {
		MustListenAndServe(ctx context.Context, attachRoutes func(gin.IRouter))
	}
	Config struct {
		TLS   *tls.Config `yaml:"-"`
		Port  uint32      `yaml:"port"`
		Debug bool        `yaml:"debug"`
	}

	httpServer struct {
		Router *gin.Engine
		Config *Config
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

		if strings.HasPrefix(path, "/health") {
			// Skip logging for health checks.
			return
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

		if token := authGetToken(c); token != nil {
			logArgs = append(logArgs, "user_masterkey", token.GetMasterPublicKey())
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

func (s *httpServer) MustListenAndServe(ctx context.Context, attachRoutes func(gin.IRouter)) {
	var wg sync.WaitGroup

	attachRoutes(s.Router)
	if s.Config.Debug {
		for _, item := range s.Router.Routes() {
			slog.InfoContext(ctx, "registered route", "method", item.Method, "path", item.Path, "handler", item.Handler)
		}
	}

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
