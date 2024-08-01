// SPDX-License-Identifier: ice License 1.0

package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	swaggerfiles "github.com/swaggo/files"
	ginswagger "github.com/swaggo/gin-swagger"

	appcfg "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/log"
)

func New(state State, cfgKey, swaggerRoot string) Server {
	appcfg.MustLoadFromKey(cfgKey, &cfg)
	appcfg.MustLoadFromKey("development", &development)

	return &srv{State: state, swaggerRoot: swaggerRoot, applicationYAMLKey: cfgKey}
}

func (s *srv) ListenAndServe(ctx context.Context, cancel context.CancelFunc) {
	s.Init(ctx, cancel)
	s.setupRouter() //nolint:contextcheck // Nope, we don't need it.
	s.setupServer(ctx)
	go s.startServer(s.server)
	go s.startServer(s.h3server)
	s.wait(ctx)
	s.shutDown() //nolint:contextcheck // Nope, we want to gracefully shutdown on a different context.
}

func (s *srv) setupRouter() {
	if !development {
		gin.SetMode(gin.ReleaseMode)
		s.router = gin.New()
		s.router.Use(gin.Recovery())
	} else {
		gin.ForceConsoleColor()
		s.router = gin.Default()
	}
	log.Info(fmt.Sprintf("GIN Mode: %v\n", gin.Mode()))
	s.router.RemoteIPHeaders = []string{"cf-connecting-ip", "X-Real-IP", "X-Forwarded-For"}
	s.router.TrustedPlatform = gin.PlatformCloudflare
	s.router.HandleMethodNotAllowed = true
	s.router.RedirectFixedPath = true
	s.router.RemoveExtraSlash = true
	s.router.UseRawPath = true

	log.Info("registering routes...")
	s.RegisterRoutes(s.router)
	log.Info(fmt.Sprintf("%v routes registered", len(s.router.Routes())))
	s.setupSwaggerRoutes()
	s.setupHealthCheckRoutes()
}

func (s *srv) setupHealthCheckRoutes() {
	s.router.GET("health-check", RootHandler[healthCheck, map[string]string, *ErrorResponse](func(ctx context.Context, _ *Request[healthCheck, map[string]string]) (*Response[map[string]string], *ErrResponse[*ErrorResponse]) { //nolint:lll // .
		if err := s.State.CheckHealth(ctx); err != nil {
			return nil, Unexpected(errors.Wrapf(err, "health check failed"))
		}

		return OK(&map[string]string{"clientIp": "1.2.3.4"}), nil
	}))
}

func (s *srv) setupSwaggerRoutes() {
	root := s.swaggerRoot
	if root == "" {
		return
	}
	s.router.
		GET(root, func(c *gin.Context) {
			c.Redirect(http.StatusFound, (&url.URL{Path: fmt.Sprintf("%v/swagger/index.html", root)}).RequestURI())
		}).
		GET(fmt.Sprintf("%v/swagger/*any", root), ginswagger.WrapHandler(swaggerfiles.Handler))
}

func (s *srv) setupServer(ctx context.Context) {
	s.server = &http.Server{ //nolint:gosec // Not an issue, each request has a deadline set by the handler; and we're behind a proxy.
		Addr:    fmt.Sprintf(":%v", cfg.HTTPServer.Port),
		Handler: s.router,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}
	s.h3server = &http3.Server{
		Addr:    fmt.Sprintf(":%v", cfg.HTTPServer.Port),
		Port:    int(cfg.HTTPServer.Port),
		Handler: s.router,
		ConnContext: func(connCtx context.Context, c quic.Connection) context.Context {
			// TODO: reload values from ctx
			return connCtx
		},
	}
}

func (s *srv) startServer(server interface {
	ListenAndServeTLS(certFile, keyFile string) error
}) {
	defer log.Info("server stopped listening")
	log.Info(fmt.Sprintf("server started listening on %v...", cfg.HTTPServer.Port))

	isUnexpectedError := func(err error) bool {
		return err != nil &&
			!errors.Is(err, io.EOF) &&
			!errors.Is(err, http.ErrServerClosed)
	}

	if err := server.ListenAndServeTLS(cfg.HTTPServer.CertPath, cfg.HTTPServer.KeyPath); isUnexpectedError(err) {
		s.quit <- syscall.SIGTERM
		log.Error(errors.Wrap(err, "server.ListenAndServeTLS failed"))
	}
}

func (s *srv) wait(ctx context.Context) {
	quit := make(chan os.Signal, 1)
	s.quit = quit
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-ctx.Done():
	case <-quit:
	}
}

func (s *srv) shutDown() {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.DefaultEndpointTimeout)
	defer cancel()
	log.Info("shutting down server...")

	if err := s.server.Shutdown(ctx); err != nil && !errors.Is(err, io.EOF) {
		log.Error(errors.Wrap(err, "server shutdown failed"))
	} else {
		log.Info("server shutdown succeeded")
	}

	if err := s.h3server.Close(); err != nil && !errors.Is(err, io.EOF) {
		log.Error(errors.Wrap(err, "h3 server shutdown failed"))
	} else {
		log.Info("h3 server shutdown succeeded")
	}

	if err := s.State.Close(ctx); err != nil && !errors.Is(err, io.EOF) {
		log.Error(errors.Wrap(err, "state close failed"))
	} else {
		log.Info("state close succeeded")
	}
}
