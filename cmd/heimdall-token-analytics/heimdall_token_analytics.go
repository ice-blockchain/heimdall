// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/ice-blockchain/heimdall/cmd/heimdall-token-analytics/server"
	tokenanalytics "github.com/ice-blockchain/heimdall/token-analytics"
)

func newContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())

	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		force := false
		for sig := range c {
			if force {
				slog.InfoContext(ctx, "forced shutdown", "signal", sig.String())
				os.Exit(2)
			} else {
				slog.InfoContext(ctx, "graceful shutdown", "signal", sig.String())
				cancel()
				force = true
			}
		}
	}()

	return ctx
}

// @title						Token Analytics Service API.
// @version					latest
// @description				This service provides analytics data for various tokens.
// @query.collection.format	multi
// @schemes					https
// @contact.name				ice.io
// @contact.url				https://ice.io
func main() {
	var srv service

	cfg := mustLoadConfig()
	ctx := newContext()

	slog.InfoContext(ctx, "starting service", "version", cfg.Version)

	srv.Init(ctx, cfg)
	srv.MustStart(ctx)
	srv.Close(ctx)
}

func (s *service) MustStart(ctx context.Context) {
	// HTTP will block here until context is done.
	s.httpServer.MustListenAndServe(ctx, s.RegisterRoutes)
}

func (s *service) Init(ctx context.Context, cfg *Config) {
	s.httpServer = server.New(cfg.Server())
	s.tokenAnalytics = tokenanalytics.New(ctx)
	s.tokenAnalytics.MustStart(ctx)
}

func (s *service) Close(context.Context) error {
	return s.tokenAnalytics.Close()
}

func (s *service) CheckHealth(ctx context.Context) error {
	return s.tokenAnalytics.HealthCheck(ctx)
}

func readVersionString() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}

	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			return setting.Value
		}
	}

	return "unknown"
}
