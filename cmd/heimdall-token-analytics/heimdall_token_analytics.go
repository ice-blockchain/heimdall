// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"fmt"

	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/server"
	tokenanalytics "github.com/ice-blockchain/heimdall/token-analytics"
	appcfg "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/log"
)

// @title						Service that syncs coins data from 3rd party
// @version					latest
// @description				It is responsible for syncing coins data.
// @query.collection.format	multi
// @schemes					https
// @contact.name				ice.io
// @contact.url				https://ice.io
func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cfg struct {
		Version string `yaml:"version"`
	}

	appcfg.MustLoadFromKey(applicationYamlKey, &cfg)

	log.Info(fmt.Sprintf("starting version `%v`...", cfg.Version))
	server.New(&service{}, applicationYamlKey, "").ListenAndServe(ctx, cancel, new(noAuth))
}

func (s *service) RegisterRoutes(router *server.Router) {
}

func (s *service) Init(ctx context.Context, cancel context.CancelFunc) {
	s.tokenAnalytics = tokenanalytics.New(ctx)
	s.tokenAnalytics.MustStart(ctx)
}

func (s *service) Close(ctx context.Context) error {
	if ctx.Err() != nil {
		return errors.Wrap(ctx.Err(), "could not close repository because context ended")
	}

	return s.tokenAnalytics.Close()
}

func (s *service) CheckHealth(ctx context.Context) error {
	log.Debug("checking health...")

	return s.tokenAnalytics.Healthcheck(ctx)
}

func (n *noAuth) VerifyToken(ctx context.Context, token string) (server.Token, error) {
	return nil, errors.Errorf("auth disabled")
}
