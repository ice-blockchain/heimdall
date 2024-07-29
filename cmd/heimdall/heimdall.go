// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"

	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/ice-blockchain/heimdall/server"
	appcfg "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/log"
)

// @title						User accounts management for ION
// @version					latest
// @description				It is responsible for providing off chain account management for the ION Platform; it is the first layer of interaction between users and the platform.
// @query.collection.format	multi
// @schemes					https
// @contact.name				ice.io
// @contact.url				https://ice.io
func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cfg config
	appcfg.MustLoadFromKey(applicationYamlKey, &cfg)
	server.New(&service{cfg: &cfg}, applicationYamlKey, "/docs/").ListenAndServe(ctx, cancel)
}

func (s *service) RegisterRoutes(router *server.Router) {
	s.setupDfnsProxyRoutes(router)
}

func (s *service) Init(ctx context.Context, cancel context.CancelFunc) {
	s.accounts = accounts.New(ctx)
}

func (s *service) Close(ctx context.Context) error {
	if ctx.Err() != nil {
		return errors.Wrap(ctx.Err(), "could not close repository because context ended")
	}

	return multierror.Append( //nolint:wrapcheck //.
		nil,
	).ErrorOrNil()
}

func (s *service) CheckHealth(ctx context.Context) error {
	log.Debug("checking health...", "package", "users")
	return nil
}
