// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/ice-blockchain/heimdall/coins"
	"github.com/ice-blockchain/heimdall/server"
	appcfg "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
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
	s.coinSyncer = coins.MustStartSyncer(ctx, cancel)
	s.verifiedQueueRepository = accounts.NewVerifiedQueueRepository(ctx)

	go s.processVerifiedUsersQueue(ctx)
}

func (s *service) Close(ctx context.Context) error {
	if ctx.Err() != nil {
		return errors.Wrap(ctx.Err(), "could not close repository because context ended")
	}
	err := multierror.Append(
		errors.Wrapf(s.coinSyncer.Close(), "failed to close coin syncer"),
		errors.Wrapf(s.verifiedQueueRepository.Close(), "failed to close verifiedQueueRepository"),
	).ErrorOrNil()

	return errors.Wrapf(err, "failed to close services")
}

func (s *service) CheckHealth(ctx context.Context) error {
	log.Debug("checking health...")

	return multierror.Append(
		errors.Wrapf(s.coinSyncer.HealthCheck(ctx), "coins sync check failed"),
		errors.Wrapf(s.verifiedQueueRepository.HealthCheck(ctx), "verifiedQueueRepository check failed"),
	).ErrorOrNil()
}

func (n *noAuth) VerifyToken(ctx context.Context, token string) (server.Token, error) {
	return nil, errors.Errorf("auth disabled")
}

func (s *service) processVerifiedUsersQueue(ctx context.Context) {
	for {
		if err := s.verifiedQueueRepository.ProcessNextVerifiedUsersQueue(ctx); err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				time.Sleep(10 * time.Second)

				continue
			}
			log.Error(errors.Wrap(err, "processing verified user failed"))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}
