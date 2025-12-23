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
	relaymanagement "github.com/ice-blockchain/heimdall/relay-management"
	"github.com/ice-blockchain/heimdall/server"
	tokenanalytics "github.com/ice-blockchain/heimdall/token-analytics"
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
	ta := tokenanalytics.NewUserRepository(ctx)
	s.tokenAnalytics = ta
	s.coinSyncer = coins.MustStartSyncer(ctx, cancel, ta)
	s.verifiedQueueRepository = accounts.NewVerifiedQueueRepository(ctx, s.tokenAnalytics)
	s.relayLivenessCheck = relaymanagement.NewRelaysSync(ctx)

	go s.processVerifiedUsersQueue(ctx)
	go s.processRelayLivenessCheck(ctx)
}

func (s *service) Close(ctx context.Context) error {
	if ctx.Err() != nil {
		return errors.Wrap(ctx.Err(), "could not close repository because context ended")
	}
	err := multierror.Append(
		errors.Wrapf(s.coinSyncer.Close(), "failed to close coin syncer"),
		errors.Wrapf(s.verifiedQueueRepository.Close(), "failed to close verifiedQueueRepository"),
		errors.Wrapf(s.tokenAnalytics.Close(), "failed to close tokenAnalytics"),
	).ErrorOrNil()

	return errors.Wrapf(err, "failed to close services")
}

func (s *service) CheckHealth(ctx context.Context) error {
	log.Debug("checking health...")

	return multierror.Append(
		errors.Wrapf(s.coinSyncer.HealthCheck(ctx), "coins sync check failed"),
		errors.Wrapf(s.verifiedQueueRepository.HealthCheck(ctx), "verifiedQueueRepository check failed"),
		// TODO: re-enable when token analytics is stable.
		// errors.Wrapf(s.tokenAnalytics.HealthCheck(ctx), "tokenAnalytics check failed"),
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

func (s *service) processRelayLivenessCheck(ctx context.Context) {
	for {
		if err := s.relayLivenessCheck.CheckRelayStatus(ctx); err != nil {
			if errors.Is(err, relaymanagement.ErrNoRelays) {
				time.Sleep(1 * time.Minute)

				continue
			}
			log.Error(errors.Wrap(err, "processing relay liveness check failed"))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(1 * time.Minute):
		}
	}
}
