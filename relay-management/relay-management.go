// SPDX-License-Identifier: ice License 1.0

package relaymanagement

import (
	"context"

	"github.com/pkg/errors"

	appcfg "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func NewRelays(ctx context.Context) Relays {
	var cfg config
	appcfg.MustLoadFromKey(applicationYamlKey, &cfg)
	db := storage.MustConnect(ctx, ddl, applicationYamlKey)
	r := relaysRepository{
		cfg:      &cfg,
		db:       db,
		shutdown: db.Close,
	}
	return &r
}

func (r *relaysRepository) GetAllIONConnectRelays(ctx context.Context, requestedRelay string) ([]string, error) {
	allRelays, err := storage.Select[ionConnectRelays](ctx, r.db, `SELECT array_agg(url) as ion_connect_relays 
		FROM ion_connect_relays
		WHERE region = (SELECT region FROM ion_connect_relays WHERE url = $1)
		AND (unhealthy_started_at is NULL OR unhealthy_started_at between now()-'6 hours'::INTERVAL AND now() )`, requestedRelay)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			err = nil
		}
		return nil, errors.Wrapf(err, "failed to list ion connect relays from db")
	}
	if len(allRelays) == 0 || allRelays[0].IONConnectRelays == nil {
		return nil, ErrNoRelays
	}
	return allRelays[0].IONConnectRelays, nil
}

func (r *relaysRepository) IONConnectRelaysForUser(ctx context.Context, userId string, followeeMasterKeys []string) ([]string, error) {
	userRelays, err := storage.Select[ionConnectRelays](ctx, r.db, `
		SELECT array_agg(url) as ion_connect_relays FROM ion_connect_relays_with_the_lowest_storage_by_region;
	`)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			err = nil
		}
		return nil, errors.Wrapf(err, "failed to choose best ion connect relays for user %v", userId)
	}
	if len(userRelays) == 0 || userRelays[0].IONConnectRelays == nil {
		return nil, ErrNoRelays
	}
	return userRelays[0].IONConnectRelays, nil
}
