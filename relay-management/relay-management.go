// SPDX-License-Identifier: ice License 1.0

package relaymanagement

import (
	"context"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func NewRelays(ctx context.Context) Relays {
	db := storage.MustConnect(ctx, ddl, applicationYamlKey)
	r := relaysRepository{
		db:       db,
		shutdown: db.Close,
	}
	return &r
}

func (r *relaysRepository) GetAllIONConnectRelays(ctx context.Context, requestedRelay string) ([]*UserAssignedRelay, error) {
	allRelays, err := storage.Select[ionConnectRelays](ctx, r.db, `
		WITH relays (url, "type") AS (
				SELECT url, relay_type as relay FROM ion_connect_relays
				WHERE relay_group = (SELECT relay_group FROM ion_connect_relays WHERE url = $1)
				  AND (unhealthy_started_at is NULL OR unhealthy_started_at between now()-'6 hours'::INTERVAL AND now() )
				)
		SELECT json_agg(relays) as ion_connect_relays from relays;`, requestedRelay)
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

func (r *relaysRepository) IONConnectRelaysForUser(ctx context.Context, userId string) ([]*UserAssignedRelay, error) {
	userRelays, err := storage.Select[ionConnectRelays](ctx, r.db, `
		WITH relays(url, "type") as (
    		SELECT url, relay_type FROM ion_connect_relays_with_the_lowest_storage_by_region
		)
		SELECT json_agg(relays) as ion_connect_relays from relays;
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

func (r *UserAssignedRelays) Scan(value any) error {
	if value == nil {
		*r = UserAssignedRelays([]*UserAssignedRelay{})
		return nil
	}
	err := json.Unmarshal([]byte((value.(string))), r)
	return errors.Wrapf(err, "failed to unmarshal value from db %v", value)
}
