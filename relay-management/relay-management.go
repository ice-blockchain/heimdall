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
	allRelays, err := storage.Select[struct {
		IONConnectRelays []string `db:"ion_connect_relays"`
	}](ctx, r.db, `SELECT array_agg(url) as ion_connect_relays 
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
	res := make([]*UserAssignedRelay, 0, len(allRelays[0].IONConnectRelays))
	for _, relayUrl := range allRelays[0].IONConnectRelays {
		res = append(res, &UserAssignedRelay{URL: relayUrl})
	}
	return res, nil
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
	var data []byte
	switch v := value.(type) {
	case string:
		data = []byte(v)
	case []byte:
		data = v
	default:
		return errors.Errorf("unexpected type %T for value: %v", value, value)
	}
	err := json.Unmarshal(data, r)
	return errors.Wrapf(err, "failed to unmarshal value from db %v", value)
}
