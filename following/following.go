// SPDX-License-Identifier: ice License 1.0

package following

import (
	"context"

	"github.com/cockroachdb/errors"
	"github.com/nbd-wtf/go-nostr"

	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func New(ctx context.Context) Following {
	db := storage.MustConnect(ctx, ddl, applicationYamlKey)

	var cfg Config
	config.MustLoadFromKey(applicationYamlKey, &cfg)

	return &following{
		db:     db,
		config: &cfg,
	}
}

func (f *following) ProcessFollowersEvent(ctx context.Context, followListEvent, attestationEvent *model.Event) error {
	now := nostr.Now()
	if allowed, err := model.OnBehalfIsAccessAllowed(attestationEvent.Tags, followListEvent.PubKey, followListEvent.Kind, now); err != nil {
		return errors.Wrap(err, "failed to check if attestation event allows other event")
	} else if !allowed {
		return errors.Wrap(ErrOnBehalfAccessDenied, "attestation event does not allow the other event")
	}
	var followedPubkeys []string
	for _, tag := range followListEvent.Tags {
		if tag.Key() == "p" && tag.Value() != "" {
			followedPubkeys = append(followedPubkeys, tag.Value())
		}
	}
	stmt := `
		WITH deleted AS (
			DELETE FROM following
			WHERE follower_master_pubkey = $1
			  	  AND master_pubkey != ALL($2)
		)
		INSERT INTO following (master_pubkey, follower_master_pubkey)
		SELECT master_pubkey, $1
		FROM unnest($2) AS master_pubkey
		ON CONFLICT DO NOTHING`
	_, err := storage.Exec(ctx, f.db, stmt, followListEvent.GetMasterPublicKey(), followedPubkeys)
	if err != nil {
		if errors.Is(err, storage.ErrRelationNotFound) {
			return errors.Wrap(ErrRelationNotFound, "failed to update following relationships")
		}

		return errors.Wrap(err, "failed to update following relationships")
	}

	return nil
}

func (f *following) Close() error {
	return f.db.Close()
}

func (f *following) HealthCheck(ctx context.Context) error {
	return errors.Wrap(f.db.Ping(ctx), "failed to ping database")
}
