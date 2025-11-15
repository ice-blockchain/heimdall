// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"crypto/tls"
	"math/rand"

	"github.com/nbd-wtf/go-nostr"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (a *verifiedUsersSync) ProcessNextVerifiedUsersQueue(ctx context.Context) error {
	if errors.Is(storage.CheckWrite(ctx, a.db), storage.ErrReadOnly) {
		log.Info("skipping verified users processing, DB is read-only")
		return ErrNotFound
	}

	return errors.Wrap(storage.DoInTransaction(ctx, a.db, func(conn storage.QueryExecer) error {
		query := `
			WITH next_user AS (
				SELECT q.user_id AS id
				FROM verified_users_sync_queue q
				JOIN users u ON q.user_id = u.id AND u.verified = false
				ORDER BY q.created_at 
				LIMIT 1
				FOR UPDATE
			),
			deleted AS (
				DELETE FROM verified_users_sync_queue
				WHERE user_id IN (SELECT id FROM next_user)
			)
			UPDATE users 
				SET verified = true 
			WHERE id IN (SELECT id FROM next_user)
			RETURNING master_pubkey, 
				COALESCE(
					(SELECT json_agg(json_build_object('url', i.url, 'type', i.relay_type)) 
					 FROM ion_connect_relays i 
					 WHERE i.url = ANY(ion_connect_relays)),
					'[]'::json
				) AS ion_connect_relays
		`
		userData, err := storage.ExecOne[LiteUser](ctx, conn, query)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return nil
			}
			return errors.Wrap(err, "failed to get and process verified user")
		}
		if syncErr := a.tokenAnalyticsRepo.SetVerified(ctx, userData.MasterPubKey); syncErr != nil {
			return errors.Wrapf(syncErr, "failed to sync verified status to token-analytics for user %v", userData.MasterPubKey)
		}
		verificationEvents, err := generateVerificationEvents(a.privateKey, userData.MasterPubKey)
		if err != nil {
			return errors.Wrap(err, "failed to generate verification events")
		}
		writeRelayUrls := make([]string, 0, len(userData.IONConnectRelays))
		for _, relay := range userData.IONConnectRelays {
			if relay.Type == model.RelayListWriteMarker || relay.Type == "" {
				writeRelayUrls = append(writeRelayUrls, relay.URL)
			}
		}
		return errors.Wrapf(a.publishEvents(ctx, writeRelayUrls, verificationEvents),
			"failed to process verified user: %s", userData.MasterPubKey)
	}), "failed to process verified user")
}

func generateVerificationEvents(heimdallPrivateKey string, masterPubKey string) (events []*model.Event, err error) {
	now := nostr.Now()
	badgeDefinitionEvent := &model.Event{
		Event: nostr.Event{
			CreatedAt: now,
			Kind:      nostr.KindBadgeDefinition,
			Tags: nostr.Tags{
				{"d", verifiedBadgeDTag},
				{"name", verifiedBadgeName},
				{"description", verifiedBadgeDescription},
				verifiedBadgeImage1024X1024Tag,
				verifiedBadgeThumbnail256X256Tag,
			},
		},
	}
	if err := badgeDefinitionEvent.SignWithAlg(heimdallPrivateKey, model.SignAlgEDDSA, model.KeyAlgCurve25519); err != nil {
		return nil, errors.Wrap(err, "failed to sign badge definition event")
	}
	badgeAwardEvent := &model.Event{
		Event: nostr.Event{
			CreatedAt: now,
			Kind:      nostr.KindBadgeAward,
			Tags: nostr.Tags{
				{"a", badgeDefinitionEvent.Address()},
				{"p", masterPubKey},
			},
		},
	}
	if err := badgeAwardEvent.SignWithAlg(heimdallPrivateKey, model.SignAlgEDDSA, model.KeyAlgCurve25519); err != nil {
		return nil, errors.Wrap(err, "failed to sign badge award event")
	}

	return []*model.Event{badgeDefinitionEvent, badgeAwardEvent}, nil
}

func (a *verifiedUsersSync) publishEvents(ctx context.Context, relays []string, events []*model.Event) error {
	relay := getRandomRelay(relays)
	if relay == "" {
		return nil
	}
	nostrRelay := nostr.NewRelay(ctx, relay, nostr.WithSignatureChecker(func(e *nostr.Event) bool {
		subzeroEvent := model.Event{Event: *e}
		ok, _ := subzeroEvent.CheckSignature()

		return ok
	}))
	if err := nostrRelay.ConnectWithTLS(ctx, &tls.Config{InsecureSkipVerify: true}); err != nil {
		return errors.Wrapf(err, "failed to connect to relay %s", relay)
	}
	defer nostrRelay.Close()
	_ = nostrRelay.Publish(ctx, events[0].Event)
	if err := nostrRelay.Auth(ctx, func(event *nostr.Event) error {
		subZeroEvent := model.Event{Event: *event}
		if err := subZeroEvent.SignWithAlg(a.privateKey, model.SignAlgEDDSA, model.KeyAlgCurve25519); err != nil {
			return err
		}
		*event = subZeroEvent.Event

		return nil
	}); err != nil {
		return errors.Wrapf(err, "failed to auth to relay %s", relay)
	}
	if err := nostrRelay.PublishMany(ctx, &events[0].Event, &events[1].Event); err != nil {
		return errors.Wrapf(err, "failed to publish events: %s, %s", events[0].Event.ID, events[1].Event.ID)
	}

	return nil
}

func getRandomRelay(relays []string) string {
	if len(relays) == 0 {
		return ""
	}

	return relays[rand.Intn(len(relays))]
}
