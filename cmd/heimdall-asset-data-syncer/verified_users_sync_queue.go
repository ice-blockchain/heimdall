// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"math/rand"

	"github.com/nbd-wtf/go-nostr"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func (s *service) ProcessNextVerifiedUsersQueue(ctx context.Context) error {
	return errors.Wrap(storage.DoInTransaction(ctx, s.db, func(conn storage.QueryExecer) error {
		query := `
			WITH next_user AS (
				SELECT q.user_id AS id, u.master_pubkey, u.ion_connect_relays, u.username
				FROM verified_users_sync_queue q
				JOIN users u ON q.user_id = u.id
				WHERE u.verified = false
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
			RETURNING master_pubkey, ion_connect_relays, username
		`
		userData, err := storage.ExecOne[verifiedUserQueueData](ctx, conn, query)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return nil
			}
			return errors.Wrap(err, "failed to get and process verified user")
		}
		badgeDefinitionEvent, badgeAwardEvent, err := accounts.GenerateVerificationEvents(s.privateKey, s.publicKey, userData.MasterPubKey)
		if err != nil {
			return errors.Wrap(err, "failed to generate verification events")
		}
		ephemeralEvent, err := s.generateEphemeralVerificationEvent(userData, badgeDefinitionEvent, badgeAwardEvent)
		if err != nil {
			return errors.Wrap(err, "failed to generate ephemeral verification event")
		}

		return errors.Wrapf(s.publishEvents(ctx, userData.IONConnectRelays, []*model.Event{badgeDefinitionEvent, badgeAwardEvent, ephemeralEvent}),
			"failed to process verified user: %s", userData.MasterPubKey)
	}), "failed to process verified user")
}

func (s *service) generateEphemeralVerificationEvent(userData *verifiedUserQueueData, badgeDefinitionEvent, badgeAwardEvent *model.Event) (*model.Event, error) {
	now := nostr.Now()
	userProfileMetadataEvent := &model.Event{
		Event: nostr.Event{
			CreatedAt: now,
			Kind:      nostr.KindProfileMetadata,
			Content:   `{"name":"` + userData.Username + `"}`,
		},
	}
	if err := userProfileMetadataEvent.SignWithAlg(s.privateKey, model.SignAlgEDDSA, model.KeyAlgCurve25519); err != nil {
		return nil, errors.Wrap(err, "failed to sign user profile metadata event")
	}
	event := &model.Event{
		Event: nostr.Event{
			CreatedAt: now,
			Kind:      model.CustomIONKindEphemeralEmbeddding,
			Content:   userProfileMetadataEvent.String(),
			Tags: nostr.Tags{
				{"e", badgeAwardEvent.GetID()},
				{"e", badgeDefinitionEvent.GetID()},
			},
		},
	}
	if err := event.SignWithAlg(s.privateKey, model.SignAlgEDDSA, model.KeyAlgCurve25519); err != nil {
		return nil, errors.Wrap(err, "failed to sign profile badge event")
	}

	return event, nil
}

func (s *service) publishEvents(ctx context.Context, relays []string, events []*model.Event) error {
	relay := getRandomRelay(relays)
	if relay == "" {
		return nil
	}
	nostrRelay := nostr.NewRelay(ctx, relay, nostr.WithSignatureChecker(func(e *nostr.Event) bool {
		subzeroEvent := model.Event{Event: *e}
		ok, _ := subzeroEvent.CheckSignature()

		return ok
	}))
	if err := nostrRelay.Connect(ctx); err != nil {
		return errors.Wrapf(err, "failed to connect to relay %s", relay)
	}
	defer nostrRelay.Close()
	_ = nostrRelay.Publish(ctx, events[0].Event)
	if err := nostrRelay.Auth(ctx, func(event *nostr.Event) error {
		subZeroEvent := model.Event{Event: *event}
		if err := subZeroEvent.SignWithAlg(s.privateKey, model.SignAlgEDDSA, model.KeyAlgCurve25519); err != nil {
			return err
		}
		*event = subZeroEvent.Event

		return nil
	}); err != nil {
		return errors.Wrapf(err, "failed to auth to relay %s", relay)
	}
	if err := nostrRelay.PublishMany(ctx, &events[0].Event, &events[1].Event, &events[2].Event); err != nil {
		return errors.Wrapf(err, "failed to publish events: %s, %s, %s", events[0].Event.ID, events[1].Event.ID, events[2].Event.ID)
	}

	return nil
}

func getRandomRelay(relays []string) string {
	if len(relays) == 0 {
		return ""
	}

	return relays[rand.Intn(len(relays))]
}
