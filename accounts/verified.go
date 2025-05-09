// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"math/rand"
	"strconv"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (a *accounts) IsUserVerified(ctx context.Context, masterPubKey string) (bool, []*model.Event, error) {
	query := `SELECT verified FROM users WHERE master_pubkey = $1`
	type result struct {
		Verified bool `db:"verified"`
	}
	res, err := storage.Get[result](ctx, a.db, query, masterPubKey)
	if err != nil {
		return false, nil, errors.Wrap(err, "failed to check user verification status")
	}
	if !res.Verified {
		return false, nil, nil
	}
	badgeDefinitionEvent, badgeAwardEvent, err := a.generateVerificationEvents(masterPubKey)
	if err != nil {
		return true, nil, err
	}

	return true, []*model.Event{badgeDefinitionEvent, badgeAwardEvent}, nil
}

func (a *accounts) ProcessVerifiedUsersQueue(ctx context.Context) error {
	for ctx.Err() == nil {
		userData, err := a.getNextUserFromVerifiedUsersQueue(ctx)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				break
			}

			return errors.Wrap(err, "failed to get verified users batch")
		}
		if userData == nil {
			break
		}
		if err := a.processVerifiedUser(ctx, userData); err != nil {
			log.Error(errors.Wrapf(err, "failed to process verified user %s", userData.UserID))

			return err
		}
	}

	return nil
}

func (a *accounts) processVerifiedUser(ctx context.Context, userData *verifiedUserQueueData) error {
	if !userData.Verified {
		if err := a.removeUserFromQueue(ctx, userData.UserID); err != nil {
			return errors.Wrap(err, "failed to remove unverified user from queue")
		}
		return nil
	}
	badgeDefinitionEvent, badgeAwardEvent, err := a.generateVerificationEvents(userData.MasterPubKey)
	if err != nil {
		return errors.Wrap(err, "failed to generate verification events")
	}
	ephemeralEvent, err := a.generateEphemeralVerificationEvent(badgeDefinitionEvent, badgeAwardEvent)
	if err != nil {
		return errors.Wrap(err, "failed to generate ephemeral verification event")
	}
	if err := a.markUserAsVerified(ctx, userData.UserID); err != nil {
		return errors.Wrap(err, "failed to mark user as verified")
	}
	if err := a.publishEvents(ctx, userData.IONConnectRelays, []*model.Event{badgeDefinitionEvent, badgeAwardEvent, ephemeralEvent}); err != nil {
		return errors.Wrap(err, "failed to publish events")
	}

	return nil
}

func (a *accounts) getNextUserFromVerifiedUsersQueue(ctx context.Context) (*verifiedUserQueueData, error) {
	query := `
		SELECT 
			q.user_id,
			u.master_pubkey,
			u.ion_connect_relays,
			u.verified
		FROM verified_users_sync_queue q
		JOIN users u ON q.user_id = u.id
		ORDER BY q.created_at 
		LIMIT 1
	`
	userData, err := storage.Get[verifiedUserQueueData](ctx, a.db, query)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get verified user from queue")
	}

	return userData, nil
}

func (a *accounts) removeUserFromQueue(ctx context.Context, userID string) error {
	_, err := storage.Exec(ctx, a.db, `DELETE FROM verified_users_sync_queue WHERE user_id = $1`, userID)
	if err != nil {
		return errors.Wrapf(err, "failed to remove user: %s from sync queue", userID)
	}

	return nil
}

func (a *accounts) markUserAsVerified(ctx context.Context, userID string) error {
	query := `
		WITH updated AS (
			UPDATE users SET verified = true 
			WHERE id = $1
			RETURNING id
		)
		DELETE FROM verified_users_sync_queue WHERE user_id = $1
	`
	_, err := storage.Exec(ctx, a.db, query, userID)
	if err != nil {
		return errors.Wrapf(err, "failed to mark user: %s as verified", userID)
	}

	return nil
}

func (a *accounts) generateVerificationEvents(masterPubKey string) (badgeDefinitionEvent, badgeAwardEvent *model.Event, err error) {
	nowTimestamp := nostr.Timestamp(time.Now().Unix())

	badgeEvent := &model.Event{
		Event: nostr.Event{
			PubKey:    a.publicKey,
			CreatedAt: nowTimestamp,
			Kind:      nostr.KindBadgeDefinition,
			Tags: nostr.Tags{
				{"b", a.publicKey},
				{"d", verifiedBadgeDTag},
				{"name", verifiedBadgeName},
				{"description", verifiedBadgeDescription},
				{"image", verifiedBadgeImage, "1024x1024"},
				{"thumb", verifiedBadgeThumbnail, "256x256"},
			},
		},
	}
	if err := badgeEvent.SignWithAlg(a.privateKey, model.SignAlgEDDSA, model.KeyAlgCurve25519); err != nil {
		return nil, nil, errors.Wrap(err, "failed to sign badge event")
	}
	profileBadgeEvent := &model.Event{
		Event: nostr.Event{
			PubKey:    a.publicKey,
			CreatedAt: nowTimestamp,
			Kind:      nostr.KindBadgeAward,
			Tags: nostr.Tags{
				{"a", strconv.Itoa(nostr.KindBadgeAward) + ":" + a.publicKey + ":" + verifiedBadgeDTag},
				{"p", masterPubKey},
				{"b", a.publicKey},
			},
		},
	}
	if err := profileBadgeEvent.SignWithAlg(a.privateKey, model.SignAlgEDDSA, model.KeyAlgCurve25519); err != nil {
		return nil, nil, errors.Wrap(err, "failed to sign profile badge event")
	}

	return badgeEvent, profileBadgeEvent, nil
}

func (a *accounts) generateEphemeralVerificationEvent(badgeDefinitionEvent, badgeAwardEvent *model.Event) (*model.Event, error) {
	heimdalProfileMetadataEvt := &model.Event{
		Event: nostr.Event{
			PubKey:    a.publicKey,
			CreatedAt: nostr.Timestamp(time.Now().Unix()),
			Kind:      nostr.KindProfileMetadata,
			Content:   `{"name":"heimdall","display_name":"heimdall"}`,
		},
	}
	if err := heimdalProfileMetadataEvt.SignWithAlg(a.privateKey, model.SignAlgEDDSA, model.KeyAlgCurve25519); err != nil {
		return nil, errors.Wrap(err, "failed to sign heimdal profile metadata event")
	}
	event := &model.Event{
		Event: nostr.Event{
			PubKey:    a.publicKey,
			CreatedAt: nostr.Timestamp(time.Now().Unix()),
			Kind:      model.CustomIONKindEphemeralEmbeddding,
			Content:   heimdalProfileMetadataEvt.String(),
			Tags: nostr.Tags{
				{"e", badgeDefinitionEvent.GetID()},
				{"e", badgeAwardEvent.GetID()},
				{"b", a.publicKey},
			},
		},
	}
	if err := event.SignWithAlg(a.privateKey, model.SignAlgEDDSA, model.KeyAlgCurve25519); err != nil {
		return nil, errors.Wrap(err, "failed to sign profile badge event")
	}

	return event, nil
}

func (a *accounts) publishEvents(ctx context.Context, relays []string, events []*model.Event) error {
	relay := getRandomRelay(relays)
	if relay == "" {
		return nil
	}
	nostrRelay := nostr.NewRelay(ctx, relay)
	if err := nostrRelay.Connect(ctx); err != nil {
		return errors.Wrapf(err, "failed to connect to relay %s", relay)
	}
	defer nostrRelay.Close()
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
