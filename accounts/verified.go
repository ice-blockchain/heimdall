// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/rand"
	"strconv"

	"github.com/google/uuid"
	"github.com/nbd-wtf/go-nostr"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
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
	userData, err := a.getNextUserFromVerifiedUsersQueue(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to get verified users batch")
	}
	if userData == nil {
		return nil
	}
	if err := a.processVerifiedUser(ctx, userData); err != nil {
		return errors.Wrapf(err, "failed to process verified user %s", userData.MasterPubKey)
	}

	return nil
}

func (a *accounts) processVerifiedUser(ctx context.Context, userData *verifiedUserQueueData) error {
	badgeDefinitionEvent, badgeAwardEvent, err := a.generateVerificationEvents(userData.MasterPubKey)
	if err != nil {
		return errors.Wrap(err, "failed to generate verification events")
	}
	ephemeralEvent, err := a.generateEphemeralVerificationEvent(userData, badgeDefinitionEvent, badgeAwardEvent)
	if err != nil {
		return errors.Wrap(err, "failed to generate ephemeral verification event")
	}
	if err := a.markUserAsVerified(ctx, userData.MasterPubKey); err != nil {
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
			u.master_pubkey,
			u.ion_connect_relays,
			u.username
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

func (a *accounts) markUserAsVerified(ctx context.Context, masterPubKey string) error {
	query := `
		WITH updated AS (
			UPDATE users SET verified = true 
			WHERE master_pubkey = $1
			RETURNING id
		)
		DELETE FROM verified_users_sync_queue WHERE user_id = (SELECT id FROM updated)
	`
	_, err := storage.Exec(ctx, a.db, query, masterPubKey)
	if err != nil {
		return errors.Wrapf(err, "failed to mark user: %s as verified", masterPubKey)
	}

	return nil
}

func (a *accounts) generateVerificationEvents(masterPubKey string) (badgeDefinitionEvent, badgeAwardEvent *model.Event, err error) {
	now := nostr.Now()
	dUuid, err := uuid.NewV7()
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate UUID")
	}
	badgeDefinitionEvent = &model.Event{
		Event: nostr.Event{
			CreatedAt: now,
			Kind:      nostr.KindBadgeDefinition,
			Tags: nostr.Tags{
				{"d", verifiedBadgeDTag + "-" + dUuid.String()},
				{"name", verifiedBadgeName},
				{"description", verifiedBadgeDescription},
			},
		},
	}
	for key, image := range verifiedBadgeImage {
		badgeDefinitionEvent.Event.Tags = append(badgeDefinitionEvent.Event.Tags, nostr.Tag{"image", image, key})
	}
	for key, thumbnail := range verifiedBadgeThumbnail {
		badgeDefinitionEvent.Event.Tags = append(badgeDefinitionEvent.Event.Tags, nostr.Tag{"thumb", thumbnail, key})
	}
	if err := badgeDefinitionEvent.SignWithAlg(a.privateKey, model.SignAlgEDDSA, model.KeyAlgCurve25519); err != nil {
		return nil, nil, errors.Wrap(err, "failed to sign badge definition event")
	}
	badgeAwardEvent = &model.Event{
		Event: nostr.Event{
			CreatedAt: now,
			Kind:      nostr.KindBadgeAward,
			Tags: nostr.Tags{
				{"a", strconv.Itoa(nostr.KindBadgeDefinition) + ":" + a.publicKey + ":" + verifiedBadgeDTag},
				{"p", masterPubKey},
			},
		},
	}
	if err := badgeAwardEvent.SignWithAlg(a.privateKey, model.SignAlgEDDSA, model.KeyAlgCurve25519); err != nil {
		return nil, nil, errors.Wrap(err, "failed to sign badge award event")
	}

	return badgeDefinitionEvent, badgeAwardEvent, nil
}

func (a *accounts) generateEphemeralVerificationEvent(userData *verifiedUserQueueData, badgeDefinitionEvent, badgeAwardEvent *model.Event) (*model.Event, error) {
	now := nostr.Now()
	fmt.Printf("userData.Username: %s\n", userData.Username)
	userProfileMetadataEvent := &model.Event{
		Event: nostr.Event{
			CreatedAt: now,
			Kind:      nostr.KindProfileMetadata,
			Content:   `{"name":"` + userData.Username + `"}`,
		},
	}
	if err := userProfileMetadataEvent.SignWithAlg(a.privateKey, model.SignAlgEDDSA, model.KeyAlgCurve25519); err != nil {
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
	tlsConfig, err := createTLSConfig(a.cfg.CaCert)
	if err != nil {
		return errors.Wrap(err, "failed to create TLS config")
	}
	nostrRelay, err := connectToRelay(ctx, relay, tlsConfig)
	if err != nil {
		return errors.Wrapf(err, "failed to connect to relay %s", relay)
	}
	defer nostrRelay.Close()
	_ = nostrRelay.Publish(ctx, events[0].Event)
	if err = nostrRelay.Auth(ctx, func(event *nostr.Event) error {
		subZeroEvent := model.Event{Event: *event}
		if err := subZeroEvent.SignWithAlg(a.privateKey, model.SignAlgEDDSA, model.KeyAlgCurve25519); err != nil {
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

func createTLSConfig(caFile string) (*tls.Config, error) {
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM([]byte(caFile)); !ok {
		return nil, errors.New("failed to append CA certificate to cert pool")
	}
	tlsConfig := &tls.Config{
		RootCAs:    caCertPool,
		MinVersion: tls.VersionTLS13,
	}

	return tlsConfig, nil
}

func connectToRelay(ctx context.Context, url string, conf *tls.Config) (*nostr.Relay, error) {
	relay := nostr.NewRelay(ctx, url, nostr.WithSignatureChecker(func(e *nostr.Event) bool {
		subzeroEvent := model.Event{Event: *e}
		ok, _ := subzeroEvent.CheckSignature()

		return ok
	}))
	err := relay.ConnectWithTLS(ctx, conf)
	if err != nil {
		return nil, errors.Wrapf(err, "can't connect to the relays")
	}

	return relay, nil
}

func getRandomRelay(relays []string) string {
	if len(relays) == 0 {
		return ""
	}

	return relays[rand.Intn(len(relays))]
}
