// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"crypto/tls"
	"math/rand"

	"github.com/google/uuid"
	"github.com/nbd-wtf/go-nostr"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/subzero/model"
)

const (
	PlatformXCom = "x.com"
)

func (a *accounts) CreateCommunityTokenAdaptor(ctx context.Context, platform, postID string) (*CommunityTokenAdaptorResponse, error) {
	if platform != PlatformXCom {
		return nil, errors.Errorf("unsupported platform: %s", platform)
	}
	keypair, err := a.GetNextIdentityKeypairForCommunityToken(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get identity keypair")
	}
	communityTokenEvent := &model.Event{
		Event: nostr.Event{
			CreatedAt: nostr.Now(),
			Kind:      model.CustomIONKindTokenizedCommunityDefinition,
			Tags: nostr.Tags{
				{"d", uuid.New().String()},
				{"h", postID},
				{"k", "1"},
				{"platform", platform},
				{"t", "community_token"},
				{"b", keypair.PublicKey},
			},
		},
	}
	if err := communityTokenEvent.SignWithAlg(keypair.PrivateKey, model.SignAlgEDDSA, model.KeyAlgCurve25519); err != nil {
		return nil, errors.Wrap(err, "failed to sign community token event")
	}
	if err := publishEventsToRelay(ctx, keypair.PrivateKey, []string{keypair.RelayURL}, []*model.Event{communityTokenEvent}); err != nil {
		return nil, errors.Wrap(err, "failed to publish community token event")
	}
	address := communityTokenEvent.Address()

	return &CommunityTokenAdaptorResponse{
		Address: address,
	}, nil
}

func publishEventsToRelay(ctx context.Context, privateKey string, relays []string, events []*model.Event) error {
	relay := selectRandomRelay(relays)
	if relay == "" {
		return nil
	}
	if len(events) == 0 {
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
		if err := subZeroEvent.SignWithAlg(privateKey, model.SignAlgEDDSA, model.KeyAlgCurve25519); err != nil {
			return err
		}
		*event = subZeroEvent.Event

		return nil
	}); err != nil {
		return errors.Wrapf(err, "failed to auth to relay %s", relay)
	}
	nostrEvents := make([]*nostr.Event, len(events))
	for i, evt := range events {
		nostrEvents[i] = &evt.Event
	}

	if err := nostrRelay.PublishMany(ctx, nostrEvents...); err != nil {
		eventIDs := make([]string, len(events))
		for i, evt := range events {
			eventIDs[i] = evt.Event.ID
		}
		return errors.Wrapf(err, "failed to publish events: %v", eventIDs)
	}

	return nil
}

func selectRandomRelay(relays []string) string {
	if len(relays) == 0 {
		return ""
	}

	return relays[rand.Intn(len(relays))]
}
