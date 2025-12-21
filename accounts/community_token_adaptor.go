// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"strings"

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
	if err := publishEventsToRelay(ctx, keypair.PrivateKey, keypair.RelayURL, []*model.Event{communityTokenEvent}); err != nil {
		return nil, errors.Wrap(err, "failed to publish community token event")
	}
	address := communityTokenEvent.Address()

	return &CommunityTokenAdaptorResponse{
		Address: address,
	}, nil
}

func publishEventsToRelay(ctx context.Context, privateKey string, relay string, events []*model.Event) error {
	nostrEvents := make([]*nostr.Event, len(events))
	for i, evt := range events {
		nostrEvents[i] = &evt.Event
	}
	nostrRelay := nostr.NewRelay(ctx, relay, nostr.WithSignatureChecker(func(e *nostr.Event) bool {
		subzeroEvent := model.Event{Event: *e}
		ok, err := subzeroEvent.CheckSignature()

		return ok && err == nil
	}))
	if err := nostrRelay.Connect(ctx); err != nil {
		return errors.Wrapf(err, "failed to connect to relay %s", relay)
	}
	defer nostrRelay.Close()

	err := nostrRelay.Publish(ctx, events[0].Event)
	if err != nil {
		if strings.Contains(err.Error(), "auth-required:") {
			err = errors.Wrap(nostrRelay.Auth(ctx, func(event *nostr.Event) error {
				subZeroEvent := model.Event{Event: *event}
				if err := subZeroEvent.SignWithAlg(privateKey, model.SignAlgEDDSA, model.KeyAlgCurve25519); err != nil {
					return err
				}
				*event = subZeroEvent.Event

				return nil
			}), "failed to authenticate to relay")
			if err != nil {
				return errors.Wrapf(err, "failed to auth to relay %s", relay)
			}
		} else {
			return errors.Wrapf(err, "failed to publish event to relay %s", relay)
		}
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
