// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync/atomic"

	"github.com/nbd-wtf/go-nostr"
	"github.com/pkg/errors"

	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
	stdtime "github.com/ice-blockchain/wintr/time"
)

const (
	identityInternalUserPrefix = "identity_internal_"
)

type (
	identityKeypair struct {
		PrivateKey     string
		PublicKey      string
		RelayURL       string
		InternalUserID string
	}

	keypairData struct {
		PrivateKey      string
		PublicKey       string
		AllRelaysInfo   []relayInfo
		WriteRelayURL   string
		RelayGroup      string
		UserID          string
		IdentityKeyName string
	}

	relayInfo struct {
		URL        string `db:"url"`
		RelayGroup string `db:"relay_group"`
		RelayType  string `db:"relay_type"`
	}
)

var (
	keypairCounter atomic.Uint64
)

func (a *accounts) InitializeIdentityKeypairs(ctx context.Context) error {
	if len(a.cfg.IdentityKeypairs) == 0 {
		log.Info("No identity keypairs configured, skipping initialization")

		return nil
	}
	allRelays, err := storage.Select[relayInfo](ctx, a.db, `
		SELECT 
			url, relay_group, relay_type
		FROM ion_connect_relays 
		ORDER BY relay_group, total_used_storage ASC
	`)
	if err != nil {
		return errors.Wrap(err, "failed to get all relays")
	}
	allRelaysInfoByGroup := make(map[string][]relayInfo)
	writeRelaysByGroup := make(map[string]string)
	relayGroupsOrder := []string{}
	seenGroups := make(map[string]bool)

	for _, r := range allRelays {
		if !seenGroups[r.RelayGroup] {
			relayGroupsOrder = append(relayGroupsOrder, r.RelayGroup)
			seenGroups[r.RelayGroup] = true
		}
		allRelaysInfoByGroup[r.RelayGroup] = append(allRelaysInfoByGroup[r.RelayGroup], *r)
		if r.RelayType == "write" {
			if _, exists := writeRelaysByGroup[r.RelayGroup]; exists {
				return errors.Errorf("relay_group %s has multiple write relays, only one is allowed", r.RelayGroup)
			}
			writeRelaysByGroup[r.RelayGroup] = r.URL
		}
	}
	if len(relayGroupsOrder) == 0 {
		return nil
	}
	keypairs := make([]keypairData, 0, len(a.cfg.IdentityKeypairs))
	for i, kp := range a.cfg.IdentityKeypairs {
		pubKey, err := model.GetPublicKey(kp.PrivateKey)
		if err != nil {
			return errors.Wrapf(err, "invalid identity private key at index %d", i)
		}
		relayGroup := relayGroupsOrder[i]

		allRelaysInfo := allRelaysInfoByGroup[relayGroup]
		if len(allRelaysInfo) == 0 {
			return errors.Errorf("no relays found for relay_group %s", relayGroup)
		}
		writeRelayURL, exists := writeRelaysByGroup[relayGroup]
		if !exists {
			return errors.Errorf("no write relay found for relay_group %s", relayGroup)
		}
		keypairs = append(keypairs, keypairData{
			PrivateKey:      kp.PrivateKey,
			PublicKey:       pubKey,
			AllRelaysInfo:   allRelaysInfo,
			WriteRelayURL:   writeRelayURL,
			RelayGroup:      relayGroup,
			UserID:          identityInternalUserPrefix + pubKey,
			IdentityKeyName: identityInternalUserPrefix + pubKey,
		})
	}
	a.keypairRelayGroups = make([]string, len(keypairs))
	for i, kp := range keypairs {
		a.keypairRelayGroups[i] = kp.RelayGroup
	}
	if err := a.createInternalIdentityUsers(ctx, keypairs); err != nil {
		return errors.Wrap(err, "failed to create internal identity users")
	}
	for i, kp := range keypairs {
		if err := a.publishRelayListEvent(ctx, kp.PrivateKey, kp.WriteRelayURL, kp.AllRelaysInfo); err != nil {
			log.Error(errors.Wrapf(err, "failed to publish relay list for keypair %d: %s", i, kp.PublicKey))
		}
		log.Info(fmt.Sprintf("Identity keypair %d initialized: %s (relay group: %s, relay: %s, user: %s)", i, kp.PublicKey, kp.RelayGroup, kp.WriteRelayURL, kp.UserID))
	}

	return nil
}

func (a *accounts) createInternalIdentityUsers(ctx context.Context, keypairs []keypairData) error {
	if len(keypairs) == 0 {
		return nil
	}
	nowTime := stdtime.Now()
	var values []string
	var args []interface{}
	argIdx := 1
	for _, kp := range keypairs {
		relayURLs := make([]string, len(kp.AllRelaysInfo))
		for i, r := range kp.AllRelaysInfo {
			relayURLs[i] = r.URL
		}

		values = append(values, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, ARRAY[]::TEXT[], $%d::TEXT[])",
			argIdx, argIdx, argIdx+1, argIdx+2, argIdx+3, argIdx+4))
		args = append(args, nowTime, kp.UserID, kp.IdentityKeyName, kp.PublicKey, relayURLs)
		argIdx += 5
	}
	sql := fmt.Sprintf(`
		INSERT INTO users (
			created_at, updated_at, id, identity_key_name, master_pubkey, clients, ion_connect_relays
		) VALUES %s
		ON CONFLICT (master_pubkey) DO NOTHING
	`, strings.Join(values, ", "))
	if _, err := storage.Exec(ctx, a.db, sql, args...); err != nil {
		return errors.Wrap(err, "failed to execute bulk insert")
	}

	return nil
}

func (a *accounts) publishRelayListEvent(ctx context.Context, privateKey, publishToRelayURL string, allRelays []relayInfo) error {
	pubkey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		return errors.Wrap(err, "failed to derive public key")
	}
	tags := make(nostr.Tags, 0, len(allRelays)+1)
	tags = append(tags, nostr.Tag{"b", pubkey})
	for _, r := range allRelays {
		tags = append(tags, nostr.Tag{"r", r.URL, r.RelayType})
	}

	relayListEvent := &model.Event{
		Event: nostr.Event{
			CreatedAt: nostr.Now(),
			Kind:      nostr.KindRelayListMetadata,
			Tags:      tags,
		},
	}
	if err := relayListEvent.SignWithAlg(privateKey, model.SignAlgEDDSA, model.KeyAlgCurve25519); err != nil {
		return errors.Wrap(err, "failed to sign relay list event")
	}

	return errors.Wrap(publishEventsToRelay(ctx, privateKey, []string{publishToRelayURL}, []*model.Event{relayListEvent}), "failed to publish relay list event")
}

func (a *accounts) GetNextIdentityKeypairForCommunityToken(ctx context.Context) (*identityKeypair, error) {
	idx := int(keypairCounter.Add(1)-1) % len(a.cfg.IdentityKeypairs)
	kp := a.cfg.IdentityKeypairs[idx]
	pubKey, err := model.GetPublicKey(kp.PrivateKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get public key for keypair %d", idx)
	}
	if idx >= len(a.keypairRelayGroups) {
		return nil, errors.Errorf("relay group not found for keypair %d (keypairs not initialized)", idx)
	}
	relayGroup := a.keypairRelayGroups[idx]
	type relayInfo struct {
		URL string `db:"url"`
	}
	relays, err := storage.Select[relayInfo](ctx, a.db, `
		SELECT url FROM ion_connect_relays 
		WHERE relay_group = $1 
		AND relay_type = 'write'
		ORDER BY total_used_storage ASC
	`, relayGroup)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get relays for relay_group %s", relayGroup)
	}
	if len(relays) == 0 {
		return nil, errors.Errorf("no healthy relays found for relay_group %s", relayGroup)
	}
	selectedRelay := relays[rand.Intn(len(relays))].URL
	keypair := &identityKeypair{
		PrivateKey:     kp.PrivateKey,
		PublicKey:      pubKey,
		RelayURL:       selectedRelay,
		InternalUserID: identityInternalUserPrefix + pubKey,
	}

	return keypair, nil
}
