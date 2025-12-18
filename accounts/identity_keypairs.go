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
		WriteRelayURLs  []string
		UserID          string
		IdentityKeyName string
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
	type relayInfo struct {
		URL        string `db:"url"`
		RelayGroup string `db:"relay_group"`
		RelayType  string `db:"relay_type"`
	}
	allRelays, err := storage.Select[relayInfo](ctx, a.db, `
		SELECT url, relay_group, relay_type FROM ion_connect_relays 
		ORDER BY relay_group, total_used_storage ASC
	`)
	if err != nil {
		return errors.Wrap(err, "failed to get all relays")
	}
	writeRelaysByGroup := make(map[string][]string)
	for _, r := range allRelays {
		if r.RelayType == "write" {
			writeRelaysByGroup[r.RelayGroup] = append(writeRelaysByGroup[r.RelayGroup], r.URL)
		}
	}

	keypairs := make([]keypairData, 0, len(a.cfg.IdentityKeypairs))
	for i, kp := range a.cfg.IdentityKeypairs {
		if kp.PrivateKey == "" {
			return errors.Errorf("identity keypair %d has empty privateKey", i)
		}
		if kp.RelayGroup == "" {
			return errors.Errorf("identity keypair %d has empty relayGroup", i)
		}
		pubKey, err := model.GetPublicKey(kp.PrivateKey)
		if err != nil {
			return errors.Wrapf(err, "invalid identity private key at index %d", i)
		}
		writeRelayURLs := writeRelaysByGroup[kp.RelayGroup]
		if len(writeRelayURLs) == 0 {
			return errors.Errorf("no write relays found for relay_group %s", kp.RelayGroup)
		}

		keypairs = append(keypairs, keypairData{
			PrivateKey:      kp.PrivateKey,
			PublicKey:       pubKey,
			WriteRelayURLs:  writeRelayURLs,
			UserID:          identityInternalUserPrefix + pubKey,
			IdentityKeyName: identityInternalUserPrefix + pubKey,
		})
	}
	if err := a.createInternalIdentityUsers(ctx, keypairs); err != nil {
		return errors.Wrap(err, "failed to create internal identity users")
	}
	for i, kp := range keypairs {
		writeRelay := kp.WriteRelayURLs[rand.Intn(len(kp.WriteRelayURLs))]
		if err := a.publishRelayListEvent(ctx, kp.PrivateKey, writeRelay); err != nil {
			log.Error(errors.Wrapf(err, "failed to publish relay list for keypair %d: %s", i, kp.PublicKey))
		}
		log.Info(fmt.Sprintf("Identity keypair %d initialized: %s (relay: %s, user: %s)", i, kp.PublicKey, writeRelay, kp.UserID))
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
		values = append(values, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, ARRAY[]::TEXT[], $%d::TEXT[])",
			argIdx, argIdx, argIdx+1, argIdx+2, argIdx+3, argIdx+4))
		args = append(args, nowTime, kp.UserID, kp.IdentityKeyName, kp.PublicKey, kp.WriteRelayURLs)
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
	log.Info(fmt.Sprintf("Created %d internal identity users", len(keypairs)))

	return nil
}

func (a *accounts) publishRelayListEvent(ctx context.Context, privateKey, relayURL string) error {
	relayListEvent := &model.Event{
		Event: nostr.Event{
			CreatedAt: nostr.Now(),
			Kind:      nostr.KindRelayListMetadata,
			Tags: nostr.Tags{
				{"r", relayURL, "write"},
			},
			Content: "",
		},
	}
	if err := relayListEvent.SignWithAlg(privateKey, model.SignAlgEDDSA, model.KeyAlgCurve25519); err != nil {
		return errors.Wrap(err, "failed to sign relay list event")
	}

	return errors.Wrap(publishEventsToRelay(ctx, privateKey, []string{relayURL}, []*model.Event{relayListEvent}), "failed to publish relay list event")
}

func (a *accounts) GetNextIdentityKeypairForCommunityToken(ctx context.Context) (*identityKeypair, error) {
	idx := int(keypairCounter.Add(1)-1) % len(a.cfg.IdentityKeypairs)
	kp := a.cfg.IdentityKeypairs[idx]
	pubKey, err := model.GetPublicKey(kp.PrivateKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get public key for keypair %d", idx)
	}
	type relayInfo struct {
		URL string `db:"url"`
	}
	relays, err := storage.Select[relayInfo](ctx, a.db, `
		SELECT url FROM ion_connect_relays 
		WHERE relay_group = $1 
		AND unhealthy_started_at IS NULL
		ORDER BY total_used_storage ASC
	`, kp.RelayGroup)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get relays for relay_group %s", kp.RelayGroup)
	}
	if len(relays) == 0 {
		return nil, errors.Errorf("no healthy relays found for relay_group %s", kp.RelayGroup)
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
