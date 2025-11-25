// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/nbd-wtf/go-nostr"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) onTokenCreated(ctx context.Context, contractAddress string, ev *bondingcurve.LogTokenCreated) error {
	if !strings.EqualFold(contractAddress, t.bondingCurveContractAddress) {
		log.Debug(fmt.Sprintf("Ignoring TokenCreated from non-BondingCurve contract: %v", contractAddress))

		return nil
	}
	ionConnectAddress := ev.IonConnectAddress
	if ionConnectAddress == "" {
		return fmt.Errorf("ion_connect_address is empty for token %s", contractAddress)
	}
	_, _, err := parseTokenType(ionConnectAddress)
	if err != nil {
		return fmt.Errorf("failed to parse ion_connect_address %s: %w", ionConnectAddress, err)
	}
	if err := t.createStreamForContractAddress(ctx, ev.Address.String()); err != nil {
		return fmt.Errorf("failed to create stream to monitor contract %v: %w", ev.Address.String(), err)
	}
	log.Info(fmt.Sprintf("Successfully created stream for bonded token: %v", ev.Address.String()))

	return nil
}

func parseTokenType(ionConnectAddress string) (tokenType, masterPubkey string, err error) {
	parts := strings.Split(ionConnectAddress, ":")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid ION Connect address format (expected kind:masterpubkey:dtag): %s", ionConnectAddress)
	}
	if parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid ION Connect address format (empty kind or masterpubkey): %s", ionConnectAddress)
	}
	masterPubkey = parts[1]
	kind, err := strconv.Atoi(parts[0])
	if err != nil {
		return "", "", fmt.Errorf("failed to parse kind from ION Connect address '%s': %w", ionConnectAddress, err)
	}
	switch kind {
	case nostr.KindProfileMetadata:
		return TokenTypeProfile, masterPubkey, nil
	case nostr.KindTextNote:
		return TokenTypePost, masterPubkey, nil
	case nostr.KindArticle:
		return TokenTypeArticle, masterPubkey, nil
	case model.CustomIONKindEditableTextNote:
		// TODO: take some type from tx as no other way to detect video?
		return TokenTypePost, masterPubkey, nil
	default:
		return "", "", fmt.Errorf("unknown nostr kind %d for ION Connect address '%s'", kind, ionConnectAddress)
	}
}
