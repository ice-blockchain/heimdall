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
	externalAddress := ev.ExternalAddress
	if externalAddress == "" {
		return fmt.Errorf("external_address is empty for token %s", contractAddress)
	}
	_, _, err := parseTokenType(externalAddress)
	if err != nil {
		return fmt.Errorf("failed to parse external_address %s: %w", externalAddress, err)
	}
	if err := t.createStreamForContractAddress(ctx, ev.Address.String()); err != nil {
		return fmt.Errorf("failed to create stream to monitor contract %v: %w", ev.Address.String(), err)
	}
	log.Info(fmt.Sprintf("Successfully created stream for bonded token: %v", ev.Address.String()))

	return nil
}

func parseTokenType(externalAddress string) (tokenType, masterPubkey string, err error) {
	parts := strings.Split(externalAddress, ":")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid external address format (expected kind:masterpubkey:dtag): %s", externalAddress)
	}
	if parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid external address format (empty kind or masterpubkey): %s", externalAddress)
	}
	masterPubkey = parts[1]
	kind, err := strconv.Atoi(parts[0])
	if err != nil {
		return "", "", fmt.Errorf("failed to parse kind from external address '%s': %w", externalAddress, err)
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
		return "", "", fmt.Errorf("unknown nostr kind %d for external address '%s'", kind, externalAddress)
	}
}
