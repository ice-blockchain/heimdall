// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"strings"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
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

	_, _, err := parseTokenType(ev.ExternalType, externalAddress)
	if err != nil {
		return fmt.Errorf("failed to parse token type %d, external_address %s: %w", ev.ExternalType, externalAddress, err)
	}

	hexAddr := ev.Address.String()
	if strings.Contains(strings.ToLower(hexAddr), "dead") {
		log.Info(fmt.Sprintf("Ignoring TokenCreated for dead token: %v", hexAddr))
		return nil
	}

	if err := t.createStreamForContractAddress(ctx, hexAddr, false); err != nil {
		return fmt.Errorf("failed to create stream to monitor contract %v: %w", hexAddr, err)
	}
	log.Info(fmt.Sprintf("Successfully created stream for bonded token: %v (type=%d, external=%s)", hexAddr, ev.ExternalType, externalAddress))

	return nil
}

func parseTokenType(externalType byte, externalAddress string) (tokenType, masterPubkeyOrXHandle string, err error) {
	if externalAddress == "" {
		return "", "", fmt.Errorf("external address is empty")
	}
	switch externalType {
	case 'a': // IonConnect Profile
		return TokenTypeProfile, externalAddress, nil
	case 'b': // IonConnect Post
		parts := strings.Split(externalAddress, ":")
		if len(parts) < 2 || parts[1] == "" {
			return "", "", fmt.Errorf("invalid IonConnect post format: %s", externalAddress)
		}
		return TokenTypePost, parts[1], nil
	case 'c': // IonConnect Video
		parts := strings.Split(externalAddress, ":")
		if len(parts) < 2 || parts[1] == "" {
			return "", "", fmt.Errorf("invalid IonConnect video format: %s", externalAddress)
		}
		return TokenTypeVideo, parts[1], nil
	case 'd': // IonConnect Article
		parts := strings.Split(externalAddress, ":")
		if len(parts) < 2 || parts[1] == "" {
			return "", "", fmt.Errorf("invalid IonConnect article format: %s", externalAddress)
		}
		return TokenTypeArticle, parts[1], nil

	case 'z': // X.com Profile
		return TokenTypeProfile, externalAddress, nil
	case 'y': // X.com Post
		return TokenTypePost, externalAddress, nil
	case 'x': // X.com Video
		return TokenTypeVideo, externalAddress, nil
	case 'w': // X.com Article
		return TokenTypeArticle, externalAddress, nil

	default:
		return "", "", fmt.Errorf("unknown externalType '%c' (%d)", externalType, externalType)
	}
}

func (t *tokenAnalytics) onUniswapPoolCreated(ctx context.Context, tx *txEvent, ev *bondingcurve.LogPoolCreated) error {
	log.Debug(fmt.Sprintf("PoolCreated: baseToken=%s, otherToken=%s, pool=%s tx=%s", ev.Token0.Hex(), ev.Token1.Hex(), ev.PoolAddress.Hex(), tx.TransactionHash))
	hexAddr := ev.PoolAddress.String()
	if strings.Contains(strings.ToLower(ev.PoolAddress.String()), "dead") ||
		strings.Contains(strings.ToLower(ev.Token0.String()), "dead") ||
		strings.Contains(strings.ToLower(ev.Token1.String()), "dead") {
		log.Info(fmt.Sprintf("Ignoring PoolCreated for dead token: %v %v %v", ev.PoolAddress.String(), ev.Token0.String(), ev.Token1.String()))
		return nil
	}
	type tokenExists struct {
		TokenExists bool `db:"token_exists"`
	}
	result, err := storage.Get[tokenExists](ctx, t.ingestedDataDB, `
		SELECT exists (SELECT 1 from tokens WHERE contract_address = $1 OR contract_address = $2) as token_exists
	`, ev.Token0.Hex(), ev.Token1.Hex())
	if err != nil {
		return fmt.Errorf("failed to find token for pool %v one of(%v, %v): %w", strings.ToLower(ev.PoolAddress.Hex()), ev.Token0.Hex(), ev.Token1.Hex(), err)
	}
	if !result.TokenExists {
		log.Info(fmt.Sprintf("Ignoring PoolCreated for dead token: %v", hexAddr))
		return nil // Not our token.
	}
	if err = t.createStreamForContractAddress(ctx, hexAddr, true); err != nil {
		return fmt.Errorf("failed to create stream to monitor uniswap pool %v: %w", hexAddr, err)
	}
	log.Info(fmt.Sprintf("Successfully created stream for uniswap pool: %v", hexAddr))
	return nil
}
