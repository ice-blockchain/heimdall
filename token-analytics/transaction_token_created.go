// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"strings"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) onTokenCreated(ctx context.Context, contractAddress string, ev *bondingcurve.LogTokenCreated) error {
	if !strings.EqualFold(contractAddress, t.tokenFactoryContractAddress) {
		log.Debug(fmt.Sprintf("Ignoring TokenCreated from non-TokenFactory contract: got %v, expected %v", contractAddress, t.tokenFactoryContractAddress))

		return nil
	}
	externalAddress := ev.ExternalAddress
	if externalAddress == "" {
		return fmt.Errorf("external_address is empty for token %s", contractAddress)
	}

	_, _, _, err := parseTokenType(ev.ExternalType, externalAddress)
	if err != nil {
		return fmt.Errorf("failed to parse token type %d, external_address %s: %w", ev.ExternalType, externalAddress, err)
	}
	log.Debug(fmt.Sprintf("TokenCreated: external_address=%s, external_type=%d, contract_address=%s", externalAddress, ev.ExternalType, contractAddress))

	return nil
}

func parseTokenType(externalType byte, externalAddress string) (tokenType, platform, masterPubkeyOrXHandle string, err error) {
	if externalAddress == "" {
		return "", "", "", fmt.Errorf("external address is empty")
	}
	switch externalType {
	case 'a': // IonConnect Profile
		return TokenTypeProfile, PlatformGroupIonConnect, externalAddress, nil
	case 'b': // IonConnect Post
		parts := strings.Split(externalAddress, ":")
		if len(parts) < 2 || parts[1] == "" {
			return "", "", "", fmt.Errorf("invalid IonConnect post format: %s", externalAddress)
		}
		return TokenTypePost, PlatformGroupIonConnect, parts[1], nil
	case 'c': // IonConnect Video
		parts := strings.Split(externalAddress, ":")
		if len(parts) < 2 || parts[1] == "" {
			return "", "", "", fmt.Errorf("invalid IonConnect video format: %s", externalAddress)
		}
		return TokenTypeVideo, PlatformGroupIonConnect, parts[1], nil
	case 'd': // IonConnect Article
		parts := strings.Split(externalAddress, ":")
		if len(parts) < 2 || parts[1] == "" {
			return "", "", "", fmt.Errorf("invalid IonConnect article format: %s", externalAddress)
		}
		return TokenTypeArticle, PlatformGroupIonConnect, parts[1], nil

	case 'z': // X.com Profile
		return TokenTypeProfile, PlatformGroupXCom, externalAddress, nil
	case 'y': // X.com Post
		return TokenTypePost, PlatformGroupXCom, externalAddress, nil
	case 'x': // X.com Video
		return TokenTypeVideo, PlatformGroupXCom, externalAddress, nil
	case 'w': // X.com Article
		return TokenTypeArticle, PlatformGroupXCom, externalAddress, nil

	default:
		return "", "", "", fmt.Errorf("unknown externalType '%c' (%d)", externalType, externalType)
	}
}

func (t *tokenAnalytics) onUniswapPoolCreated(ctx context.Context, tx *txEvent, ev *bondingcurve.LogPoolCreated) error {
	log.Debug(fmt.Sprintf("PoolCreated: baseToken=%s, otherToken=%s, pool=%s tx=%s", ev.Token0.Hex(), ev.Token1.Hex(), ev.PoolAddress.Hex(), tx.TransactionHash))

	return nil
}
