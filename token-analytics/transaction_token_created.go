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

	hexAddr := ev.Address.String()
	if strings.Contains(strings.ToLower(hexAddr), "dead") {
		log.Info(fmt.Sprintf("Ignoring TokenCreated for dead token: %v", hexAddr))
		return nil
	}

	if err := t.createStreamForContractAddress(ctx, hexAddr); err != nil {
		return fmt.Errorf("failed to create stream to monitor contract %v: %w", hexAddr, err)
	}
	log.Info(fmt.Sprintf("Successfully created stream for bonded token: %v", hexAddr))

	return nil
}

func parseTokenType(externalAddress string) (tokenType, masterPubkeyOrXHandle string, err error) {
	if len(externalAddress) < 1 {
		return "", "", fmt.Errorf("external address too short: %s", externalAddress)
	}

	prefix := externalAddress[0:1]

	switch prefix {
	case string(PlatformIonConnectProfile):
		if len(externalAddress) < 2 {
			return "", "", fmt.Errorf("invalid IonConnect profile format: %s", externalAddress)
		}
		return TokenTypeProfile, externalAddress[1:], nil
	case string(PlatformIonConnectPost):
		parts := strings.Split(externalAddress[1:], ":")
		if len(parts) < 2 || parts[1] == "" {
			return "", "", fmt.Errorf("invalid IonConnect post format: %s", externalAddress)
		}
		return TokenTypePost, parts[1], nil
	case string(PlatformIonConnectVideo):
		parts := strings.Split(externalAddress[1:], ":")
		if len(parts) < 2 || parts[1] == "" {
			return "", "", fmt.Errorf("invalid IonConnect video format: %s", externalAddress)
		}
		return TokenTypeVideo, parts[1], nil
	case string(PlatformIonConnectArticle):
		parts := strings.Split(externalAddress[1:], ":")
		if len(parts) < 2 || parts[1] == "" {
			return "", "", fmt.Errorf("invalid IonConnect article format: %s", externalAddress)
		}
		return TokenTypeArticle, parts[1], nil
	case string(PlatformXComProfile):
		handle := externalAddress[1:]
		if handle == "" {
			return "", "", fmt.Errorf("invalid X.com profile format: %s", externalAddress)
		}

		return TokenTypeProfile, handle, nil
	case string(PlatformXComPost):
		postID := externalAddress[1:]
		if postID == "" {
			return "", "", fmt.Errorf("invalid X.com post format: %s", externalAddress)
		}

		return TokenTypePost, postID, nil
	case string(PlatformXComVideo):
		postID := externalAddress[1:]
		if postID == "" {
			return "", "", fmt.Errorf("invalid X.com video format: %s", externalAddress)
		}

		return TokenTypeVideo, postID, nil
	case string(PlatformXComArticle):
		postID := externalAddress[1:]
		if postID == "" {
			return "", "", fmt.Errorf("invalid X.com article format: %s", externalAddress)
		}

		return TokenTypeArticle, postID, nil

	default:
		return "", "", fmt.Errorf("unknown platform prefix '%s' in external address: %s", prefix, externalAddress)
	}
}
