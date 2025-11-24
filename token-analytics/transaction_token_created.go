// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/nbd-wtf/go-nostr"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/subzero/model"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) onTokenCreated(ctx context.Context, tx *txEvent, contractAddress string, ev *bondingcurve.LogTokenCreated) error {
	if !strings.EqualFold(contractAddress, t.bondingCurveContractAddress) {
		log.Debug(fmt.Sprintf("Ignoring TokenCreated from non-BondingCurve contract: %v", contractAddress))

		return nil
	}
	if err := t.saveTokenMetadata(ctx, tx, ev); err != nil {
		log.Error(fmt.Errorf("failed to save token metadata for %v: %w", ev.Address.String(), err))

		return err
	}
	if err := t.createStreamForContractAddress(ctx, ev.Address.String()); err != nil {
		tokenAddress := strings.ToLower(ev.Address.Hex())
		streamErr := fmt.Errorf("failed to create stream to monitor contract %v: %w", ev.Address.String(), err)
		if deleteErr := t.deleteTokenMetadata(ctx, tokenAddress); deleteErr != nil {
			rollbackErr := fmt.Errorf("failed to rollback token metadata for %v after stream creation failure: %w", tokenAddress, deleteErr)

			return errors.Join(streamErr, rollbackErr)
		}

		return streamErr
	}
	log.Info(fmt.Sprintf("Successfully created stream for bonded token: %v", ev.Address.String()))

	return nil
}

func (t *tokenAnalytics) saveTokenMetadata(ctx context.Context, tx *txEvent, ev *bondingcurve.LogTokenCreated) error {
	contractAddress := strings.ToLower(ev.Address.Hex())

	ionConnectAddress := ev.IonConnectAddress
	if ionConnectAddress == "" {
		return fmt.Errorf("ion_connect_address is empty for token %s", contractAddress)
	}
	tokenType, creatorMasterPubkey, err := parseTokenType(ionConnectAddress)
	if err != nil {
		return fmt.Errorf("failed to parse ion_connect_address %s: %w", ionConnectAddress, err)
	}

	_, err = storage.Exec(ctx, t.ingestedDataDB, `
		WITH user_data AS (
			SELECT username 
			FROM users 
			WHERE master_pubkey = $4
		)
		INSERT INTO tokens (
			created_at,
			updated_at,
			contract_address,
			ion_connect_address,
			ticker,
			total_supply,
			creator_master_pubkey,
			type
		)
		SELECT 
			$1, $1, $2, $3,
			(SELECT username FROM user_data),
			$5, $4, $6
		ON CONFLICT (ion_connect_address) 
		DO UPDATE SET
			updated_at = EXCLUDED.updated_at,
			total_supply = EXCLUDED.total_supply,
			creator_master_pubkey = EXCLUDED.creator_master_pubkey,
			contract_address = EXCLUDED.contract_address,
			ticker = COALESCE(EXCLUDED.ticker, tokens.ticker)
	`, tx.BlockTimestamp, contractAddress, ionConnectAddress, creatorMasterPubkey, ev.TotalSupply.String(), tokenType)
	if err != nil {
		return fmt.Errorf("failed to insert token %v: %w", contractAddress, err)
	}

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

func (t *tokenAnalytics) deleteTokenMetadata(ctx context.Context, contractAddress string) error {
	_, err := storage.Exec(ctx, t.ingestedDataDB, `DELETE FROM tokens WHERE contract_address = $1`, contractAddress)

	return fmt.Errorf("failed to delete token %v: %w", contractAddress, err)
}
