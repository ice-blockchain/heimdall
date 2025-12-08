// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/cockroachdb/errors"
	"github.com/redis/go-redis/v9"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) UpdateTokenExternalData(ctx context.Context, externalAddress, creatorUsername, creatorDisplayName, creatorAvatar string, creatorVerified bool) error {
	query := `
		INSERT INTO users (
			created_at, updated_at, id, master_pubkey, blockchain_address, 
			external_address, username, display_name, avatar, verified, lookup, platform_group
		)
		VALUES (
			NOW(), NOW(), $1, $1, '', 
			$1, $2, $3, $4, $5, LOWER($2 || ' ' || COALESCE($3, '')), 'xcom'::platform_type
		)
		ON CONFLICT (master_pubkey) 
		DO UPDATE SET
			external_address = EXCLUDED.external_address,
			username = EXCLUDED.username,
			display_name = EXCLUDED.display_name,
			avatar = EXCLUDED.avatar,
			verified = EXCLUDED.verified,
			lookup = EXCLUDED.lookup,
			platform_group = EXCLUDED.platform_group,
			updated_at = NOW()
	`

	_, err := storage.Exec(ctx, t.ingestedDataDB, query,
		externalAddress,
		creatorUsername,
		creatorDisplayName,
		creatorAvatar,
		creatorVerified,
	)
	if err != nil {
		return fmt.Errorf("failed to upsert user external data: %w", err)
	}

	return nil
}

func (t *tokenAnalytics) fetchTopPlatformHoldersRankingsBatch(ctx context.Context, rows []*tokenRowWithTopPlatformHolders, limit int64) (map[string][]holderMetadata, map[string]*redis.ZSliceCmd, error) {
	tokenHoldersMetadata := make(map[string][]holderMetadata, len(rows))
	for _, row := range rows {
		if row.TopPlatformHoldersJSON != "" && row.TopPlatformHoldersJSON != "[]" {
			var metadata []holderMetadata
			if err := json.Unmarshal([]byte(row.TopPlatformHoldersJSON), &metadata); err != nil {
				return nil, nil, errors.Wrapf(err, "failed to parse top platform holders JSON for token %v", row.ExternalAddress)
			}
			tokenHoldersMetadata[row.ExternalAddress] = metadata
		}
	}
	rankingsCmds := make(map[string]*redis.ZSliceCmd, len(tokenHoldersMetadata))
	if responses, txErr := t.processedDataDB.TxPipelined(ctx, func(pipeliner redis.Pipeliner) error {
		for tokenAddr := range tokenHoldersMetadata {
			key := keyUserPositionOfToken(tokenAddr)
			rankingsCmds[tokenAddr] = pipeliner.ZRevRangeWithScores(ctx, key, 0, limit-1)
		}
		return nil
	}); txErr != nil {
		return nil, nil, errors.Wrap(txErr, "failed to fetch top holders rankings from Redis")
	} else {
		for _, response := range responses {
			if rerr := response.Err(); rerr != nil && !errors.Is(rerr, redis.Nil) {
				return nil, nil, errors.Wrapf(rerr, "failed to `%v`", response.FullName())
			}
		}
	}

	return tokenHoldersMetadata, rankingsCmds, nil
}

func (t *tokenAnalytics) buildTopPlatformHoldersFromRankings(row *tokenRowWithTopPlatformHolders, tokenHoldersMetadata map[string][]holderMetadata, rankingsCmds map[string]*redis.ZSliceCmd) ([]HolderPosition, error) {
	topPlatformHolders := make([]HolderPosition, 0)
	metadata, hasMetadata := tokenHoldersMetadata[row.ExternalAddress]
	if !hasMetadata {
		return topPlatformHolders, nil
	}
	rankingsCmd, hasRankings := rankingsCmds[row.ExternalAddress]
	if !hasRankings {
		log.Warn(fmt.Sprintf("No rankings command found for token %v", row.ExternalAddress))
		return topPlatformHolders, nil
	}
	rankings, err := rankingsCmd.Result()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get rankings result for token %v", row.ExternalAddress)
	}
	holderMetadataMap := make(map[string]*holderMetadata, len(metadata))
	for i := range metadata {
		holderMetadataMap[metadata[i].HolderExternalAddress] = &metadata[i]
	}

	totalSupplyFloat, err := parseTotalSupply(row.TotalSupply, row.ExternalAddress)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse total supply for token %v", row.ExternalAddress)
	}

	for rank, z := range rankings {
		userExternalAddress, ok := z.Member.(string)
		if !ok {
			continue
		}
		holderMeta, exists := holderMetadataMap[userExternalAddress]
		if !exists {
			log.Warn(fmt.Sprintf("Holder metadata not found for external_address: %v", userExternalAddress))
			continue
		}

		amountTokens := z.Score
		amountUSD := amountTokens * row.PriceUSD
		supplyShare := calculateSupplyShare(amountTokens, totalSupplyFloat)

		holderAddresses, err := buildAddressesFromExternalAddress(holderMeta.HolderExternalAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to build holder addresses from external_address %s: %w", holderMeta.HolderExternalAddress, err)
		}
		amountUint64 := uint64(amountTokens)

		topPlatformHolders = append(topPlatformHolders, HolderPosition{
			Holder: User{
				Username:  holderMeta.HolderUsername,
				Display:   holderMeta.HolderDisplay,
				Verified:  holderMeta.HolderVerified,
				Avatar:    holderMeta.HolderAvatar,
				Addresses: holderAddresses,
			},
			Rank:        uint64(rank + 1),
			Amount:      amountUint64,
			AmountUSD:   amountUSD,
			SupplyShare: supplyShare,
		})
	}

	return topPlatformHolders, nil
}

func parseTotalSupply(totalSupply, tokenAddress string) (float64, error) {
	totalSupplyBigInt := new(big.Int)
	if _, ok := totalSupplyBigInt.SetString(totalSupply, 10); !ok {
		return 0, errors.Errorf("failed to parse total supply for token %v", tokenAddress)
	}

	return weiToFloat64FromBigInt(totalSupplyBigInt), nil
}

func calculateSupplyShare(amountTokens, totalSupply float64) float64 {
	if totalSupply > 0 {
		return (amountTokens / totalSupply) * 100.0
	}

	return 0.0
}

func weiToFloat64(weiAmount int64) float64 {
	amountBigFloat := new(big.Float).SetInt64(weiAmount)
	amountBigFloat.Quo(amountBigFloat, big.NewFloat(1e18))
	result, _ := amountBigFloat.Float64()

	return result
}

func weiToUint64FromBigInt(weiAmount *big.Int) uint64 {
	if weiAmount == nil {
		return 0
	}
	amountBigFloat := new(big.Float).SetInt(weiAmount)
	amountBigFloat.Quo(amountBigFloat, big.NewFloat(1e18))
	result, _ := amountBigFloat.Uint64()

	return result
}

func weiToFloat64FromBigInt(weiAmount *big.Int) float64 {
	if weiAmount == nil {
		return 0
	}
	amountBigFloat := new(big.Float).SetInt(weiAmount)
	amountBigFloat.Quo(amountBigFloat, big.NewFloat(1e18))
	result, _ := amountBigFloat.Float64()

	return result
}

func calculatePnL(amountUSD, totalInvestedUSD float64) (pnl float64, pnlPercentage float64) {
	pnl = amountUSD - totalInvestedUSD
	pnlPercentage = 0.0
	if totalInvestedUSD > 0 {
		pnlPercentage = (pnl / totalInvestedUSD) * 100
	}

	return pnl, pnlPercentage
}
