// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/cockroachdb/errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/redis/go-redis/v9"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) UpdateLoggedInUserProfile(ctx context.Context,
	masterPubkey, userExternalAddress, userUsername, userDisplayName, userAvatar string, userVerified bool,
	userBNBBSCWallet string) error {

	userQuery := `
		INSERT INTO users (
			created_at, updated_at, id, master_pubkey, blockchain_address, 
			external_address, username, display_name, avatar, verified, lookup, platform_group
		)
		VALUES (
			NOW(), NOW(), $1, $1, $2, $3, $4, $5, $6, $7, LOWER($4 || ' ' || COALESCE($5, '')), 'xcom'::platform_type
		)
		ON CONFLICT (master_pubkey) 
		DO UPDATE SET
			external_address = COALESCE(NULLIF(EXCLUDED.external_address, ''), users.external_address),
			username = COALESCE(NULLIF(EXCLUDED.username, ''), users.username),
			display_name = COALESCE(NULLIF(EXCLUDED.display_name, ''), users.display_name),
			avatar = COALESCE(NULLIF(EXCLUDED.avatar, ''), users.avatar),
			verified = EXCLUDED.verified,
			blockchain_address = COALESCE(NULLIF(EXCLUDED.blockchain_address, ''), users.blockchain_address),
			lookup = COALESCE(NULLIF(EXCLUDED.lookup, ''), users.lookup),
			platform_group = EXCLUDED.platform_group,
			updated_at = NOW()
	`

	_, err := storage.Exec(ctx, t.ingestedDataDB, userQuery,
		masterPubkey,
		userBNBBSCWallet,
		userExternalAddress,
		userUsername,
		userDisplayName,
		userAvatar,
		userVerified,
	)
	if err != nil {
		if storage.IsErr(err, storage.ErrDuplicate) {
			return errors.Wrapf(ErrDuplicate, "failed to update logged-in user profile for master pubkey: %v", userExternalAddress)
		}
		return fmt.Errorf("failed to update logged-in user profile: %w", err)
	}

	return nil
}

func (t *tokenAnalytics) UpdateTokenExternalData(ctx context.Context,
	tokenExternalAddress, userExternalAddress, userUsername, userDisplayName, userAvatar string, userVerified bool,
	userBNBBSCWallet, tokenTitle, tokenDescription, tokenImageURL string) error {

	hasUserData := userExternalAddress != "" || userBNBBSCWallet != "" || userUsername != "" ||
		userDisplayName != "" || userAvatar != ""
	hasTokenData := tokenTitle != "" || tokenDescription != "" || tokenImageURL != ""
	if !hasUserData && !hasTokenData {
		return nil
	}
	const userUpsertSQL = `
		INSERT INTO users (
			created_at, updated_at, id, master_pubkey, blockchain_address, 
			external_address, username, display_name, avatar, verified, lookup, platform_group
		)
		VALUES (
			NOW(), NOW(), $1, $1, $2, $3, $4, $5, $6, $7, LOWER($4 || ' ' || COALESCE($5, '')), 'xcom'::platform_type
		)
		ON CONFLICT (master_pubkey) 
		DO UPDATE SET
			external_address = COALESCE(NULLIF(EXCLUDED.external_address, ''), users.external_address),
			username = COALESCE(NULLIF(EXCLUDED.username, ''), users.username),
			display_name = COALESCE(NULLIF(EXCLUDED.display_name, ''), users.display_name),
			avatar = COALESCE(NULLIF(EXCLUDED.avatar, ''), users.avatar),
			verified = EXCLUDED.verified,
			blockchain_address = COALESCE(NULLIF(EXCLUDED.blockchain_address, ''), users.blockchain_address),
			lookup = CASE
				WHEN EXCLUDED.username != '' OR EXCLUDED.display_name != '' THEN
					LOWER(TRIM(COALESCE(NULLIF(EXCLUDED.username, ''), users.username) || ' ' || COALESCE(NULLIF(EXCLUDED.display_name, ''), users.display_name)))
				ELSE users.lookup
			END,
			platform_group = EXCLUDED.platform_group,
			updated_at = NOW()
`

	var query string
	var args []interface{}
	if hasUserData && hasTokenData {
		query = `
			WITH user_update AS (
				` + userUpsertSQL + `
				RETURNING master_pubkey
			)
			UPDATE tokens
			SET 
				title = CASE WHEN $8 != '' THEN $8 ELSE title END,
				description = CASE WHEN $9 != '' THEN $9 ELSE description END,
				image_url = CASE WHEN $10 != '' THEN $10 ELSE image_url END,
				updated_at = NOW()
			WHERE external_address = $11
			RETURNING contract_address;
		`
		args = []interface{}{
			userExternalAddress, userBNBBSCWallet, userExternalAddress, userUsername,
			userDisplayName, userAvatar, userVerified, tokenTitle, tokenDescription,
			tokenImageURL, tokenExternalAddress,
		}
	} else if hasUserData {
		query = userUpsertSQL + ` RETURNING master_pubkey;`
		args = []interface{}{
			userExternalAddress, userBNBBSCWallet, userExternalAddress, userUsername,
			userDisplayName, userAvatar, userVerified,
		}
	} else {
		query = `
			UPDATE tokens
			SET 
				title = CASE WHEN $1 != '' THEN $1 ELSE title END,
				description = CASE WHEN $2 != '' THEN $2 ELSE description END,
				image_url = CASE WHEN $3 != '' THEN $3 ELSE image_url END,
				updated_at = NOW()
			WHERE external_address = $4
			RETURNING contract_address;
		`
		args = []interface{}{tokenTitle, tokenDescription, tokenImageURL, tokenExternalAddress}
	}

	_, err := storage.Exec(ctx, t.ingestedDataDB, query, args...)
	if err != nil {
		if storage.IsErr(err, storage.ErrDuplicate) {
			return errors.Wrapf(ErrDuplicate, "failed to update token external data for: %v", userExternalAddress)
		}
		return fmt.Errorf("failed to update token external data: %w", err)
	}

	return nil
}

func (t *tokenAnalytics) GetTokenPricing(ctx context.Context, externalAddress string, tradeType TradeType) (amount uint64, amountUsd float64, err error) {
	type tokenInfo struct {
		BaseToken       string `db:"base_token"`
		ContractAddress string `db:"contract_address"`
		Type            string `db:"token_type"`
		Platform        string `db:"platform"`
	}
	result, err := storage.Get[tokenInfo](ctx, t.ingestedDataDB, `
		SELECT 
		    t.base_token,
		    t.contract_address,
		    "type" as token_type,
		    platform
		FROM tokens t WHERE t.external_address = $1`, externalAddress)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to find token by external address %v: %w", externalAddress, err)
	}
	baseToken := result.BaseToken
	if common.HexToAddress(baseToken).String() != common.HexToAddress(t.cfg.IONTokenAddress).String() {
		return 0, 0, fmt.Errorf("unsupported base token %v (token %v)", baseToken, externalAddress)
	}
	amountToConvert := new(big.Int).SetUint64(1e18)
	resAmount, err := t.bondingCurve.Pricing(ctx, common.HexToAddress(result.BaseToken), common.HexToAddress(result.ContractAddress), amountToConvert, tradeType == TradeTypeSell)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get pricing for token %v (%v): %w", externalAddress, result.ContractAddress, err)
	}
	basePrice := t.ionPriceUSD.Load()
	amountUsd = toUSD(resAmount, *basePrice)
	return weiToUint64FromBigInt(resAmount), amountUsd, nil
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
		if metadata[i].HolderExternalAddress != nil {
			holderMetadataMap[*metadata[i].HolderExternalAddress] = &metadata[i]
		}
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

		amountWei := tokensToWeiBigInt(amountTokens)

		holderAddresses, err := buildAddressesFromExternalAddressAndPlatform(strVal(holderMeta.HolderExternalAddress), strVal(holderMeta.HolderPlatform))
		if err != nil {
			return nil, fmt.Errorf("failed to build holder addresses from external_address %s (platform %s): %w", strVal(holderMeta.HolderExternalAddress), strVal(holderMeta.HolderPlatform), err)
		}

		topPlatformHolders = append(topPlatformHolders, HolderPosition{
			Holder: User{
				Username:  holderMeta.HolderUsername,
				Display:   holderMeta.HolderDisplay,
				Verified:  holderMeta.HolderVerified,
				Avatar:    holderMeta.HolderAvatar,
				Addresses: holderAddresses,
			},
			Rank:        uint64(rank + 1),
			Amount:      amountWei.String(),
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

func toUSD(amount *big.Int, basePrice float64) float64 {
	amountInTokens := new(big.Float).Quo(new(big.Float).SetInt(amount), big.NewFloat(1e18))
	amountInUsdBig := new(big.Float).Mul(amountInTokens, big.NewFloat(basePrice))
	amountUsd, _ := amountInUsdBig.Float64()
	return amountUsd
}

func weiToFloat64FromBigFloat(weiAmount *big.Float) float64 {
	if weiAmount == nil {
		return 0
	}
	result := new(big.Float).Quo(weiAmount, big.NewFloat(1e18))
	convertedResult, _ := result.Float64()

	return convertedResult
}

func calculatePnL(amountUSD, totalInvestedUSD float64) (pnl float64, pnlPercentage float64) {
	pnl = amountUSD - totalInvestedUSD
	pnlPercentage = 0.0
	if totalInvestedUSD > 0 {
		pnlPercentage = (pnl / totalInvestedUSD) * 100
	}

	return pnl, pnlPercentage
}

func strVal(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func strPtr(s string) *string {
	return &s
}

func tokensToWeiBigInt(tokenAmount float64) *big.Int {
	tokensBigFloat := big.NewFloat(tokenAmount)
	weiBigFloat := new(big.Float).Mul(tokensBigFloat, big.NewFloat(1e18))
	weiInt, _ := weiBigFloat.Int(nil)

	return weiInt
}
