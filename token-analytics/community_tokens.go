// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/redis/go-redis/v9"

	"github.com/ice-blockchain/heimdall/coins"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) UpdateLoggedInUserProfile(ctx context.Context,
	masterPubkey, userExternalAddress, userUsername, userDisplayName, userAvatar string, userVerified bool,
	userContentId string) error {

	userQuery := `
		INSERT INTO users (
			created_at, updated_at, id, master_pubkey, content_author_id, 
			external_address, username, display_name, avatar, verified, lookup, platform_group
		)
		VALUES (
			NOW(), NOW(), $1, $1, $2, $3, $4, $5, $6, $7, LOWER($4 || ' ' || COALESCE($5, '')), 'xcom'::platform_type
		)
		ON CONFLICT (content_author_id) 
		DO UPDATE SET
			master_pubkey = EXCLUDED.master_pubkey,
			external_address = COALESCE(NULLIF(EXCLUDED.external_address, ''), users.external_address),
			username = COALESCE(NULLIF(EXCLUDED.username, ''), users.username),
			display_name = COALESCE(NULLIF(EXCLUDED.display_name, ''), users.display_name),
			avatar = COALESCE(NULLIF(EXCLUDED.avatar, ''), users.avatar),
			verified = EXCLUDED.verified,
			lookup = CASE
				WHEN EXCLUDED.username != '' OR EXCLUDED.display_name != '' THEN
					LOWER(TRIM(COALESCE(NULLIF(EXCLUDED.username, ''), users.username) || ' ' || COALESCE(NULLIF(EXCLUDED.display_name, ''), users.display_name)))
				ELSE users.lookup
			END,
			platform_group = EXCLUDED.platform_group,
			updated_at = NOW()
	`

	_, err := storage.Exec(ctx, t.ingestedDataDB, userQuery,
		masterPubkey,
		userContentId,
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
	tokenExternalAddress, postAuthorExternalAddress, postAuthorUsername, postAuthorDisplayName, postAuthorAvatar string, postAuthorVerified bool,
	userContentId, tokenImageUrl string) error {

	ionConnectAddress, err := t.identityClient.AdaptExternalEventToIONConnectEvent(ctx, "x.com", tokenExternalAddress)
	if err != nil {
		return errors.Wrapf(err, "failed to create community token adaptor for %s", tokenExternalAddress)
	}
	log.Debug(fmt.Sprintf("Created community token adaptor for %s: %s", tokenExternalAddress, ionConnectAddress))

	query := `
		WITH post_author_update AS (
			INSERT INTO users (
				created_at, updated_at, id, master_pubkey, content_author_id, 
				external_address, username, display_name, avatar, verified, lookup, platform_group
			)
			VALUES (
				NOW(), NOW(), $1, $1, $2, $3, $4, $5, $6, $7, LOWER($4 || ' ' || COALESCE($5, '')), 'xcom'::platform_type
			)
			ON CONFLICT (content_author_id) 
			DO UPDATE SET
				master_pubkey = EXCLUDED.master_pubkey,
				external_address = COALESCE(NULLIF(EXCLUDED.external_address, ''), users.external_address),
				username = COALESCE(NULLIF(EXCLUDED.username, ''), users.username),
				display_name = COALESCE(NULLIF(EXCLUDED.display_name, ''), users.display_name),
				avatar = COALESCE(NULLIF(EXCLUDED.avatar, ''), users.avatar),
				verified = EXCLUDED.verified,
				lookup = CASE
					WHEN EXCLUDED.username != '' OR EXCLUDED.display_name != '' THEN
						LOWER(TRIM(COALESCE(NULLIF(EXCLUDED.username, ''), users.username) || ' ' || COALESCE(NULLIF(EXCLUDED.display_name, ''), users.display_name)))
					ELSE users.lookup
				END,
				platform_group = EXCLUDED.platform_group,
				updated_at = NOW()
			RETURNING 1
		)
		UPDATE tokens
		SET 
			content_author_id = $2,
			image_url = CASE WHEN $9 != '' THEN $9 ELSE image_url END,
			ion_connect_address = $8,
			updated_at = NOW()
		FROM post_author_update
		WHERE external_address = $10;
	`

	_, err = storage.Exec(ctx, t.ingestedDataDB, query,
		postAuthorExternalAddress, userContentId, postAuthorExternalAddress, postAuthorUsername,
		postAuthorDisplayName, postAuthorAvatar, postAuthorVerified, ionConnectAddress, tokenImageUrl, tokenExternalAddress,
	)
	if err != nil {
		if storage.IsErr(err, storage.ErrDuplicate) {
			return errors.Wrapf(ErrDuplicate, "failed to update token external data for: %v", postAuthorExternalAddress)
		}
		return fmt.Errorf("failed to update token external data: %w", err)
	}

	return nil
}

func (t *tokenAnalytics) GetTokenPricing(ctx context.Context, externalAddress string, tradeType TradeType, amount *big.Int) (amountOut, amountBNB *big.Int, amountUsd float64, ionPriceInUSD float64, bnbPriceInUSD float64, err error) {
	type tokenInfo struct {
		BaseToken       string `db:"base_token"`
		ContractAddress string `db:"contract_address"`
	}
	ionPrice := t.ionPriceUSD.Load()
	ionPriceInUSD = *ionPrice
	bnbPrice := t.bnbPriceUSD.Load()
	bnbPriceInUSD = *bnbPrice
	contractOrFatAddress := []byte{}
	result, err := storage.Get[tokenInfo](ctx, t.ingestedDataDB, `
		SELECT 
		    t.base_token,
		    t.contract_address
		FROM tokens t WHERE t.external_address = $1`, externalAddress)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			result = &tokenInfo{
				BaseToken: t.cfg.IONTokenAddress,
			}
			contractOrFatAddress, err = hex.DecodeString(strings.TrimPrefix(externalAddress, "0x"))
			if err != nil {
				return nil, nil, 0, *ionPrice, bnbPriceInUSD, nil
			}
			err = nil
		}
		if err != nil {
			return nil, nil, 0, 0, 0, fmt.Errorf("failed to find token by external address %v: %w", externalAddress, err)
		}
	}

	if len(contractOrFatAddress) == 0 {
		contractOrFatAddress = common.HexToAddress(result.ContractAddress).Bytes()
	}
	amountToConvert := new(big.Int).SetUint64(1e18)
	if amount != nil {
		amountToConvert = amount
	}
	toBNBRatio := ionPriceInUSD / bnbPriceInUSD
	if strings.Contains(strings.ToLower(common.HexToAddress(result.ContractAddress).String()), "dead") {
		amountUsd = toUSD(amountToConvert, *ionPrice)
		amountInBNB := new(big.Float).Mul(big.NewFloat(toBNBRatio), new(big.Float).SetInt(amountToConvert))
		amountBNB, _ = amountInBNB.Int(nil)
		return amountToConvert, amountBNB, amountUsd, *ionPrice, bnbPriceInUSD, nil
	}
	resAmount, err := t.bondingCurve.Pricing(ctx, common.HexToAddress(result.BaseToken), contractOrFatAddress, amountToConvert, tradeType == TradeTypeSell)
	if err != nil {
		return nil, nil, 0, 0, 0, fmt.Errorf("failed to get pricing for token %v (%v): %w", externalAddress, result.ContractAddress, err)
	}
	var creatorPrice float64
	amountUsd, creatorPrice, err = t.calculatePriceInUSD(ctx, weiToFloat64FromBigInt(resAmount), result.BaseToken)
	if err != nil {
		return nil, nil, 0, 0, 0, fmt.Errorf("failed to get usd price for token %v (%v base %v): %w", externalAddress, result.ContractAddress, result.BaseToken, err)
	}
	if result.BaseToken != t.cfg.IONTokenAddress {
		creatorRatio := ionPriceInUSD / creatorPrice
		resAmount, _ = new(big.Float).Mul(new(big.Float).SetInt(resAmount), big.NewFloat(creatorRatio)).Int(nil)
	}
	amountInBNB := new(big.Float).Mul(big.NewFloat(toBNBRatio), new(big.Float).SetInt(resAmount))
	amountBNB, _ = amountInBNB.Int(nil)

	return resAmount, amountBNB, amountUsd, *ionPrice, bnbPriceInUSD, nil
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

		holderAddresses, err := buildAddressesFromExternalAddressAndPlatform(strVal(holderMeta.HolderExternalAddress), strVal(holderMeta.HolderPlatform), "")
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

func (t *tokenAnalyticsUsers) GetTokenUpdates(ctx context.Context, contractAddresses []string) (map[string]coins.TokenAnalyticsToken, error) {
	result, err := storage.Select[tokenAndUserInfo](ctx, t.ingestedDataDB, `
		SELECT 
		    t.contract_address,
		    t.external_address as token_external_address,
		    COALESCE(t.title, '') as title,
		    COALESCE(t.ticker, '') as ticker,
		    COALESCE(t.image_url, '') as image_url,
		    t.price_usd
		FROM tokens t WHERE t.contract_address = ANY($1)`, contractAddresses)
	if err != nil {
		return nil, fmt.Errorf("failed to get token updates: %w", err)
	}
	tokenUpdates := make(map[string]coins.TokenAnalyticsToken, len(contractAddresses))
	for _, t := range result {
		tokenUpdates[t.ContractAddress] = t
	}
	return tokenUpdates, nil
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

func calculatePnL(amountUSD, totalInvestedUSD, totalRealizedUSD float64) (pnl float64, pnlPercentage float64) {
	totalValue := amountUSD + totalRealizedUSD
	pnl = totalValue - totalInvestedUSD
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
