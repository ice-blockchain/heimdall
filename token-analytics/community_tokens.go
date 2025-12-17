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
	postAuthorContentId, tokenTitle, tokenDescription, tokenImageURL string) error {

	hasPostAuthorData := postAuthorContentId != "" || postAuthorUsername != "" || postAuthorDisplayName != "" || postAuthorAvatar != ""
	hasTokenData := tokenTitle != "" || tokenDescription != "" || tokenImageURL != ""
	if !hasPostAuthorData && !hasTokenData {
		return nil
	}
	const postAuthorUpsertSQL = `
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

	var query string
	var args []interface{}
	if hasPostAuthorData && hasTokenData {
		query = `
			WITH post_author_update AS (
				` + postAuthorUpsertSQL + `
			)
			UPDATE tokens
			SET 
				content_author_id = $2,
				title = CASE WHEN $8 != '' THEN $8 ELSE title END,
				description = CASE WHEN $9 != '' THEN $9 ELSE description END,
				image_url = CASE WHEN $10 != '' THEN $10 ELSE image_url END,
				updated_at = NOW()
			WHERE external_address = $11;
		`
		args = []interface{}{
			postAuthorExternalAddress, postAuthorContentId, postAuthorExternalAddress, postAuthorUsername,
			postAuthorDisplayName, postAuthorAvatar, postAuthorVerified, tokenTitle, tokenDescription,
			tokenImageURL, tokenExternalAddress,
		}
	} else if hasPostAuthorData {
		query = postAuthorUpsertSQL + `;`
		args = []interface{}{
			postAuthorExternalAddress, postAuthorContentId, postAuthorExternalAddress, postAuthorUsername,
			postAuthorDisplayName, postAuthorAvatar, postAuthorVerified,
		}
	} else {
		query = `
			UPDATE tokens
			SET 
				title = CASE WHEN $1 != '' THEN $1 ELSE title END,
				description = CASE WHEN $2 != '' THEN $2 ELSE description END,
				image_url = CASE WHEN $3 != '' THEN $3 ELSE image_url END,
				updated_at = NOW()
			WHERE external_address = $4;
		`
		args = []interface{}{tokenTitle, tokenDescription, tokenImageURL, tokenExternalAddress}
	}

	_, err := storage.Exec(ctx, t.ingestedDataDB, query, args...)
	if err != nil {
		if storage.IsErr(err, storage.ErrDuplicate) {
			return errors.Wrapf(ErrDuplicate, "failed to update token external data for: %v", postAuthorExternalAddress)
		}
		return fmt.Errorf("failed to update token external data: %w", err)
	}

	return nil
}

func (t *tokenAnalytics) GetTokenPricing(ctx context.Context, externalAddress string, tradeType TradeType, amount *big.Int) (amountOut, amountBNB *big.Int, amountUsd float64, err error) {
	type tokenInfo struct {
		BaseToken       string `db:"base_token"`
		ContractAddress string `db:"contract_address"`
	}
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
				return nil, nil, 0, errors.Errorf("invalid address %v", externalAddress)
			}
			err = nil
		}
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to find token by external address %v: %w", externalAddress, err)
		}
	}

	baseToken := result.BaseToken
	if len(contractOrFatAddress) == 0 {
		contractOrFatAddress = common.HexToAddress(result.ContractAddress).Bytes()
	}
	if common.HexToAddress(baseToken).String() != common.HexToAddress(t.cfg.IONTokenAddress).String() {
		return nil, nil, 0, fmt.Errorf("unsupported base token %v (token %v)", baseToken, externalAddress)
	}
	amountToConvert := new(big.Int).SetUint64(1e18)
	if amount != nil {
		amountToConvert = amount
	}
	if strings.Contains(strings.ToLower(common.HexToAddress(result.ContractAddress).String()), "dead") {
		basePrice := t.ionPriceUSD.Load()
		amountUsd = toUSD(amountToConvert, *basePrice)
		return amountToConvert, new(big.Int).Mul(new(big.Int).SetInt64(int64(randInt(100000))), amountToConvert), amountUsd, nil
	}
	resAmount, err := t.bondingCurve.Pricing(ctx, common.HexToAddress(result.BaseToken), contractOrFatAddress, amountToConvert, tradeType == TradeTypeSell)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to get pricing for token %v (%v): %w", externalAddress, result.ContractAddress, err)
	}
	basePrice := t.ionPriceUSD.Load()
	amountUsd = toUSD(resAmount, *basePrice)
	return resAmount, new(big.Int).Mul(new(big.Int).SetInt64(int64(randInt(100000))), resAmount), amountUsd, nil
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
