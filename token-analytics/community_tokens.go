// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"github.com/nbd-wtf/go-nostr"
	"github.com/redis/go-redis/v9"

	"github.com/ice-blockchain/heimdall/coins"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) UpdateLoggedInUserProfile(ctx context.Context,
	masterPubkey, userExternalAddress, userUsername, userDisplayName, userAvatar string, userVerified bool,
	userContentId string) error {
	uuid, _ := uuid.NewV7()
	id := uuid.String()
	mergeQuery := `
		MERGE INTO users AS target
		USING (
			SELECT 
				$1::TEXT AS id,
				$2::TEXT AS master_pubkey,
				NULLIF($3, '')::TEXT AS content_author_id,
				$4::TEXT AS external_address,
				$5::TEXT AS username,
				$6::TEXT AS display_name,
				$7::TEXT AS avatar,
				$8::BOOLEAN AS verified
		) AS source
		ON (
			target.content_author_id IS NULL
			AND target.external_address = source.external_address
		)
		WHEN MATCHED THEN
			UPDATE SET
				content_author_id = source.content_author_id,
				updated_at = NOW()
		WHEN NOT MATCHED THEN
			INSERT (
				created_at, updated_at, id, master_pubkey, content_author_id,
				external_address, username, display_name, avatar, verified, lookup, platform_group
			)
			VALUES (
				NOW(), NOW(), source.id, source.master_pubkey, source.content_author_id,
				source.external_address, source.username, source.display_name, source.avatar, source.verified,
				LOWER(source.username || ' ' || COALESCE(source.display_name, '')), 'xcom'::platform_type
			)
	`

	_, err := storage.Exec(ctx, t.ingestedDataDB, mergeQuery,
		id,
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

	userId := postAuthorExternalAddress
	if userId == "" {
		userId = userContentId
	}

	query := `
		WITH post_author_update AS (
			INSERT INTO users (
				created_at, updated_at, id, master_pubkey, content_author_id, 
				external_address, username, display_name, avatar, verified, lookup, platform_group
			)
			VALUES (
				NOW(), NOW(), $1, $2, $3, $4, $5, $6, $7, $8, LOWER($5 || ' ' || COALESCE($6, '')), 'xcom'::platform_type
			)
			ON CONFLICT (id) 
			DO UPDATE SET
				master_pubkey = CASE WHEN EXCLUDED.master_pubkey != '' THEN EXCLUDED.master_pubkey ELSE users.master_pubkey END,
				content_author_id = COALESCE(NULLIF(EXCLUDED.content_author_id, ''), users.content_author_id),
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
			RETURNING content_author_id
		)
		INSERT INTO tokens (
			created_at, updated_at, contract_address, external_address, content_author_id,
			image_url, ion_connect_address, platform, type, lookup
		)
		SELECT 
			NOW(), NOW(), 
			NULL,  -- contract_address = NULL for pending tokens
			$11,
			pau.content_author_id,
			NULLIF($10, ''),
			$9,
			'xcom'::platform_type,
			'post',
			LOWER(TRIM(COALESCE($11, '') || ' ' || COALESCE($5, '') || ' ' || COALESCE($6, '')))
		FROM post_author_update pau
		ON CONFLICT (external_address) 
		DO UPDATE SET
			content_author_id = COALESCE(EXCLUDED.content_author_id, tokens.content_author_id),
			image_url = CASE WHEN EXCLUDED.image_url IS NOT NULL THEN EXCLUDED.image_url ELSE tokens.image_url END,
			ion_connect_address = COALESCE(EXCLUDED.ion_connect_address, tokens.ion_connect_address),
			updated_at = NOW();
	`

	_, err = storage.Exec(ctx, t.ingestedDataDB, query,
		userId, postAuthorExternalAddress, userContentId, postAuthorExternalAddress,
		postAuthorUsername, postAuthorDisplayName, postAuthorAvatar, postAuthorVerified,
		ionConnectAddress, tokenImageUrl, tokenExternalAddress,
	)
	if err != nil {
		if storage.IsErr(err, storage.ErrDuplicate) {
			return errors.Wrapf(ErrDuplicate, "failed to update token external data for: %v", postAuthorExternalAddress)
		}
		return fmt.Errorf("failed to update token external data: %w", err)
	}

	return nil
}

func (t *tokenAnalytics) GetTokenPricing(ctx context.Context, externalAddress string, tradeType TradeType, amount *big.Int) (pricing *Pricing, err error) {
	type tokenInfo struct {
		BaseToken       string  `db:"base_token"`
		ContractAddress string  `db:"contract_address"`
		PriceModel      string  `db:"price_model"`
		TotalSupply     string  `db:"total_supply"`
		Type            string  `db:"type"`
		StartPrice      string  `db:"start_price"`
		EndPrice        string  `db:"end_price"`
		FeeSponsor      *string `db:"fee_sponsor"`
	}
	ionPrice := t.ionPriceUSD.Load()
	ionPriceInUSD := *ionPrice
	bnbPrice := t.bnbPriceUSD.Load()
	bnbPriceInUSD := *bnbPrice
	contractOrFatAddress := []byte{}
	result, err := storage.Get[tokenInfo](ctx, t.ingestedDataDB, `
		SELECT 
		    t.base_token,
		    t."type",
		    t.contract_address,
			t.price_model,
			t.total_supply,
			t.start_price,
			t.end_price
		FROM tokens t WHERE t.external_address = $1`, externalAddress)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			var baseToken string
			if strings.HasPrefix(externalAddress, fatAddressV2Prefix) {
				decodedBytes, hexErr := hex.DecodeString(strings.TrimPrefix(externalAddress, "0x"))
				if hexErr != nil {
					return nil, fmt.Errorf("invalid Fat Address V2 format: %w", hexErr)
				}

				// If this is a Double Fat Address (recordsCount == 2)
				if len(decodedBytes) >= 2 && decodedBytes[1] == 2 {
					allTokens, allTypes, _, _, extractErr := extractAllTokensFromFatAddress(decodedBytes)
					if extractErr != nil {
						return nil, fmt.Errorf("failed to parse Double Fat Address V2: %w", extractErr)
					}
					if len(allTokens) != 2 {
						return nil, fmt.Errorf("expected 2 tokens in Double Fat Address V2, got %d", len(allTokens))
					}

					creatorExternalAddress := allTokens[0]
					contractOrFatAddress = decodedBytes

					creatorToken, creatorErr := storage.Get[tokenInfo](ctx, t.ingestedDataDB, `
						SELECT contract_address, base_token 
						FROM tokens 
						WHERE external_address = $1`, creatorExternalAddress)

					if creatorErr != nil && !storage.IsErr(creatorErr, storage.ErrNotFound) {
						return nil, fmt.Errorf("failed to query creator token %s: %w", creatorExternalAddress, creatorErr)
					}

					if creatorErr == nil && creatorToken.ContractAddress != "" {
						baseToken = creatorToken.ContractAddress
					} else {
						baseToken, err = t.determineBaseTokenFromExternalAddress(ctx, creatorExternalAddress)
						if err != nil {
							return nil, fmt.Errorf("failed to determine base token for creator %s: %w", creatorExternalAddress, err)
						}
					}
					tokenStartParams, ok := t.cfg.BondingCurve.CreateTokenDefaults[allTypes[1]]
					if !ok {
						return nil, fmt.Errorf("token type %s not found in bonding curve config", allTypes[1])
					}
					result = &tokenInfo{
						BaseToken:       baseToken,
						ContractAddress: "",
						PriceModel:      tokenStartParams.BondingCurveAlgAddress,
						TotalSupply:     tokenStartParams.EmissionVolume,
						Type:            allTypes[1],
						StartPrice:      tokenStartParams.InitialPrice,
						EndPrice:        tokenStartParams.FinalPrice,
						FeeSponsor:      &tokenStartParams.FeeSponsorAddress,
					}
					err = nil
				} else {
					// Single Fat Address
					allTokens, allTypes, _, _, extractErr := extractAllTokensFromFatAddress(decodedBytes)
					if extractErr != nil {
						return nil, fmt.Errorf("failed to parse Fat Address V2: %w", extractErr)
					}
					if len(allTokens) == 0 {
						return nil, fmt.Errorf("no tokens found in Fat Address V2")
					}

					actualTokenAddress := allTokens[0]
					contractOrFatAddress = decodedBytes

					// - X.com tokens (numeric ID) → ION
					// - ONLINE+ profile tokens (0:pubkey:) → ION
					// - ONLINE+ content tokens (0:pubkey:contentId) → creator's profile token
					baseToken, baseTokenErr := t.determineBaseTokenFromExternalAddress(ctx, actualTokenAddress)
					if baseTokenErr != nil {
						return nil, fmt.Errorf("failed to determine base token for %s (from Fat Address %s): %w", actualTokenAddress, externalAddress, baseTokenErr)
					}
					tokenStartParams, ok := t.cfg.BondingCurve.CreateTokenDefaults[allTypes[0]]
					if !ok {
						return nil, fmt.Errorf("token type %s not found in bonding curve config", allTypes[0])
					}
					result = &tokenInfo{
						BaseToken:       baseToken,
						ContractAddress: "",
						PriceModel:      tokenStartParams.BondingCurveAlgAddress,
						TotalSupply:     tokenStartParams.EmissionVolume,
						Type:            allTypes[0],
						StartPrice:      tokenStartParams.InitialPrice,
						EndPrice:        tokenStartParams.FinalPrice,
						FeeSponsor:      &tokenStartParams.FeeSponsorAddress,
					}
					err = nil
				}
			} else {
				// xcom ext calls it with a invalid payload to get ion / bnb prices
				_, hexErr := hex.DecodeString(strings.TrimPrefix(externalAddress, "0x"))
				if hexErr != nil {
					return &Pricing{
						IonPriceInUSD: *ionPrice,
						BNBPriceInUSD: bnbPriceInUSD,
					}, nil
				}
			}
		}
		if err != nil {
			return nil, fmt.Errorf("failed to find token by external address %v: %w", externalAddress, err)
		}
	}
	if result.BaseToken == "" {
		var baseTokenErr error
		result.BaseToken, baseTokenErr = t.determineBaseTokenFromExternalAddress(ctx, externalAddress)
		if baseTokenErr != nil {
			return nil, fmt.Errorf("failed to determine base token for %s: %w", externalAddress, baseTokenErr)
		}
		log.Debug(fmt.Sprintf("Token %s found in DB but base_token is empty, determined: %s", externalAddress, result.BaseToken))
	}

	if len(contractOrFatAddress) == 0 {
		if result.ContractAddress == "" {
			return nil, fmt.Errorf("token not found in database and no contract address available for %s", externalAddress)
		}
		contractOrFatAddress = common.HexToAddress(result.ContractAddress).Bytes()
	}
	amountToConvert := new(big.Int).SetUint64(1e18)
	if amount != nil {
		amountToConvert = amount
	}
	startPrice, ok := new(big.Int).SetString(result.StartPrice, 10)
	if !ok {
		return nil, fmt.Errorf("failed to parse start price %v for token %v", result.EndPrice, externalAddress)
	}
	startPriceUSD, _, err := t.calculatePriceInUSD(ctx, weiToFloat64FromBigInt(startPrice), result.BaseToken)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to handle base token for start price usd calculation %v", result.BaseToken)
	}
	endPrice, ok := new(big.Int).SetString(result.EndPrice, 10)
	if !ok {
		return nil, fmt.Errorf("failed to parse end price %v for token %v", result.EndPrice, externalAddress)
	}
	endPriceUSD, _, err := t.calculatePriceInUSD(ctx, weiToFloat64FromBigInt(endPrice), result.BaseToken)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to handle base token for end price usd calculation %v", result.BaseToken)
	}
	feeSponsorAddress := ""
	tokenStartParams, ok := t.cfg.BondingCurve.CreateTokenDefaults[result.Type]
	if result.FeeSponsor != nil {
		feeSponsorAddress = *result.FeeSponsor
	} else {
		if !ok {
			return nil, fmt.Errorf("token type %s not found in bonding curve config", result.Type)
		}
		feeSponsorAddress = tokenStartParams.FeeSponsorAddress
	}

	toBNBRatio := ionPriceInUSD / bnbPriceInUSD
	if strings.Contains(strings.ToLower(common.HexToAddress(result.ContractAddress).String()), "dead") {
		amountUsd := toUSD(amountToConvert, *ionPrice)
		amountInBNB := new(big.Float).Mul(big.NewFloat(toBNBRatio), new(big.Float).SetInt(amountToConvert))
		amountBNB, _ := amountInBNB.Int(nil)
		return &Pricing{
			AmountInBase:           amountToConvert,
			AmountInBNB:            amountBNB,
			BondingCurveAlgAddress: result.PriceModel,
			FeeSponsorAddress:      feeSponsorAddress,
			FeeSponsorId:           tokenStartParams.FeeSponsorId,
			AmountInUSD:            amountUsd,
			IonPriceInUSD:          ionPriceInUSD,
			BNBPriceInUSD:          bnbPriceInUSD,
			InitialPrice:           result.StartPrice,
			InitialPriceUSD:        startPriceUSD,
			FinalPrice:             result.EndPrice,
			FinalPriceUSD:          endPriceUSD,
			EmissionVolume:         result.TotalSupply,
		}, nil
	}

	var fromToken, toToken []byte
	if tradeType == TradeTypeBuy {
		fromToken = common.HexToAddress(result.BaseToken).Bytes()
		toToken = contractOrFatAddress
	} else {
		fromToken = contractOrFatAddress
		toToken = common.HexToAddress(result.BaseToken).Bytes()
	}

	resAmount, err := t.bondingCurve.Pricing(ctx, common.BytesToAddress(fromToken), toToken, amountToConvert, tradeType == TradeTypeSell)
	if err != nil {
		return nil, fmt.Errorf("failed to get pricing for token %v (%v): %w", externalAddress, result.ContractAddress, err)
	}
	var creatorPrice float64
	amountUsd, creatorPrice, err := t.calculatePriceInUSD(ctx, weiToFloat64FromBigInt(resAmount), result.BaseToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get usd price for token %v (%v base %v): %w", externalAddress, result.ContractAddress, result.BaseToken, err)
	}

	var amountForBNB *big.Int
	if result.BaseToken != t.cfg.IONTokenAddress {
		creatorRatio := ionPriceInUSD / creatorPrice
		amountForBNB, _ = new(big.Float).Mul(new(big.Float).SetInt(resAmount), big.NewFloat(creatorRatio)).Int(nil)
	} else {
		amountForBNB = resAmount
	}

	amountInBNB := new(big.Float).Mul(big.NewFloat(toBNBRatio), new(big.Float).SetInt(amountForBNB))
	amountBNB, _ := amountInBNB.Int(nil)
	return &Pricing{
		AmountInBase:           resAmount,
		AmountInBNB:            amountBNB,
		BondingCurveAlgAddress: result.PriceModel,
		FeeSponsorAddress:      feeSponsorAddress,
		FeeSponsorId:           tokenStartParams.FeeSponsorId,
		AmountInUSD:            amountUsd,
		IonPriceInUSD:          *ionPrice,
		BNBPriceInUSD:          bnbPriceInUSD,
		InitialPrice:           result.StartPrice,
		InitialPriceUSD:        startPriceUSD,
		FinalPrice:             result.EndPrice,
		FinalPriceUSD:          endPriceUSD,
		EmissionVolume:         result.TotalSupply,
	}, nil
}

func (t *tokenAnalytics) determineBaseTokenFromExternalAddress(ctx context.Context, externalAddress string) (string, error) {
	if !strings.Contains(externalAddress, ":") {
		return t.cfg.IONTokenAddress, nil
	}
	parts := strings.Split(externalAddress, ":")
	if len(parts) < 2 {
		log.Warn(fmt.Sprintf("Invalid ONLINE_PLUS external address format: %s, defaulting to ION", externalAddress))

		return t.cfg.IONTokenAddress, nil
	}
	kind := parts[0]
	if kind == strconv.Itoa(nostr.KindProfileMetadata) {
		return t.cfg.IONTokenAddress, nil
	}
	creatorPubkey := parts[1]
	if creatorPubkey == "" {
		return "", fmt.Errorf("empty creator pubkey in external address: %s", externalAddress)
	}
	type creatorTokenInfo struct {
		ContractAddress string `db:"contract_address"`
	}
	creatorExternalAddress := BuildProfileExternalAddress(creatorPubkey)
	creatorToken, err := storage.Get[creatorTokenInfo](ctx, t.ingestedDataDB, `
		SELECT contract_address
		FROM tokens
		WHERE external_address = $1
	`, creatorExternalAddress)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			return t.cfg.IONTokenAddress, nil
		}
		return "", fmt.Errorf("failed to get creator token info for %s: %w", creatorExternalAddress, err)
	}

	return creatorToken.ContractAddress, nil
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

		holderAddresses, err := buildUserAddressesFromExternalAddressAndPlatform(strVal(holderMeta.HolderExternalAddress), strVal(holderMeta.HolderPlatform), "")
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
		    COALESCE(t.type, '') as token_type,
			t.platform as platform,
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
func weiToFloat64FromBigString(weiAmount string) float64 {
	b, _ := new(big.Int).SetString(weiAmount, 10)
	return weiToFloat64FromBigInt(b)
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
