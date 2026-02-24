// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"math/big"
	"slices"

	"github.com/cockroachdb/errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/redis/go-redis/v9"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) GetTopHolders(ctx context.Context, externalAddress string, limit int64) ([]*TopHolderPosition, error) {
	key := keyUserPositionOfToken(externalAddress)
	result, err := t.processedDataDB.ZRevRangeWithScores(ctx, key, 0, limit-1).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return []*TopHolderPosition{}, nil
		}

		return nil, errors.Wrap(err, "failed to fetch top holders from DragonflyDB")
	}
	if len(result) == 0 {
		return []*TopHolderPosition{}, nil
	}
	keyBlockchainAddresses := keyUserPositionOfTokenByUserBlockchainAddress(externalAddress)
	resultBlockChainAddresses, err := t.processedDataDB.ZRevRangeWithScores(ctx, keyBlockchainAddresses, 0, limit-1).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			resultBlockChainAddresses = make([]redis.Z, 0)
			err = nil
		}
		if err != nil {
			return nil, errors.Wrap(err, "failed to fetch top holders from DragonflyDB")
		}
	}
	userIonConnects := make([]string, 0, len(result))
	for _, z := range result {
		if userIonConnect, ok := z.Member.(string); ok {
			userIonConnects = append(userIonConnects, userIonConnect)
		}
	}
	userBlockchainAddresses := make([]string, 0, len(resultBlockChainAddresses))
	for _, z := range resultBlockChainAddresses {
		if userBlockchainAddress, ok := z.Member.(string); ok {
			userBlockchainAddresses = append(userBlockchainAddresses, userBlockchainAddress)
		}
	}

	query := `
	WITH token_info AS (
		SELECT t.content_author_id                            as content_author_id,
		   creator.username                               as creator_username,
		   creator.display_name                           as creator_display,
		   creator.verified                               as creator_verified,
		   creator.avatar                                 as creator_avatar,
		   creator.platform_group                         as creator_platform,
		   COALESCE(creator_fees_transferred.amount, '0') as creator_fees,
		   t.content_author_id                            as creator_bnb_bsc_address,
		   creator.external_address                       as creator_external_address,
		   t.price_usd                                    as price_usd,
		   t.total_supply                                 as total_supply,
		   t.bonding_curve_migrated                       as bonding_curve_migrated,
		   t.pair_id                                      as pair_id,
		   t.base_token,
		   t.contract_address,
		   t.type                                         as token_type,
		   t.platform                                     as token_platform,
		   uap.user_external_address as holder_external_address,
		   (SELECT utp_inner.user_blockchain_address 
		    FROM user_token_positions utp_inner 
		    WHERE utp_inner.external_address = t.external_address 
		      AND utp_inner.user_external_address = uap.user_external_address 
		    LIMIT 1) as holder_bnb_bsc_address,
		   holder_user_agg.id as holder_id
		FROM tokens t
			 JOIN user_aggregate_positions uap ON uap.external_address = t.external_address
					AND uap.user_external_address = ANY($2)
			 LEFT JOIN users holder_user_agg ON holder_user_agg.external_address = uap.user_external_address
			 LEFT JOIN user_bsc_addresses creator_addr ON creator_addr.bsc_address = t.content_author_id
			 LEFT JOIN users creator ON creator.id = creator_addr.user_id
			 LEFT JOIN fees_transferred creator_fees_transferred
					   ON recipient_bsc_address = t.content_author_id AND
						  token_external_address = t.external_address AND fee_type = 'creator'
		WHERE t.external_address = $1
		  AND t.ticker IS NOT NULL
		UNION ALL
		SELECT t.content_author_id                            as content_author_id,
		   creator.username                               as creator_username,
		   creator.display_name                           as creator_display,
		   creator.verified                               as creator_verified,
		   creator.avatar                                 as creator_avatar,
		   creator.platform_group                         as creator_platform,
		   COALESCE(creator_fees_transferred.amount, '0') as creator_fees,
		   t.content_author_id                            as creator_bnb_bsc_address,
		   creator.external_address                       as creator_external_address,
		   t.price_usd                                    as price_usd,
		   t.total_supply                                 as total_supply,
		   t.bonding_curve_migrated                       as bonding_curve_migrated,
		   t.pair_id                                      as pair_id,
		   t.base_token,
		   t.contract_address,
		   t.type                                         as token_type,
		   t.platform                                     as token_platform,
		   utp.user_external_address as holder_external_address,
		   utp.user_blockchain_address as holder_bnb_bsc_address,
		   holder_addr.user_id as holder_id
		FROM tokens t
			 JOIN user_token_positions utp ON utp.external_address = t.external_address
					AND utp.user_blockchain_address = ANY($3)
			 LEFT JOIN user_aggregate_positions uap_check ON uap_check.external_address = t.external_address
					AND uap_check.user_external_address = utp.user_external_address
					AND uap_check.user_external_address = ANY($2)
			 LEFT JOIN user_bsc_addresses creator_addr ON creator_addr.bsc_address = t.content_author_id
			 LEFT JOIN users creator ON creator.id = creator_addr.user_id
			 LEFT JOIN user_bsc_addresses holder_addr
					   ON holder_addr.bsc_address = utp.user_blockchain_address
			 LEFT JOIN fees_transferred creator_fees_transferred
					   ON recipient_bsc_address = t.content_author_id AND
						  token_external_address = t.external_address AND fee_type = 'creator'
		WHERE t.external_address = $1
		  AND t.ticker IS NOT NULL
		  AND uap_check.user_external_address IS NULL
	)
    SELECT
        t.content_author_id,
        t.creator_username,
        t.creator_display,
        t.creator_verified,
        t.creator_avatar,
        t.creator_platform,
        t.creator_fees,
        t.creator_bnb_bsc_address,
        t.creator_external_address,
        t.price_usd,
        t.total_supply,
        t.bonding_curve_migrated,
        t.pair_id,
        t.base_token,
        t.token_type,
        t.token_platform,

        t.holder_bnb_bsc_address,
        t.holder_external_address,
		holder.master_pubkey as holder_master_pubkey,
		holder.username as holder_username,
		holder.display_name as holder_display,
		holder.verified as holder_verified,
		holder.avatar as holder_avatar,
		holder.platform_group as holder_platform
    FROM token_info t
        LEFT JOIN users holder ON holder.id = t.holder_id OR holder.external_address = t.holder_external_address
	UNION ALL (
		    SELECT
        t.content_author_id,
        t.creator_username,
        t.creator_display,
        t.creator_verified,
        t.creator_avatar,
        t.creator_platform,
        t.creator_fees,
        t.creator_bnb_bsc_address,
        t.creator_external_address,
        t.price_usd,
        t.total_supply,
        t.bonding_curve_migrated,
        t.pair_id,
        t.base_token,
        t.token_type,
        t.token_platform,

        t.holder_bnb_bsc_address,
        t.holder_external_address,
		NULL as holder_master_pubkey,
	    holder_content_pool.ticker as holder_username,
	    '$' || holder_content_pool.ticker || ' Pool' as holder_display,
	    TRUE as holder_verified,
	    holder_content_pool.image_url as holder_avatar,
	    'ionconnect' as holder_platform
    FROM token_info t
        JOIN tokens holder_content_pool ON holder_content_pool.external_address = t.holder_external_address
									   AND holder_content_pool.base_token = t.contract_address
	);
`
	rows, err := storage.Select[holderWithTokenData](ctx, t.ingestedDataDB, query, externalAddress, userIonConnects, userBlockchainAddresses)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch holders data")
	}
	if len(rows) == 0 {
		return []*TopHolderPosition{}, nil
	}

	tokenMigrated := rows[0].BondingCurveMigrated
	pairId := rows[0].PairId
	creatorAddresses, err := buildUserAddressesFromExternalAddressAndPlatform(strVal(rows[0].CreatorExternalAddress), strVal(rows[0].CreatorPlatform), strVal(rows[0].CreatorBnbBscAddress))
	if err != nil {
		return nil, fmt.Errorf("failed to build creator addresses from external_address %s (platform %s): %w", strVal(rows[0].CreatorExternalAddress), strVal(rows[0].CreatorPlatform), err)
	}
	creator := &User{
		Username:  rows[0].CreatorUsername,
		Display:   rows[0].CreatorDisplay,
		Verified:  rows[0].CreatorVerified,
		Avatar:    rows[0].CreatorAvatar,
		Addresses: creatorAddresses,
	}

	creatorPosition := t.creatorPosition(ctx, externalAddress, creatorAddresses)
	if creatorPosition == 0 { // When creator has position fees are included in it as we read balance from blockchain
		creatorPosition = weiToFloat64FromBigString(rows[0].CreatorFees)
		for idx, z := range result {
			if z.Score < creatorPosition {
				creatorFeeRank := min(idx-1, 0)
				result = slices.Insert(result, creatorFeeRank, redis.Z{Member: rows[0].CreatorExternalAddress, Score: creatorPosition})
				if int64(len(result)) >= limit {
					result = result[:len(result)-1]
				}
				creatorFeeUSD, _, err := t.calculatePriceInUSD(ctx, creatorPosition, rows[0].BaseToken)
				if err != nil {
					return nil, errors.Wrap(err, "failed to calculate usd price for creator fee")
				}

				rows = slices.Insert(rows, max(idx-1, 0), &holderWithTokenData{
					ContentAuthorID:        creator.MasterPubkey,
					CreatorUsername:        creator.Username,
					CreatorDisplay:         creator.Display,
					CreatorAvatar:          creator.Avatar,
					CreatorExternalAddress: rows[0].CreatorExternalAddress,
					CreatorPlatform:        rows[0].CreatorPlatform,
					CreatorBnbBscAddress:   rows[0].CreatorBnbBscAddress,
					CreatorFees:            rows[0].CreatorFees,
					TotalSupply:            rows[0].TotalSupply,
					BondingCurveMigrated:   rows[0].BondingCurveMigrated,
					PairId:                 rows[0].PairId,
					BaseToken:              rows[0].BaseToken,
					TokenType:              rows[0].TokenType,
					TokenPlatform:          rows[0].TokenPlatform,
					HolderMasterPubkey:     creator.MasterPubkey,
					HolderUsername:         creator.Username,
					HolderDisplay:          creator.Display,
					HolderAvatar:           creator.Avatar,
					HolderExternalAddress:  rows[0].CreatorExternalAddress,
					HolderBnbBscAddress:    rows[0].CreatorBnbBscAddress,
					HolderPlatform:         rows[0].CreatorPlatform,
					PriceUSD:               creatorFeeUSD,
					CreatorVerified:        creator.Verified,
					HolderVerified:         creator.Verified,
				})
				break
			}
		}
	}

	if !tokenMigrated {
		if rows, result, resultBlockChainAddresses, err = t.enrichTopHoldersWithBongingCurve(ctx, pairId, externalAddress, rows, creator, limit, result, resultBlockChainAddresses); err != nil {
			return nil, errors.Wrapf(err, "failed to enrich top holders with bonging curve for token %v", externalAddress)
		}
	}
	isIonConnectContentToken := rows[0].TokenType != TokenTypeProfile && rows[0].TokenPlatform == PlatformGroupIonConnect
	if !isIonConnectContentToken {
		if rows, result, resultBlockChainAddresses, err = t.enrichTopHoldersWithBurned(ctx, externalAddress, rows, creator, limit, result, resultBlockChainAddresses); err != nil {
			return nil, errors.Wrapf(err, "failed to enrich top holders with burned for token %v", externalAddress)
		}
	}

	positions, err := buildTopHolderPositions(externalAddress, result, resultBlockChainAddresses, rows, t.cfg.BondingCurve.SmartContractAddress, t.cfg.BondingCurve.BurnAddress)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build top holder positions")
	}
	if int64(len(positions)) > limit {
		positions = positions[:limit]
	}

	return positions, nil
}

func (t *tokenAnalytics) enrichTopHoldersWithBurned(ctx context.Context, externalAddress string, rows []*holderWithTokenData, creator *User, limit int64, result, resultByBlockchain []redis.Z) ([]*holderWithTokenData, []redis.Z, []redis.Z, error) {
	burnedAmount, err := storage.Get[float64](ctx, t.ingestedDataDB, `SELECT 
    	amount/1e18 FROM fees_transferred
    	WHERE token_external_address = $1 AND recipient_bsc_address = $2`, externalAddress, t.cfg.BondingCurve.BurnAddress)
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			err = nil
			zero := float64(0)
			burnedAmount = &zero
		}
		if err != nil {
			return nil, nil, nil, errors.Wrapf(err, "failed to fetch burned amount for token %v", externalAddress)
		}
	}
	burnedUSD, _, err := t.calculatePriceInUSD(ctx, *burnedAmount, rows[0].BaseToken)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "failed to calculate price in USD for burned amount, token %v, baseToken %v", externalAddress, rows[0].BaseToken)
	}
	if len(result) >= 2 {
		result = slices.Insert(result, 1, redis.Z{Member: t.cfg.BondingCurve.BurnAddress, Score: *burnedAmount})
		resultByBlockchain = slices.Insert(resultByBlockchain, 1, redis.Z{Member: t.cfg.BondingCurve.BurnAddress, Score: *burnedAmount})
	} else {
		result = append(result, redis.Z{Member: t.cfg.BondingCurve.BurnAddress, Score: *burnedAmount})
		resultByBlockchain = append(resultByBlockchain, redis.Z{Member: t.cfg.BondingCurve.BurnAddress, Score: *burnedAmount})
	}
	if int64(len(result)) > limit {
		result = result[:len(result)-1]
	}
	if int64(len(resultByBlockchain)) > limit {
		resultByBlockchain = resultByBlockchain[:len(resultByBlockchain)-1]
	}
	burnedPlatform := PlatformGroupIonConnect
	burnedAvatar := burnedTopHolderAvatar
	burnedDisplayName := burnedTopHolderDisplayName
	burnedVerified := false
	burnedUsername := ""
	burnedRow := &holderWithTokenData{
		ContentAuthorID:        creator.MasterPubkey,
		CreatorUsername:        creator.Username,
		CreatorDisplay:         creator.Display,
		CreatorAvatar:          creator.Avatar,
		CreatorExternalAddress: rows[0].CreatorExternalAddress,
		CreatorPlatform:        rows[0].CreatorPlatform,
		CreatorBnbBscAddress:   rows[0].CreatorBnbBscAddress,
		TotalSupply:            rows[0].TotalSupply,
		TokenType:              rows[0].TokenType,
		TokenPlatform:          rows[0].TokenPlatform,
		HolderMasterPubkey:     &t.cfg.BondingCurve.BurnAddress,
		HolderUsername:         &burnedUsername,
		HolderDisplay:          &burnedDisplayName,
		HolderAvatar:           &burnedAvatar,
		HolderExternalAddress:  &t.cfg.BondingCurve.BurnAddress,
		HolderPlatform:         &burnedPlatform,
		PriceUSD:               burnedUSD,
		CreatorVerified:        creator.Verified,
		HolderVerified:         &burnedVerified,
		PairId:                 rows[0].PairId,
		BaseToken:              rows[0].BaseToken,
		HolderBnbBscAddress:    &t.cfg.BondingCurve.BurnAddress,
		CreatorFees:            rows[0].CreatorFees,
	}
	if len(rows) >= 2 {
		rows = slices.Insert(rows, 1, burnedRow)
	} else {
		rows = append(rows, burnedRow)
	}

	return rows, result, resultByBlockchain, nil
}

func (t *tokenAnalytics) creatorPosition(ctx context.Context, tokenExternalAddress string, creatorAddresses *Addresses) float64 {
	userPositionKey := keyUserPositionOfTokenByUserBlockchainAddress(tokenExternalAddress)
	currentScore, err := t.processedDataDB.ZScore(ctx, userPositionKey, creatorAddresses.Blockchain).Result()
	if err != nil && errors.Is(err, redis.Nil) {
		currentScore = 0 // Default to 0 if error
	}
	return currentScore
}

func (t *tokenAnalytics) enrichTopHoldersWithBongingCurve(ctx context.Context, pairId string, externalAddress string, rows []*holderWithTokenData, creator *User, limit int64, result, resultByBlockchain []redis.Z) ([]*holderWithTokenData, []redis.Z, []redis.Z, error) {
	progress, err := t.bondingCurve.Progress(ctx, common.HexToHash(pairId))
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "failed to get curve progress for token %v (pair %v)", externalAddress, pairId)
	}
	curveScore := weiToFloat64FromBigInt(new(big.Int).Sub(progress.BondingTokensGoal, progress.SoldTokens))
	result = slices.Insert(result, 0, redis.Z{Member: t.cfg.BondingCurve.SmartContractAddress, Score: curveScore})
	resultByBlockchain = slices.Insert(resultByBlockchain, 0, redis.Z{Member: t.cfg.BondingCurve.SmartContractAddress, Score: curveScore})
	if int64(len(result)) > limit {
		result = result[:len(result)-1]
	}
	if int64(len(resultByBlockchain)) > limit {
		resultByBlockchain = resultByBlockchain[:len(resultByBlockchain)-1]
	}
	curveUSD, _, err := t.calculatePriceInUSD(ctx, curveScore, rows[0].BaseToken)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "failed to calculate price in USD for bonding curve, token %v, baseToken %v", externalAddress, rows[0].BaseToken)
	}
	curvePlatform := PlatformGroupIonConnect
	curveAvatar := bondingCurveTopHolderAvatar
	curveDisplayName := bondingCurveTopHolderDisplayName
	curveVerified := false
	curveUsername := ""
	rows = slices.Insert(rows, 0, &holderWithTokenData{
		ContentAuthorID:        creator.MasterPubkey,
		CreatorUsername:        creator.Username,
		CreatorDisplay:         creator.Display,
		CreatorAvatar:          creator.Avatar,
		CreatorExternalAddress: rows[0].CreatorExternalAddress,
		CreatorPlatform:        rows[0].CreatorPlatform,
		CreatorBnbBscAddress:   rows[0].CreatorBnbBscAddress,
		TotalSupply:            rows[0].TotalSupply,
		TokenType:              rows[0].TokenType,
		TokenPlatform:          rows[0].TokenPlatform,
		HolderMasterPubkey:     &t.cfg.BondingCurve.SmartContractAddress,
		HolderUsername:         &curveUsername,
		HolderDisplay:          &curveDisplayName,
		HolderAvatar:           &curveAvatar,
		HolderExternalAddress:  &t.cfg.BondingCurve.SmartContractAddress,
		HolderPlatform:         &curvePlatform,
		PriceUSD:               curveUSD,
		CreatorVerified:        creator.Verified,
		HolderVerified:         &curveVerified,
		PairId:                 rows[0].PairId,
		BaseToken:              rows[0].BaseToken,
		HolderBnbBscAddress:    &t.cfg.BondingCurve.SmartContractAddress,
		CreatorFees:            rows[0].CreatorFees,
	})

	return rows, result, resultByBlockchain, nil
}

func buildTopHolderPositions(externalAddress string, rankings, rankingsByBlockchainAddress []redis.Z, rows []*holderWithTokenData, bondingCurveContractAddress, burnAddress string) ([]*TopHolderPosition, error) {
	holderDataMap := make(map[string]*holderWithTokenData)
	matching := make(map[string]string)
	for i := range rows {
		if rows[i].HolderExternalAddress != nil {
			holderDataMap[*rows[i].HolderExternalAddress] = rows[i]
			if rows[i].HolderBnbBscAddress != nil {
				matching[*rows[i].HolderExternalAddress] = *rows[i].HolderBnbBscAddress
			}
		}
		if rows[i].HolderBnbBscAddress != nil {
			holderDataMap[*rows[i].HolderBnbBscAddress] = rows[i]
		}
	}
	mergedRankings := mergeRankings(rankings, rankingsByBlockchainAddress, matching, bondingCurveContractAddress, burnAddress)

	holders := make([]*TopHolderPosition, 0, len(mergedRankings))
	currentUserRank := 0
	for _, rh := range mergedRankings {
		var holderData *holderWithTokenData
		var userExternalAddress string
		var exists bool
		if rh.hasFullUserData {
			userExternalAddress = rh.address
			holderData, exists = holderDataMap[userExternalAddress]
			if !exists {
				blockchainAddress, ok := matching[userExternalAddress]
				if len(rows) == 0 || !ok || blockchainAddress == "" {
					continue
				}
				holderData = &holderWithTokenData{
					ContentAuthorID:        rows[0].ContentAuthorID,
					CreatorUsername:        rows[0].CreatorUsername,
					CreatorDisplay:         rows[0].CreatorDisplay,
					CreatorAvatar:          rows[0].CreatorAvatar,
					CreatorExternalAddress: rows[0].CreatorExternalAddress,
					CreatorPlatform:        rows[0].CreatorPlatform,
					CreatorBnbBscAddress:   rows[0].CreatorBnbBscAddress,
					TotalSupply:            rows[0].TotalSupply,
					BondingCurveMigrated:   rows[0].BondingCurveMigrated,
					PairId:                 rows[0].PairId,
					BaseToken:              rows[0].BaseToken,
					TokenType:              rows[0].TokenType,
					TokenPlatform:          rows[0].TokenPlatform,
					PriceUSD:               rows[0].PriceUSD,
					CreatorVerified:        rows[0].CreatorVerified,
					HolderBnbBscAddress:    &blockchainAddress,
				}
			}
		} else {
			userBlockchainAddress := rh.address
			holderData, exists = holderDataMap[userBlockchainAddress]
			if !exists {
				continue
			}
			if holderData.HolderExternalAddress != nil {
				userExternalAddress = *holderData.HolderExternalAddress
			} else {
				userExternalAddress = ""
			}
		}

		totalSupplyFloat, err := parseTotalSupply(holderData.TotalSupply, externalAddress)
		if err != nil {
			log.Warn(fmt.Sprintf("Failed to parse total supply for token %v: %v", externalAddress, err))
			totalSupplyFloat = 0
		}
		amountTokens := rh.score
		amountWei := tokensToWeiBigInt(amountTokens)
		amountUSD := amountTokens * holderData.PriceUSD
		supplyShare := calculateSupplyShare(amountTokens, totalSupplyFloat)

		creatorAddresses, err := buildUserAddressesFromExternalAddressAndPlatform(strVal(holderData.CreatorExternalAddress), strVal(holderData.CreatorPlatform), strVal(holderData.CreatorBnbBscAddress))
		if err != nil {
			return nil, fmt.Errorf("failed to build creator addresses from external_address %s (platform %s): %w", strVal(holderData.CreatorExternalAddress), strVal(holderData.CreatorPlatform), err)
		}
		holderAddresses, err := buildUserAddressesFromExternalAddressAndPlatform(userExternalAddress, strVal(holderData.HolderPlatform), strVal(holderData.HolderBnbBscAddress))
		if err != nil {
			return nil, fmt.Errorf("failed to build holder addresses from external_address %s (platform %s): %w", userExternalAddress, strVal(holderData.HolderPlatform), err)
		}
		isHolderSpecial := (rh.hasFullUserData && (userExternalAddress == bondingCurveContractAddress || userExternalAddress == burnAddress)) ||
			(!rh.hasFullUserData && (rh.address == bondingCurveContractAddress || rh.address == burnAddress))

		var r uint64
		if isHolderSpecial {
			r = 0
		} else {
			currentUserRank++
			r = uint64(currentUserRank)
		}

		holder := &TopHolderPosition{
			Creator: User{
				Username:  holderData.CreatorUsername,
				Display:   holderData.CreatorDisplay,
				Verified:  holderData.CreatorVerified,
				Avatar:    holderData.CreatorAvatar,
				Addresses: creatorAddresses,
			},
			Position: HolderPosition{
				Holder: User{
					MasterPubkey: holderData.HolderMasterPubkey,
					Username:     holderData.HolderUsername,
					Display:      holderData.HolderDisplay,
					Verified:     holderData.HolderVerified,
					Avatar:       holderData.HolderAvatar,
					Addresses:    holderAddresses,
				},
				Rank:        r,
				Amount:      amountWei.String(),
				AmountUSD:   amountUSD,
				SupplyShare: supplyShare,
			},
		}

		holders = append(holders, holder)
	}

	return holders, nil
}

func isSpecialAddress(addr, bondingCurve, burn string) bool {
	return addr == bondingCurve || addr == burn
}

func mergeRankings(rankings, rankingsByBlockchain []redis.Z, matching map[string]string, bondingCurve, burn string) []rankedHolder {
	merged := make([]rankedHolder, 0, len(rankings)+len(rankingsByBlockchain))
	processedBlockchain := make(map[string]bool)

	specialInRankings := make(map[string]bool)
	for _, z := range rankings {
		if addr, ok := z.Member.(string); ok && isSpecialAddress(addr, bondingCurve, burn) {
			specialInRankings[addr] = true
		}
	}
	i, j := 0, 0
	for i < len(rankings) || j < len(rankingsByBlockchain) {
		if i >= len(rankings) {
			blockchainAddr := rankingsByBlockchain[j].Member.(string)
			if !processedBlockchain[blockchainAddr] {
				merged = append(merged, rankedHolder{
					address:         blockchainAddr,
					score:           rankingsByBlockchain[j].Score,
					hasFullUserData: false,
				})
			}
			j++

			continue
		}

		if j >= len(rankingsByBlockchain) {
			if addr, ok := rankings[i].Member.(string); ok {
				merged = append(merged, rankedHolder{
					address:         addr,
					score:           rankings[i].Score,
					hasFullUserData: true,
				})
				if blockchainAddr, exists := matching[addr]; exists {
					processedBlockchain[blockchainAddr] = true
				}
				if isSpecialAddress(addr, bondingCurve, burn) {
					processedBlockchain[addr] = true
				}
			}
			i++

			continue
		}

		addr, _ := rankings[i].Member.(string)
		blockchainAddr := rankingsByBlockchain[j].Member.(string)
		if isSpecialAddress(blockchainAddr, bondingCurve, burn) && specialInRankings[blockchainAddr] {
			processedBlockchain[blockchainAddr] = true
			j++

			continue
		}
		pickFromRankings := shouldPickFromRankings(addr, rankings[i].Score, blockchainAddr, rankingsByBlockchain[j].Score, bondingCurve, burn)
		if pickFromRankings {
			merged = append(merged, rankedHolder{
				address:         addr,
				score:           rankings[i].Score,
				hasFullUserData: true,
			})
			if blockchainAddr, exists := matching[addr]; exists {
				processedBlockchain[blockchainAddr] = true
			}
			if isSpecialAddress(addr, bondingCurve, burn) {
				processedBlockchain[addr] = true
			}
			i++
		} else {
			if !processedBlockchain[blockchainAddr] {
				merged = append(merged, rankedHolder{
					address:         blockchainAddr,
					score:           rankingsByBlockchain[j].Score,
					hasFullUserData: false,
				})
			}
			j++
		}
	}

	return merged
}

func shouldPickFromRankings(addrWithUserData string, scoreWithUserData float64, blockchainOnlyAddr string, blockchainOnlyScore float64, bondingCurve, burn string) bool {
	isAddrSpecial := isSpecialAddress(addrWithUserData, bondingCurve, burn)
	isBlockchainSpecial := isSpecialAddress(blockchainOnlyAddr, bondingCurve, burn)
	if isAddrSpecial {
		return true
	}
	if isBlockchainSpecial {
		return false
	}

	return scoreWithUserData >= blockchainOnlyScore
}
