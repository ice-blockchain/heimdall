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
	result, err := t.processedDataDB.ZRevRangeWithScores(ctx, key, 0, limit).Result()
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
	SELECT 
		t.content_author_id as content_author_id,
		creator.username as creator_username,
		creator.display_name as creator_display,
		creator.verified as creator_verified,
		creator.avatar as creator_avatar,
		creator.platform_group as creator_platform,
		t.content_author_id as creator_bnb_bsc_address,
		creator.external_address as creator_external_address,
		t.price_usd as price_usd,
		t.total_supply as total_supply,
		t.bonding_curve_migrated as bonding_curve_migrated,
		t.pair_id as pair_id,
		t.base_token,
		holder.master_pubkey as holder_master_pubkey,
		holder.username as holder_username,
		holder.display_name as holder_display,
		holder.verified as holder_verified,
		holder.avatar as holder_avatar,
		utp.user_external_address as holder_external_address,
		holder.platform_group as holder_platform,
		utp.user_blockchain_address as holder_bnb_bsc_address
	FROM tokens t
	JOIN user_token_positions utp ON utp.external_address = t.external_address
		AND (utp.user_external_address = ANY($2) OR utp.user_blockchain_address = ANY($3))
	LEFT JOIN users creator ON LOWER(creator.content_author_id) = LOWER(t.content_author_id)
	LEFT JOIN users holder ON holder.external_address = utp.user_external_address OR holder.content_author_id = utp.user_blockchain_address
	WHERE t.external_address = $1
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
	extraItemsEnriched := 0
	if !tokenMigrated {
		if rows, result, resultBlockChainAddresses, err = t.enrichTopHoldersWithBongingCurve(ctx, pairId, externalAddress, rows, creator, limit, result, resultBlockChainAddresses); err != nil {
			return nil, errors.Wrapf(err, "failed to enrich top holders with bonging curve for token %v", externalAddress)
		}
		extraItemsEnriched += 1
	}
	if rows, result, resultBlockChainAddresses, err = t.enrichTopHoldersWithBurned(ctx, externalAddress, rows, creator, limit, result, resultBlockChainAddresses); err != nil {
		return nil, errors.Wrapf(err, "failed to enrich top holders with burned for token %v", externalAddress)
	}
	extraItemsEnriched += 1
	positions, err := buildTopHolderPositions(externalAddress, result, resultBlockChainAddresses, rows, t.cfg.BondingCurve.SmartContractAddress, t.cfg.BondingCurve.BurnAddress, extraItemsEnriched)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build top holder positions")
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
	}
	if len(rows) >= 2 {
		rows = slices.Insert(rows, 1, burnedRow)
	} else {
		rows = append(rows, burnedRow)
	}

	return rows, result, resultByBlockchain, nil
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
	})

	return rows, result, resultByBlockchain, nil
}

func buildTopHolderPositions(externalAddress string, rankings, rankingsByBlockchainAddress []redis.Z, rows []*holderWithTokenData, bondingCurveContractAddress, burnAddress string, extraItemsEnriched int) ([]*TopHolderPosition, error) {
	holderDataMap := make(map[string]*holderWithTokenData)
	matching := make(map[string]string)
	for i := range rows {
		if rows[i].HolderExternalAddress != nil {
			holderDataMap[*rows[i].HolderExternalAddress] = rows[i]
			if rows[i].HolderBnbBscAddress != nil {
				holderDataMap[*rows[i].HolderBnbBscAddress] = rows[i]
				matching[*rows[i].HolderExternalAddress] = *rows[i].HolderBnbBscAddress
			}
		}
	}
	byBlockchainAddress := make(map[string]float64)
	for _, z := range rankingsByBlockchainAddress {
		byBlockchainAddress[z.Member.(string)] = z.Score
	}
	holders := make([]*TopHolderPosition, 0, len(rankings))
	for rank, z := range rankings {
		userExternalAddress, ok := z.Member.(string)
		if !ok {
			log.Warn(fmt.Sprintf("Could not convert member to string for external_address: %v", userExternalAddress))

			continue
		}
		blockchainAddress, ok := matching[userExternalAddress]
		if ok {
			delete(byBlockchainAddress, blockchainAddress)
		}
		holderData, exists := holderDataMap[userExternalAddress]
		if !exists {
			if len(rows) == 0 {
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
				PriceUSD:               rows[0].PriceUSD,
				CreatorVerified:        rows[0].CreatorVerified,

				HolderBnbBscAddress: &blockchainAddress,
			}
		}

		totalSupplyFloat, err := parseTotalSupply(holderData.TotalSupply, externalAddress)
		if err != nil {
			log.Warn(fmt.Sprintf("Failed to parse total supply for token %v: %v", externalAddress, err))
			totalSupplyFloat = 0
		}
		amountTokens := z.Score
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
		userRank := rank + 1 - extraItemsEnriched
		if userRank <= 0 {
			userRank = 1
		}
		r := uint64(userRank)
		if userExternalAddress == bondingCurveContractAddress || userExternalAddress == burnAddress {
			r = 0
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
	for rank, z := range rankingsByBlockchainAddress {
		userBlockChainAddress := z.Member.(string)
		if _, ok := byBlockchainAddress[z.Member.(string)]; !ok {
			continue
		}
		holderData, exists := holderDataMap[userBlockChainAddress]
		if !exists {
			continue
		}

		totalSupplyFloat, err := parseTotalSupply(holderData.TotalSupply, externalAddress)
		if err != nil {
			log.Warn(fmt.Sprintf("Failed to parse total supply for token %v: %v", externalAddress, err))
			totalSupplyFloat = 0
		}
		amountTokens := z.Score
		amountWei := tokensToWeiBigInt(amountTokens)
		amountUSD := amountTokens * holderData.PriceUSD
		supplyShare := calculateSupplyShare(amountTokens, totalSupplyFloat)

		creatorAddresses, err := buildUserAddressesFromExternalAddressAndPlatform(strVal(holderData.CreatorExternalAddress), strVal(holderData.CreatorPlatform), strVal(holderData.CreatorBnbBscAddress))
		if err != nil {
			return nil, fmt.Errorf("failed to build creator addresses from external_address %s (platform %s): %w", strVal(holderData.CreatorExternalAddress), strVal(holderData.CreatorPlatform), err)
		}
		holderAddresses, err := buildUserAddressesFromExternalAddressAndPlatform("", strVal(holderData.HolderPlatform), strVal(holderData.HolderBnbBscAddress))
		if err != nil {
			return nil, fmt.Errorf("failed to build holder addresses from blockchain address %s (platform %s): %w", userBlockChainAddress, strVal(holderData.HolderPlatform), err)
		}
		userRank := rank + 1 - extraItemsEnriched
		if userRank <= 0 {
			userRank = 1
		}
		r := uint64(userRank)
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
