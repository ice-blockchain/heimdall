// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"

	"github.com/cockroachdb/errors"
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
	userIonConnects := make([]string, 0, len(result))
	for _, z := range result {
		if userIonConnect, ok := z.Member.(string); ok {
			userIonConnects = append(userIonConnects, userIonConnect)
		}
	}

	query := `
		SELECT 
			t.creator_blockchain_address as creator_blockchain_address,
			creator.username as creator_username,
			creator.display_name as creator_display,
			creator.verified as creator_verified,
			creator.avatar as creator_avatar,
			creator.platform_group as creator_platform,
			t.bnb_bsc_metadata_owner_address as creator_bnb_bsc_address,
			creator.external_address as creator_external_address,
			t.price_usd as price_usd,
			t.total_supply as total_supply,
			holder.master_pubkey as holder_master_pubkey,
			holder.username as holder_username,
			holder.display_name as holder_display,
			holder.verified as holder_verified,
			holder.avatar as holder_avatar,
			holder.external_address as holder_external_address,
			holder.platform_group as holder_platform
		FROM tokens t
		LEFT JOIN users creator ON LOWER(creator.blockchain_address) = LOWER(t.creator_blockchain_address)
		JOIN users holder ON holder.external_address = ANY($2)
		WHERE t.external_address = $1
	`
	rows, err := storage.Select[holderWithTokenData](ctx, t.ingestedDataDB, query, externalAddress, userIonConnects)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch holders data")
	}
	if len(rows) == 0 {
		return []*TopHolderPosition{}, nil
	}

	positions, err := buildTopHolderPositions(externalAddress, result, rows)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build top holder positions")
	}

	return positions, nil
}

func buildTopHolderPositions(externalAddress string, rankings []redis.Z, rows []*holderWithTokenData) ([]*TopHolderPosition, error) {
	holderDataMap := make(map[string]*holderWithTokenData)
	for i := range rows {
		if rows[i].HolderExternalAddress != nil {
			holderDataMap[*rows[i].HolderExternalAddress] = rows[i]
		}
	}
	holders := make([]*TopHolderPosition, 0, len(rankings))
	for rank, z := range rankings {
		userExternalAddress, ok := z.Member.(string)
		if !ok {
			continue
		}
		holderData, exists := holderDataMap[userExternalAddress]
		if !exists {
			log.Warn(fmt.Sprintf("User data not found for user external_address: %v", userExternalAddress))
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

		creatorAddresses, err := buildAddressesFromExternalAddressAndPlatform(strVal(holderData.CreatorExternalAddress), strVal(holderData.CreatorPlatform), strVal(holderData.CreatorBnbBscAddress))
		if err != nil {
			return nil, fmt.Errorf("failed to build creator addresses from external_address %s (platform %s): %w", strVal(holderData.CreatorExternalAddress), strVal(holderData.CreatorPlatform), err)
		}
		holderAddresses, err := buildAddressesFromExternalAddressAndPlatform(userExternalAddress, strVal(holderData.HolderPlatform), "")
		if err != nil {
			return nil, fmt.Errorf("failed to build holder addresses from external_address %s (platform %s): %w", userExternalAddress, strVal(holderData.HolderPlatform), err)
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
				Rank:        uint64(rank + 1),
				Amount:      amountWei.String(),
				AmountUSD:   amountUSD,
				SupplyShare: supplyShare,
			},
		}

		holders = append(holders, holder)
	}

	return holders, nil
}
