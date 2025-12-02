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
			t.creator_master_pubkey as creator_master_pubkey,
			creator.username as creator_username,
			COALESCE(creator.display_name, '') as creator_display,
			creator.verified as creator_verified,
			COALESCE(creator.avatar, '') as creator_avatar,
			t.price_usd as price_usd,
			t.total_supply as total_supply,
			holder.master_pubkey as holder_master_pubkey,
			holder.username as holder_username,
			COALESCE(holder.display_name, '') as holder_display,
			holder.verified as holder_verified,
			COALESCE(holder.avatar, '') as holder_avatar,
			holder.external_address as holder_external_address
		FROM tokens t
		LEFT JOIN users creator ON creator.master_pubkey = t.creator_master_pubkey
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
		holderDataMap[rows[i].HolderExternalAddress] = rows[i]
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
		amountUSD := amountTokens * holderData.PriceUSD
		supplyShare := calculateSupplyShare(amountTokens, totalSupplyFloat)

		creatorAddresses, err := buildAddressesFromExternalAddress(fmt.Sprintf("%s%s", PlatformIonConnectProfile, holderData.CreatorMasterPubkey))
		if err != nil {
			return nil, fmt.Errorf("failed to build creator addresses from master_pubkey %s: %w", holderData.CreatorMasterPubkey, err)
		}
		holderAddresses, err := buildAddressesFromExternalAddress(userExternalAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to build holder addresses from external_address %s: %w", userExternalAddress, err)
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
				Amount:      uint64(amountTokens),
				AmountUSD:   amountUSD,
				SupplyShare: supplyShare,
			},
		}

		holders = append(holders, holder)
	}

	return holders, nil
}
