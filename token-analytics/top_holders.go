// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"math/big"

	"github.com/cockroachdb/errors"
	"github.com/nbd-wtf/go-nostr"
	"github.com/redis/go-redis/v9"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) GetTopHolders(ctx context.Context, ionConnectAddress string, limit int64) ([]*TopHolderPosition, error) {
	key := fmt.Sprintf("position:%s", ionConnectAddress)
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
	masterPubkeys := make([]string, 0, len(result))
	for _, z := range result {
		if masterPubkey, ok := z.Member.(string); ok {
			masterPubkeys = append(masterPubkeys, masterPubkey)
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
			COALESCE(holder.avatar, '') as holder_avatar
		FROM tokens t
		LEFT JOIN users creator ON creator.master_pubkey = t.creator_master_pubkey
		JOIN users holder ON holder.master_pubkey = ANY($2)
		WHERE t.ion_connect_address = $1
	`
	rows, err := storage.Select[holderWithTokenData](ctx, t.ingestedDataDB, query, ionConnectAddress, masterPubkeys)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch holders data")
	}
	if len(rows) == 0 {
		return []*TopHolderPosition{}, nil
	}

	return buildTopHolderPositions(ionConnectAddress, result, rows), nil
}

func buildTopHolderPositions(ionConnectAddress string, rankings []redis.Z, rows []*holderWithTokenData) []*TopHolderPosition {
	holderDataMap := make(map[string]*holderWithTokenData)
	for i := range rows {
		holderDataMap[rows[i].HolderMasterPubkey] = rows[i]
	}
	holders := make([]*TopHolderPosition, 0, len(rankings))
	for rank, z := range rankings {
		masterPubkey, ok := z.Member.(string)
		if !ok {
			continue
		}
		holderData, exists := holderDataMap[masterPubkey]
		if !exists {
			log.Warn(fmt.Sprintf("User data not found for master_pubkey: %v", masterPubkey))

			continue
		}
		amountEther := z.Score
		amountWei := uint64(amountEther * 1e18)
		amountUSD := amountEther * holderData.PriceUSD

		totalSupplyBigInt, ok := new(big.Int).SetString(holderData.TotalSupply, 10)
		if !ok {
			log.Warn(fmt.Sprintf("Failed to parse total supply for token: %v", ionConnectAddress))
			totalSupplyBigInt = big.NewInt(0)
		}
		totalSupplyFloat := bigIntToFloat(totalSupplyBigInt)

		supplyShare := 0.0
		if totalSupplyFloat > 0 {
			supplyShare = (amountEther / totalSupplyFloat) * 100.0
		}
		holder := &TopHolderPosition{
			Creator: User{
				Username:   holderData.CreatorUsername,
				Display:    holderData.CreatorDisplay,
				Verified:   holderData.CreatorVerified,
				Avatar:     holderData.CreatorAvatar,
				IonConnect: fmt.Sprintf("%v:%s:", nostr.KindProfileMetadata, holderData.CreatorMasterPubkey),
			},
			Position: HolderPosition{
				Holder: User{
					MasterPubkey: masterPubkey,
					Username:     holderData.HolderUsername,
					Display:      holderData.HolderDisplay,
					Verified:     holderData.HolderVerified,
					Avatar:       holderData.HolderAvatar,
					IonConnect:   fmt.Sprintf("%v:%s:", nostr.KindProfileMetadata, masterPubkey),
				},
				Rank:        uint64(rank + 1),
				Amount:      amountWei,
				AmountUSD:   amountUSD,
				SupplyShare: supplyShare,
			},
		}

		holders = append(holders, holder)
	}

	return holders
}
