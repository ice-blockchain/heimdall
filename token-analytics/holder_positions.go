// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"math/big"

	"github.com/cockroachdb/errors"
	"github.com/redis/go-redis/v9"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) GetHolderPositions(ctx context.Context, tokenExternalAddress string, holderExternalAddresses []string) ([]*HolderPosition, error) {
	if len(holderExternalAddresses) == 0 {
		return []*HolderPosition{}, nil
	}

	query := `
		SELECT 
			u.master_pubkey,
			u.username as username,
			u.display_name as display_name,
			u.avatar as avatar,
			u.verified as verified,
			utp.user_external_address as external_address,
			u.platform_group as platform,
			utp.amount as amount,
			COALESCE(utp.total_invested_usd, 0) as total_invested_usd,
			COALESCE(utp.total_realized_usd, 0) as total_realized_usd,
			COALESCE(t.price_usd, 0) as price_usd
		FROM user_token_positions utp
		LEFT JOIN users u ON u.external_address = utp.user_external_address
		INNER JOIN tokens t ON t.external_address = utp.external_address
		WHERE utp.external_address = $1 
		  AND utp.user_external_address = ANY($2)
	`

	rows, err := storage.Select[holderPositionRow](ctx, t.ingestedDataDB, query, tokenExternalAddress, holderExternalAddresses)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch holder positions")
	}
	key := keyUserPositionOfToken(tokenExternalAddress)
	rankings := make(map[string]int64)
	for _, row := range rows {
		if row.ExternalAddress == nil || *row.ExternalAddress == "" {
			continue
		}
		rank, err := t.processedDataDB.ZRevRank(ctx, key, *row.ExternalAddress).Result()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				continue
			}
			return nil, errors.Wrap(err, "failed to get rank from DragonflyDB")
		}
		rankings[*row.ExternalAddress] = rank + 1
	}

	positions := make([]*HolderPosition, 0, len(rows))
	for _, row := range rows {
		extAddr := strVal(row.ExternalAddress)
		amountWeiBigInt := new(big.Int)
		if _, ok := amountWeiBigInt.SetString(row.Amount, 10); !ok {
			log.Warn(fmt.Sprintf("failed to parse amount for holder %s: %v", extAddr, row.Amount))
			continue
		}

		amountTokensFloat := weiToFloat64FromBigInt(amountWeiBigInt)
		amountUSD := amountTokensFloat * row.PriceUSD
		pnl, pnlPercentage := calculatePnL(amountUSD, row.TotalInvestedUSD, row.TotalRealizedUSD)

		rank := uint64(1)
		if r, ok := rankings[extAddr]; ok {
			rank = uint64(r)
		}
		holderAddresses, err := buildAddressesFromExternalAddressAndPlatform(strVal(row.ExternalAddress), strVal(row.Platform), "")
		if err != nil {
			log.Warn(fmt.Sprintf("failed to build holder addresses from external_address %s (platform %s): %v", extAddr, strVal(row.Platform), err))

			continue
		}

		positions = append(positions, &HolderPosition{
			Rank:          rank,
			Amount:        row.Amount,
			AmountUSD:     amountUSD,
			PnL:           pnl,
			PnLPercentage: pnlPercentage,
			Holder: User{
				Username:  row.Username,
				Display:   row.DisplayName,
				Verified:  row.Verified,
				Avatar:    row.Avatar,
				Addresses: holderAddresses,
			},
		})
	}

	return positions, nil
}
