// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"math/big"

	"github.com/cockroachdb/errors"

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
			COALESCE(u.display_name, '') as display_name,
			COALESCE(u.avatar, '') as avatar,
			COALESCE(u.verified, false) as verified,
			u.external_address as external_address,
			u.platform_group as platform,
			COALESCE(utp.amount, 0) as amount,
			COALESCE(utp.total_invested_usd, 0) as total_invested_usd,
			COALESCE(t.price_usd, 0) as price_usd
		FROM users u
		LEFT JOIN user_token_positions utp ON utp.master_pubkey = u.master_pubkey AND utp.external_address = $1
		LEFT JOIN tokens t ON t.external_address = $1
		WHERE u.external_address = ANY($2)
	`

	rows, err := storage.Select[holderPositionRow](ctx, t.ingestedDataDB, query, tokenExternalAddress, holderExternalAddresses)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch holder positions")
	}
	key := keyUserPositionOfToken(tokenExternalAddress)
	rankings := make(map[string]int64)
	for _, row := range rows {
		if row.ExternalAddress == "" {
			continue
		}
		rank, err := t.processedDataDB.ZRevRank(ctx, key, row.ExternalAddress).Result()
		if err != nil {
			return nil, errors.Wrap(err, "failed to get rank from DragonflyDB")
		}
		rankings[row.ExternalAddress] = rank + 1
	}

	positions := make([]*HolderPosition, 0, len(rows))
	for _, row := range rows {
		amountWeiBigInt := new(big.Int)
		if _, ok := amountWeiBigInt.SetString(row.Amount, 10); !ok {
			log.Warn(fmt.Sprintf("failed to parse amount for holder %s: %v", row.ExternalAddress, row.Amount))
			continue
		}

		amountTokens := weiToUint64FromBigInt(amountWeiBigInt)
		amountTokensFloat := weiToFloat64FromBigInt(amountWeiBigInt)
		amountUSD := amountTokensFloat * row.PriceUSD
		pnl, pnlPercentage := calculatePnL(amountUSD, row.TotalInvestedUSD)

		rank := uint64(0)
		if r, ok := rankings[row.ExternalAddress]; ok {
			rank = uint64(r)
		}
		holderAddresses, err := buildAddressesFromExternalAddressAndPlatform(row.ExternalAddress, row.Platform)
		if err != nil {
			log.Warn(fmt.Sprintf("failed to build holder addresses from external_address %s (platform %s): %v", row.ExternalAddress, row.Platform, err))

			continue
		}

		positions = append(positions, &HolderPosition{
			Rank:          rank,
			Amount:        amountTokens,
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
