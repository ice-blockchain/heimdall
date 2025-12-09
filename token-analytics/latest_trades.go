// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/cockroachdb/errors"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) GetLatestTrades(ctx context.Context, externalAddress string, limit, offset uint64, startFrom *time.Time) ([]*Trade, time.Time, error) {
	args := []any{externalAddress}
	timeClause := ""
	if startFrom != nil {
		args = append(args, startFrom)
		timeClause = "AND token_swaps.created_at > $2"
	}
	sql := fmt.Sprintf(`
		SELECT token_swaps.created_at,
		    token_swaps.transaction_hash,
		    token_swaps.contract_address,
		    token_swaps.external_address,
		    tokens.platform,
		    token_swaps.user_address,
		    token_swaps.direction,
		    token_swaps.input_amount,
		    token_swaps.output_amount,
		    token_swaps.price_usd,
		    COALESCE(tokens.creator_master_pubkey, '') as creator_master_pubkey,
			creator.username as creator_username,
			COALESCE(creator.display_name, '') as creator_display,
			COALESCE(creator.verified, false) as creator_verified,
			COALESCE(creator.avatar, '') as creator_avatar,
			creator.external_address as creator_external_address,
			creator.platform_group as creator_platform,

			COALESCE(holder.master_pubkey, '') as holder_master_pubkey,
			holder.username as holder_username,
			COALESCE(holder.display_name, '') as holder_display,
			COALESCE(holder.verified, FALSE) as holder_verified,
			COALESCE(holder.avatar, '') as holder_avatar,
			holder.external_address as holder_external_address,
			holder.platform_group as holder_platform,
			
			COALESCE((utp.amount / 1e18)::DECIMAL, 0) as balance,
			COALESCE(((utp.amount / 1e18) * tokens.price_usd)::DECIMAL, 0) as balance_usd
		FROM token_swaps 
		JOIN tokens ON token_swaps.contract_address = tokens.contract_address
		INNER JOIN users creator ON creator.master_pubkey = tokens.creator_master_pubkey
		INNER JOIN users holder ON holder.blockchain_address = token_swaps.user_address
		INNER JOIN user_token_positions utp ON utp.external_address = token_swaps.external_address AND utp.master_pubkey = holder.master_pubkey
			WHERE tokens.external_address = $1 %[3]v
		ORDER BY token_swaps.created_at DESC
		LIMIT %[1]v OFFSET %[2]v
	`, limit, offset, timeClause)
	swaps, err := storage.Select[tokenSwap](ctx, t.ingestedDataDB, sql, args...)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return []*Trade{}, time.Now(), nil
		}
		return nil, time.Time{}, errors.Wrap(err, "failed to fetch latest trades")
	}
	trades := make([]*Trade, 0, len(swaps))
	var maxTs time.Time
	for i := range swaps {
		if i == 0 {
			maxTs = *swaps[i].CreatedAt.Time
		}
		creatorExternalAddress := swaps[i].CreatorExternalAddress
		holderExternalAddress := swaps[i].HolderExternalAddress
		var tokenAmountWeiStr string
		var typ TradeType
		if !swaps[i].Direction { // Direction=false is buy
			typ = tradeTypeBuy
			tokenAmountWeiStr = swaps[i].Output // User receives tokens
		} else { // Direction=true is sell
			typ = tradeTypeSell
			tokenAmountWeiStr = swaps[i].Input // User sends tokens
		}
		tokenAmountWeiBigInt := new(big.Int)
		if _, ok := tokenAmountWeiBigInt.SetString(tokenAmountWeiStr, 10); !ok {
			log.Warn(fmt.Sprintf("failed to parse token amount for swap %s: %v", swaps[i].TransactionHash, tokenAmountWeiStr))

			continue
		}
		tokenAmount := weiToUint64FromBigInt(tokenAmountWeiBigInt)
		tokenAmountFloat := weiToFloat64FromBigInt(tokenAmountWeiBigInt)
		amountUSD := tokenAmountFloat * swaps[i].PriceUSD

		balanceFloat := new(big.Float)
		if _, ok := balanceFloat.SetString(swaps[i].Balance); !ok {
			log.Warn(fmt.Sprintf("failed to parse balance for swap %s: %v", swaps[i].TransactionHash, swaps[i].Balance))

			continue
		}
		balance, _ := balanceFloat.Uint64()
		creatorAddresses, err := buildAddressesFromExternalAddressAndPlatform(creatorExternalAddress, swaps[i].CreatorPlatform)
		if err != nil {
			log.Warn(fmt.Sprintf("failed to build creator addresses for swap %s: %v", swaps[i].TransactionHash, err))
		}
		holderAddresses, err := buildAddressesFromExternalAddressAndPlatform(holderExternalAddress, swaps[i].HolderPlatform)
		if err != nil {
			log.Warn(fmt.Sprintf("failed to build holder addresses for swap %s: %v", swaps[i].TransactionHash, err))
		}
		tokenAddresses, err := buildAddressesFromExternalAddressAndPlatform(swaps[i].ExternalAddress, swaps[i].Platform)
		if err != nil {
			log.Warn(fmt.Sprintf("failed to build token addresses for swap %s: %v", swaps[i].TransactionHash, err))
			tokenAddresses = Addresses{}
		}
		trades = append(trades, &Trade{
			Creator: User{
				Username:  swaps[i].CreatorUsername,
				Display:   swaps[i].CreatorDisplay,
				Verified:  swaps[i].CreatorVerified,
				Avatar:    swaps[i].CreatorAvatar,
				Addresses: creatorAddresses,
			},
			Position: TradePosition{
				Holder: User{
					Username:  swaps[i].HolderUsername,
					Display:   swaps[i].HolderDisplay,
					Verified:  swaps[i].HolderVerified,
					Avatar:    swaps[i].HolderAvatar,
					Addresses: holderAddresses,
				},
				Addresses:  tokenAddresses,
				CreatedAt:  *swaps[i].CreatedAt.Time,
				Type:       typ,
				Amount:     tokenAmount,
				AmountUSD:  amountUSD,
				Balance:    balance,
				BalanceUSD: swaps[i].BalanceUSD,
			},
		})
	}
	return trades, maxTs, nil
}
