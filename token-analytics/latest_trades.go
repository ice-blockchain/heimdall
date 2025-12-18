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
		    token_swaps.user_blockchain_address,
		    token_swaps.direction,
		    token_swaps.input_amount,
		    token_swaps.output_amount,
		    token_swaps.price_usd,
		    tokens.content_author_id as content_author_id,
			creator.username as creator_username,
			creator.display_name as creator_display,
			creator.verified as creator_verified,
			creator.avatar as creator_avatar,
			creator.external_address as creator_external_address,
			creator.platform_group as creator_platform,
			tokens.bnb_bsc_metadata_owner_address as creator_bnb_bsc_address,

			holder.master_pubkey as holder_master_pubkey,
			holder.username as holder_username,
			holder.display_name as holder_display,
			holder.verified as holder_verified,
			holder.avatar as holder_avatar,
			holder.external_address as holder_external_address,
			holder.platform_group as holder_platform,
			
			utp.amount as balance,
			COALESCE(((utp.amount::NUMERIC / 1e18) * tokens.price_usd), 0) as balance_usd
		FROM token_swaps 
		JOIN tokens ON token_swaps.contract_address = tokens.contract_address
		LEFT JOIN users creator ON LOWER(creator.content_author_id) = LOWER(tokens.content_author_id)
		LEFT JOIN users holder ON LOWER(holder.content_author_id) = LOWER(token_swaps.user_blockchain_address)
		LEFT JOIN user_token_positions utp ON utp.external_address = token_swaps.external_address AND LOWER(utp.user_blockchain_address) = LOWER(token_swaps.user_blockchain_address)
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
		holderExternalAddress := strVal(swaps[i].HolderExternalAddress)
		var tokenAmountWeiStr string
		var typ TradeType
		if !swaps[i].Direction { // Direction=false is buy
			typ = TradeTypeBuy
			tokenAmountWeiStr = swaps[i].Output // User receives tokens
		} else { // Direction=true is sell
			typ = TradeTypeSell
			tokenAmountWeiStr = swaps[i].Input // User sends tokens
		}
		tokenAmountWeiBigInt := new(big.Int)
		if _, ok := tokenAmountWeiBigInt.SetString(tokenAmountWeiStr, 10); !ok {
			log.Warn(fmt.Sprintf("failed to parse token amount for swap %s: %v", swaps[i].TransactionHash, tokenAmountWeiStr))

			continue
		}
		tokenAmountFloat := weiToFloat64FromBigInt(tokenAmountWeiBigInt)
		amountUSD := tokenAmountFloat * swaps[i].PriceUSD

		balanceWei := new(big.Int)
		if _, ok := balanceWei.SetString(swaps[i].Balance, 10); !ok {
			log.Warn(fmt.Sprintf("failed to parse balance wei for swap %s: %v", swaps[i].TransactionHash, swaps[i].Balance))
			balanceWei = big.NewInt(0)
		}
		creatorAddresses, err := buildAddressesFromExternalAddressAndPlatform(strVal(swaps[i].CreatorExternalAddress), strVal(swaps[i].CreatorPlatform), strVal(swaps[i].CreatorBnbBscAddress))
		if err != nil {
			log.Warn(fmt.Sprintf("failed to build creator addresses for swap %s: %v", swaps[i].TransactionHash, err))
		}
		holderAddresses, err := buildAddressesFromExternalAddressAndPlatform(holderExternalAddress, strVal(swaps[i].HolderPlatform), "")
		if err != nil {
			log.Warn(fmt.Sprintf("failed to build holder addresses for swap %s: %v", swaps[i].TransactionHash, err))
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
				Addresses: &Addresses{
					Blockchain: swaps[i].TransactionHash,
				},
				CreatedAt:  swaps[i].CreatedAt,
				Type:       typ,
				Amount:     tokenAmountWeiStr,
				AmountUSD:  amountUSD,
				Balance:    balanceWei.String(),
				BalanceUSD: swaps[i].BalanceUSD,
			},
		})
	}
	return trades, maxTs, nil
}
