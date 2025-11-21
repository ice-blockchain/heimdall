// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/redis/go-redis/v9"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) GetCommunityTokensByIonConnectAddresses(ctx context.Context, ionConnectAddresses []string, requestorMasterPubkey string) ([]*CommunityToken, error) {
	if len(ionConnectAddresses) == 0 {
		return []*CommunityToken{}, nil
	}

	query := `
		SELECT 
			t.contract_address,
			t.ion_connect_address,
			t.type,
			creator.username as title,
			COALESCE(creator.display_name, '') as description,
			COALESCE(creator.avatar, '') as image_url,
			t.ticker,
			t.total_supply,
			COALESCE(t.creator_master_pubkey, '') as creator_master_pubkey,
			creator.username as creator_username,
			COALESCE(creator.display_name, '') as creator_display,
			creator.verified as creator_verified,
			COALESCE(creator.avatar, '') as creator_avatar,
			COALESCE(t.market_cap_usd, 0) as market_cap_usd,
			COALESCE(t.price_usd, 0) as price_usd,
		COALESCE(
			(SELECT SUM((input_amount::NUMERIC / 1e18) * price_usd)
			 FROM token_swaps 
			 WHERE token_swaps.contract_address = t.contract_address 
			   AND direction = false 
			   AND created_at > NOW() - INTERVAL '24 hours'), 
			0
		) as volume_24h,
			COALESCE(t.holders_count, 0) as holders_count,
			COALESCE((utp.amount::NUMERIC / 1e18) * t.price_usd, 0) as position_amount_usd,
			COALESCE(utp.total_invested_usd, 0) as position_total_invested_usd
		FROM tokens t
		LEFT JOIN users creator ON creator.master_pubkey = t.creator_master_pubkey
		LEFT JOIN user_token_positions utp ON utp.contract_address = t.contract_address AND utp.master_pubkey = $2
		WHERE t.ion_connect_address = ANY($1)
		ORDER BY t.created_at DESC
	`

	rows, err := storage.Select[tokenRow](ctx, t.ingestedDataDB, query, ionConnectAddresses, requestorMasterPubkey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch community tokens")
	}

	tokens := make([]*CommunityToken, 0, len(rows))
	for _, row := range rows {
		log.Debug(fmt.Sprintf("Row data: contract=%v, position_amount_usd=%v, position_invested=%v",
			row.ContractAddress, row.PositionAmountUSD, row.PositionTotalInvestedUSD))
		marketData := MarketData{
			Ticker:    row.Ticker,
			MarketCap: row.MarketCapUSD,
			Volume:    row.Volume24h,
			Holders:   uint64(row.HoldersCount),
			PriceUSD:  row.PriceUSD,
		}

		if row.PositionAmountUSD > 0 {
			position, err := t.getUserTokenPositionRanking(ctx, requestorMasterPubkey, row.ContractAddress, row.PositionAmountUSD, row.PositionTotalInvestedUSD)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to get user position ranking for token %v", row.ContractAddress)
			}
			if position != nil {
				marketData.Position = *position
			}
		}
		creatorIONConnect := ""
		if row.CreatorMasterPubkey != "" {
			creatorIONConnect = fmt.Sprintf("0:%s:", row.CreatorMasterPubkey)
		}

		token := &CommunityToken{
			Type:        row.Type,
			Title:       row.Title,
			Description: row.Description,
			ImageURL:    row.ImageURL,
			Addresses: Addresses{
				Blockchain: row.ContractAddress,
				IonConnect: row.IONConnectAddress,
			},
			Creator: User{
				Username:   row.CreatorUsername,
				Display:    row.CreatorDisplay,
				Verified:   row.CreatorVerified,
				Avatar:     row.CreatorAvatar,
				IonConnect: creatorIONConnect,
			},
			MarketData: marketData,
		}
		tokens = append(tokens, token)
	}

	return tokens, nil
}

func (t *tokenAnalytics) GetCommunityTokensByType(ctx context.Context, tokenType, keyword string, limit, offset uint32) ([]*CommunityToken, error) {
	query := `
		SELECT 
			t.contract_address,
			t.ion_connect_address,
			t.type,
			t.created_at,
			creator.username as title,
			COALESCE(creator.display_name, '') as description,
			COALESCE(creator.avatar, '') as image_url,
			t.ticker,
			t.total_supply,
			COALESCE(t.creator_master_pubkey, '') as creator_master_pubkey,
			creator.username as creator_username,
			COALESCE(creator.display_name, '') as creator_display,
			creator.verified as creator_verified,
			COALESCE(creator.avatar, '') as creator_avatar,
			COALESCE(t.market_cap_usd, 0) as market_cap_usd,
			COALESCE(t.price_usd, 0) as price_usd,
			COALESCE(
				(SELECT SUM((input_amount::NUMERIC / 1e18) * price_usd)
				 FROM token_swaps 
				 WHERE token_swaps.contract_address = t.contract_address 
				   AND direction = false 
				   AND created_at > NOW() - INTERVAL '24 hours'), 
				0
			) as volume_24h,
			COALESCE(t.holders_count, 0) as holders_count
		FROM tokens t
		LEFT JOIN users creator ON creator.master_pubkey = t.creator_master_pubkey
		WHERE 1=1
	`
	args := []interface{}{}
	argIndex := 1
	if keyword != "" {
		query += fmt.Sprintf(` AND creator.lookup ILIKE $%d`, argIndex)
		args = append(args, "%"+keyword+"%")
		argIndex++
	}
	query += " ORDER BY t.created_at DESC"
	query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIndex, argIndex+1)
	args = append(args, limit, offset)
	rows, err := storage.Select[tokenRow](ctx, t.ingestedDataDB, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch community tokens by type")
	}

	tokens := make([]*CommunityToken, 0, len(rows))
	for _, row := range rows {
		token := &CommunityToken{
			Type:        row.Type,
			Title:       row.Title,
			Description: row.Description,
			ImageURL:    row.ImageURL,
			CreatedAt:   *row.CreatedAt.Time,
			Addresses: Addresses{
				Blockchain: row.ContractAddress,
				IonConnect: row.IONConnectAddress,
			},
			Creator: User{
				Username:   row.CreatorUsername,
				Display:    row.CreatorDisplay,
				Verified:   row.CreatorVerified,
				Avatar:     row.CreatorAvatar,
				IonConnect: fmt.Sprintf("0:%s:", row.CreatorMasterPubkey),
			},
			MarketData: MarketData{
				Ticker:    row.Ticker,
				MarketCap: row.MarketCapUSD,
				Volume:    row.Volume24h,
				Holders:   uint64(row.HoldersCount),
				PriceUSD:  row.PriceUSD,
			},
		}
		tokens = append(tokens, token)
	}

	return tokens, nil
}

func (t *tokenAnalytics) getUserTokenPositionRanking(ctx context.Context, masterPubkey, contractAddress string, amountUSD, totalInvested float64) (*Position, error) {
	contractAddr := strings.ToLower(contractAddress)
	key := fmt.Sprintf("position:%s", contractAddr)

	balanceFloat, err := t.processedDataDB.ZScore(ctx, key, masterPubkey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, errors.Wrap(err, "failed to get balance from DragonflyDB")
	}
	if balanceFloat == 0 {
		return nil, nil
	}
	rank, err := t.processedDataDB.ZRevRank(ctx, key, masterPubkey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			rank = 0
		} else {
			return nil, errors.Wrap(err, "failed to get rank from DragonflyDB")
		}
	}
	pnl := amountUSD - totalInvested
	pnlPercentage := 0.0
	if totalInvested > 0 {
		pnlPercentage = (pnl / totalInvested) * 100
	}
	balanceBigFloat := new(big.Float).SetFloat64(balanceFloat)
	balanceWei := new(big.Float).Mul(balanceBigFloat, big.NewFloat(1e18))
	balanceInt, _ := balanceWei.Int(nil)

	return &Position{
		Rank:          uint64(rank + 1),
		Amount:        balanceInt.Int64(),
		AmountUSD:     amountUSD,
		PnL:           pnl,
		PnLPercentage: pnlPercentage,
	}, nil
}
