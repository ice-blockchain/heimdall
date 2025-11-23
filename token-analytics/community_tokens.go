// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"math/big"
	"time"

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
			 WHERE token_swaps.ion_connect_address = t.ion_connect_address 
			   AND direction = false 
			   AND created_at > NOW() - INTERVAL '24 hours'), 
			0
		) as volume_24h,
			COALESCE(t.holders_count, 0) as holders_count,
			COALESCE((utp.amount::NUMERIC / 1e18) * t.price_usd, 0) as position_amount_usd,
			COALESCE(utp.total_invested_usd, 0) as position_total_invested_usd
		FROM tokens t
		LEFT JOIN users creator ON creator.master_pubkey = t.creator_master_pubkey
		LEFT JOIN user_token_positions utp ON utp.ion_connect_address = t.ion_connect_address AND utp.master_pubkey = $2
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
			position, err := t.getUserTokenPositionRanking(ctx, requestorMasterPubkey, row.IONConnectAddress, row.PositionAmountUSD, row.PositionTotalInvestedUSD)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to get user position ranking for token %v", row.IONConnectAddress)
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

func (t *tokenAnalytics) GetCommunityTokensByType(ctx context.Context, tokenType, keyword string, limit, offset uint64) ([]*CommunityToken, error) {
	switch tokenType {
	case TokenTypeLatest:
		return t.getCommunityTokensByLatest(ctx, keyword, limit, offset)
	case TokenTypeFeatured:
		return t.getCommunityTokensByFeatured(ctx, limit, offset)
	default:
		return nil, errors.New("unsupported token type")
	}
}

func (t *tokenAnalytics) getCommunityTokensByLatest(ctx context.Context, keyword string, limit, offset uint64) ([]*CommunityToken, error) {
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

func (t *tokenAnalytics) getCommunityTokensByFeatured(ctx context.Context, limit, offset uint64) ([]*CommunityToken, error) {
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
		INNER JOIN tokens_featured tf ON tf.ion_connect_address = t.ion_connect_address
		LEFT JOIN users creator ON creator.master_pubkey = t.creator_master_pubkey
		ORDER BY tf.created_at DESC
		LIMIT $1 OFFSET $2
	`
	args := []interface{}{limit, offset}
	rows, err := storage.Select[tokenRow](ctx, t.ingestedDataDB, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch featured community tokens")
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

func (t *tokenAnalytics) getUserTokenPositionRanking(ctx context.Context, masterPubkey, ionConnectAddress string, amountUSD, totalInvested float64) (*Position, error) {
	key := fmt.Sprintf("position:%s", ionConnectAddress)
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

func (t *tokenAnalytics) GetLatestTrades(ctx context.Context, ionConnectAddress string, limit, offset uint64, startFrom *time.Time) ([]*Trade, time.Time, error) {
	args := []any{ionConnectAddress}
	timeClause := ""
	if startFrom != nil {
		args = append(args, startFrom)
		timeClause = "AND token_swaps.created_at > $2"
	}
	sql := fmt.Sprintf(`
		SELECT token_swaps.*,
		    tokens.ion_connect_address,   
			
		    COALESCE(tokens.creator_master_pubkey, '') as creator_master_pubkey,
			COALESCE(creator.username,'') as creator_username,
			COALESCE(creator.display_name, '') as creator_display,
			COALESCE(creator.verified, false) as creator_verified,
			COALESCE(creator.avatar, '') as creator_avatar,
			
			COALESCE(holder.master_pubkey, '') as holder_master_pubkey,
			COALESCE(holder.username,'') as holder_username,
			COALESCE(holder.display_name, '') as holder_display,
			COALESCE(holder.verified, FALSE) as holder_verified,
			COALESCE(holder.avatar, '') as holder_avatar,
			
			COALESCE((utp.amount/1e18)::DECIMAL, 0) as balance,
			COALESCE((utp.amount/1e18)::DECIMAL*tokens.price_usd,0) as balance_usd
		FROM token_swaps 
		JOIN tokens ON token_swaps.contract_address = tokens.contract_address
		LEFT JOIN users creator ON creator.master_pubkey = tokens.creator_master_pubkey
		LEFT JOIN users holder  ON holder.blockchain_address = token_swaps.user_address
		LEFT JOIN user_token_positions utp ON utp.contract_address = token_swaps.contract_address AND utp.master_pubkey = token_swaps.user_address
			WHERE tokens.ion_connect_address = $1 %[3]v
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
	trades := make([]*Trade, len(swaps))
	var maxTs time.Time
	for i := range swaps {
		if i == 0 {
			maxTs = *swaps[i].CreatedAt.Time
		}
		var creatorIONConnect, holderIONConnect = "", ""
		if swaps[i].CreatorMasterPubkey != "" {
			creatorIONConnect = fmt.Sprintf("0:%s:", swaps[i].CreatorMasterPubkey)
		}
		if swaps[i].HolderMasterPubkey != "" {
			holderIONConnect = fmt.Sprintf("0:%s:", swaps[i].HolderMasterPubkey)
		}
		var tokenAmount uint64
		var typ TradeType
		if swaps[i].Direction {
			typ = tradeTypeBuy
			tokenAmount = swaps[i].Output // User receives tokens
		} else {
			typ = tradeTypeSell
			tokenAmount = swaps[i].Input // User sends tokens
		}
		amountUSD, _ := new(big.Float).Mul(new(big.Float).SetFloat64(swaps[i].PriceUSD), new(big.Float).SetUint64(tokenAmount)).Float64()
		trades[i] = &Trade{
			Creator: User{
				Username:   swaps[i].CreatorUsername,
				Display:    swaps[i].CreatorDisplay,
				Verified:   swaps[i].CreatorVerified,
				Avatar:     swaps[i].CreatorAvatar,
				IonConnect: creatorIONConnect,
			},
			Position: TradePosition{
				Holder: User{
					Username:   swaps[i].HolderUsername,
					Display:    swaps[i].HolderDisplay,
					Verified:   swaps[i].HolderVerified,
					Avatar:     swaps[i].HolderAvatar,
					IonConnect: holderIONConnect,
				},
				Addresses: Addresses{
					Blockchain: swaps[i].ContractAddress,
					IonConnect: swaps[i].IONConnectAddress,
				},
				CreatedAt:  *swaps[i].CreatedAt.Time,
				Type:       typ,
				Amount:     tokenAmount,
				AmountUSD:  amountUSD,
				Balance:    swaps[i].Balance,
				BalanceUSD: swaps[i].BalanceUSD,
			},
		}
	}
	return trades, maxTs, nil
}
