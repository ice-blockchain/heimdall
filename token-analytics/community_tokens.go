// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/redis/go-redis/v9"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) GetCommunityTokensByExternalAddresses(ctx context.Context, externalAddresses []string, requestorMasterPubkey string, includeTopHolders *uint32) ([]*CommunityToken, error) {
	if len(externalAddresses) == 0 {
		return []*CommunityToken{}, nil
	}
	if includeTopHolders != nil && *includeTopHolders > 0 {
		return t.getCommunityTokensWithTopHolders(ctx, externalAddresses, requestorMasterPubkey, includeTopHolders)
	}
	query := `
		SELECT 
			t.contract_address,
			t.external_address,
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
			COALESCE(t.base_token, '') as base_token,
			COALESCE(t.pair_id, '') as pair_id,
		COALESCE(
			(SELECT SUM((input_amount::NUMERIC / 1e18) * price_usd)
			 FROM token_swaps 
			 WHERE token_swaps.external_address = t.external_address 
			   AND direction = false 
			   AND created_at > NOW() - INTERVAL '24 hours'), 
			0
		) as volume_24h,
			COALESCE(t.holders_count, 0) as holders_count,
			COALESCE((utp.amount::NUMERIC / 1e18) * t.price_usd, 0) as position_amount_usd,
			COALESCE(utp.total_invested_usd, 0) as position_total_invested_usd
		FROM tokens t
		LEFT JOIN users creator ON creator.master_pubkey = t.creator_master_pubkey
		LEFT JOIN user_token_positions utp ON utp.external_address = t.external_address AND utp.master_pubkey = $2
		WHERE t.external_address = ANY($1)
		ORDER BY t.created_at DESC
	`

	rows, err := storage.Select[tokenRow](ctx, t.ingestedDataDB, query, externalAddresses, requestorMasterPubkey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch community tokens")
	}
	return t.buildCommunityTokensFromRows(ctx, rows, requestorMasterPubkey)
}

func (t *tokenAnalytics) buildCommunityTokensFromRows(ctx context.Context, rows []*tokenRow, requestorMasterPubkey string) ([]*CommunityToken, error) {
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
			externalAddress := fmt.Sprintf("ion_connect:0:%s:", requestorMasterPubkey)
			position, err := t.getUserTokenPositionRanking(ctx, externalAddress, row.ExternalAddress, row.PositionAmountUSD, row.PositionTotalInvestedUSD)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to get user position ranking for token %v", row.ExternalAddress)
			}
			if position != nil {
				marketData.Position = *position
			}
		}

		token := &CommunityToken{
			Type:        row.Type,
			Title:       row.Title,
			Description: row.Description,
			ImageURL:    row.ImageURL,
			Addresses:   buildAddressesFromExternalAddress(row.ExternalAddress),
			Creator: User{
				Username:  row.CreatorUsername,
				Display:   row.CreatorDisplay,
				Verified:  row.CreatorVerified,
				Avatar:    row.CreatorAvatar,
				Addresses: buildAddressesFromExternalAddress(fmt.Sprintf("0:%s:", row.CreatorMasterPubkey)),
			},
			MarketData: marketData,
		}
		tokens = append(tokens, token)
	}

	return tokens, nil
}

func (t *tokenAnalytics) getCommunityTokensWithTopHolders(ctx context.Context, externalAddresses []string, requestorMasterPubkey string, includeTopHolders *uint32) ([]*CommunityToken, error) {
	limit := int64(*includeTopHolders)
	if limit > 10 {
		limit = 10
	}

	query := `
		SELECT 
			t.contract_address,
			t.external_address,
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
				 WHERE token_swaps.external_address = t.external_address 
				   AND direction = false 
				   AND created_at > NOW() - INTERVAL '24 hours'), 
				0
			) as volume_24h,
			COALESCE(t.holders_count, 0) as holders_count,
			COALESCE((utp.amount::NUMERIC / 1e18) * t.price_usd, 0) as position_amount_usd,
			COALESCE(utp.total_invested_usd, 0) as position_total_invested_usd,
			COALESCE(
				(SELECT JSON_AGG(
					JSON_BUILD_OBJECT(
						'holder_master_pubkey', holder_master_pubkey,
						'holder_username', holder_username,
						'holder_display', holder_display,
						'holder_verified', holder_verified,
						'holder_avatar', holder_avatar,
						'holder_external_address', holder_external_address
					) ORDER BY amount DESC
				)
				FROM (
					SELECT
						holder.master_pubkey as holder_master_pubkey,
						COALESCE(holder.username, '') as holder_username,
						COALESCE(holder.display_name, '') as holder_display,
						COALESCE(holder.verified, false) as holder_verified,
						COALESCE(holder.avatar, '') as holder_avatar,
						COALESCE(holder.external_address, '') as holder_external_address,
						utp_holders.amount as amount
					FROM user_token_positions utp_holders
					LEFT JOIN users holder ON holder.master_pubkey = utp_holders.master_pubkey
					WHERE utp_holders.external_address = t.external_address
					ORDER BY utp_holders.amount DESC
					LIMIT $3
				) top_holders_subquery
				), '[]'::JSON
			) as top_holders_json
		FROM tokens t
		LEFT JOIN users creator ON creator.master_pubkey = t.creator_master_pubkey
		LEFT JOIN user_token_positions utp ON utp.external_address = t.external_address AND utp.master_pubkey = $2
		WHERE t.external_address = ANY($1)
		ORDER BY t.created_at DESC
	`
	rows, err := storage.Select[tokenRowWithTopHolders](ctx, t.ingestedDataDB, query, externalAddresses, requestorMasterPubkey, limit)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch community tokens with top holders")
	}

	tokenHoldersMetadata, rankingsCmds, err := t.fetchTopHoldersRankingsBatch(ctx, rows, limit)
	if err != nil {
		return nil, err
	}

	tokens := make([]*CommunityToken, 0, len(rows))
	for _, row := range rows {
		log.Debug(fmt.Sprintf("Row data: contract=%v, position_amount_usd=%v, position_invested=%v",
			row.ContractAddress, row.PositionAmountUSD, row.PositionTotalInvestedUSD))

		topHolders, err := t.buildTopHoldersFromRankings(row, tokenHoldersMetadata, rankingsCmds)
		if err != nil {
			return nil, err
		}
		marketData := MarketData{
			Ticker:     row.Ticker,
			MarketCap:  row.MarketCapUSD,
			Volume:     row.Volume24h,
			Holders:    uint64(row.HoldersCount),
			PriceUSD:   row.PriceUSD,
			TopHolders: topHolders,
		}
		if row.PositionAmountUSD > 0 {
			externalAddress := fmt.Sprintf("ion_connect:0:%s:", requestorMasterPubkey)
			position, err := t.getUserTokenPositionRanking(ctx, externalAddress, row.ExternalAddress, row.PositionAmountUSD, row.PositionTotalInvestedUSD)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to get user position ranking for token %v", row.ExternalAddress)
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
			Addresses:   buildAddressesFromExternalAddress(row.ExternalAddress),
			Creator: User{
				Username:  row.CreatorUsername,
				Display:   row.CreatorDisplay,
				Verified:  row.CreatorVerified,
				Avatar:    row.CreatorAvatar,
				Addresses: buildAddressesFromExternalAddress(creatorIONConnect),
			},
			MarketData: marketData,
		}
		tokens = append(tokens, token)
	}

	return tokens, nil
}

func (t *tokenAnalytics) GetCommunityTokensByType(ctx context.Context, viewType string, tokenType *string, keyword string, limit, offset uint64) ([]*CommunityToken, error) {
	switch viewType {
	case TokenTypeLatest:
		return t.getCommunityTokensByLatest(ctx, keyword, limit, offset, tokenType)
	case TokenTypeFeatured:
		return t.getCommunityTokensByFeatured(ctx, limit, offset, tokenType)
	default:
		return nil, errors.New("unsupported token type")
	}
}

func (t *tokenAnalytics) getCommunityTokensByLatest(ctx context.Context, keyword string, limit, offset uint64, tokenType *string) ([]*CommunityToken, error) {
	query := `
		SELECT 
			t.contract_address,
			t.external_address,
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

	if tokenType != nil && *tokenType != "" {
		query += fmt.Sprintf(` AND t.type = $%d`, argIndex)
		args = append(args, *tokenType)
		argIndex++
	}
	if keyword != "" {
		query += fmt.Sprintf(` AND t.lookup ILIKE $%d`, argIndex)
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
			Addresses:   buildAddressesFromExternalAddress(row.ExternalAddress),
			Creator: User{
				Username:  row.CreatorUsername,
				Display:   row.CreatorDisplay,
				Verified:  row.CreatorVerified,
				Avatar:    row.CreatorAvatar,
				Addresses: buildAddressesFromExternalAddress(fmt.Sprintf("0:%s:", row.CreatorMasterPubkey)),
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

func (t *tokenAnalytics) getCommunityTokensByFeatured(ctx context.Context, limit, offset uint64, tokenType *string) ([]*CommunityToken, error) {
	query := `
		SELECT 
			t.contract_address,
			t.external_address,
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
		INNER JOIN tokens_featured tf ON tf.external_address = t.external_address
		LEFT JOIN users creator ON creator.master_pubkey = t.creator_master_pubkey
	`

	args := []interface{}{}
	argIndex := 1

	if tokenType != nil && *tokenType != "" {
		query += fmt.Sprintf(` WHERE t.type = $%d`, argIndex)
		args = append(args, *tokenType)
		argIndex++
	}

	query += ` ORDER BY tf.created_at DESC`
	query += fmt.Sprintf(` LIMIT $%d OFFSET $%d`, argIndex, argIndex+1)
	args = append(args, limit, offset)
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
			Addresses:   buildAddressesFromExternalAddress(row.ExternalAddress),
			Creator: User{
				Username:  row.CreatorUsername,
				Display:   row.CreatorDisplay,
				Verified:  row.CreatorVerified,
				Avatar:    row.CreatorAvatar,
				Addresses: buildAddressesFromExternalAddress(fmt.Sprintf("0:%s:", row.CreatorMasterPubkey)),
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

func (t *tokenAnalytics) getUserTokenPositionRanking(ctx context.Context, userIonConnect, tokenIonConnectAddress string, amountUSD, totalInvested float64) (*Position, error) {
	key := keyUserPositionOfToken(tokenIonConnectAddress)
	balanceFloat, err := t.processedDataDB.ZScore(ctx, key, userIonConnect).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, errors.Wrap(err, "failed to get balance from DragonflyDB")
	}
	if balanceFloat == 0 {
		return nil, nil
	}
	rank, err := t.processedDataDB.ZRevRank(ctx, key, userIonConnect).Result()
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
		SELECT token_swaps.created_at,
		    token_swaps.transaction_hash,
		    token_swaps.contract_address,
		    token_swaps.external_address,
		    token_swaps.user_address,
		    token_swaps.direction,
		    token_swaps.input_amount,
		    token_swaps.output_amount,
		    token_swaps.price_usd,
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
		LEFT JOIN user_token_positions utp ON utp.external_address = token_swaps.external_address AND utp.master_pubkey = token_swaps.user_address
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
		if !swaps[i].Direction { // Direction=false is buy
			typ = tradeTypeBuy
			tokenAmount = swaps[i].Output // User receives tokens
		} else { // Direction=true is sell
			typ = tradeTypeSell
			tokenAmount = swaps[i].Input // User sends tokens
		}
		amountUSD, _ := new(big.Float).Mul(new(big.Float).SetFloat64(swaps[i].PriceUSD), new(big.Float).SetUint64(tokenAmount)).Float64()
		trades[i] = &Trade{
			Creator: User{
				Username:  swaps[i].CreatorUsername,
				Display:   swaps[i].CreatorDisplay,
				Verified:  swaps[i].CreatorVerified,
				Avatar:    swaps[i].CreatorAvatar,
				Addresses: buildAddressesFromExternalAddress(creatorIONConnect),
			},
			Position: TradePosition{
				Holder: User{
					Username:  swaps[i].HolderUsername,
					Display:   swaps[i].HolderDisplay,
					Verified:  swaps[i].HolderVerified,
					Avatar:    swaps[i].HolderAvatar,
					Addresses: buildAddressesFromExternalAddress(holderIONConnect),
				},
				Addresses:  buildAddressesFromExternalAddress(swaps[i].ExternalAddress),
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

func (t *tokenAnalytics) UpdateTokenExternalData(ctx context.Context, externalAddress, creatorUsername, creatorDisplayName, creatorAvatar string, creatorVerified bool) error {
	query := `
		INSERT INTO users (
			created_at, updated_at, id, master_pubkey, blockchain_address, 
			external_address, username, display_name, avatar, verified, lookup
		)
		VALUES (
			NOW(), NOW(), $1, $1, '', 
			$1, $2, $3, $4, $5, LOWER($2 || ' ' || COALESCE($3, ''))
		)
		ON CONFLICT (master_pubkey) 
		DO UPDATE SET
			external_address = EXCLUDED.external_address,
			username = EXCLUDED.username,
			display_name = EXCLUDED.display_name,
			avatar = EXCLUDED.avatar,
			verified = EXCLUDED.verified,
			lookup = EXCLUDED.lookup,
			updated_at = NOW()
	`

	_, err := storage.Exec(ctx, t.ingestedDataDB, query,
		externalAddress,
		creatorUsername,
		creatorDisplayName,
		creatorAvatar,
		creatorVerified,
	)
	if err != nil {
		return fmt.Errorf("failed to upsert user external data: %w", err)
	}

	return nil
}

func (t *tokenAnalytics) fetchTopHoldersRankingsBatch(ctx context.Context, rows []*tokenRowWithTopHolders, limit int64) (map[string][]holderMetadata, map[string]*redis.ZSliceCmd, error) {
	tokenHoldersMetadata := make(map[string][]holderMetadata, len(rows))
	for _, row := range rows {
		if row.TopHoldersJSON != "" && row.TopHoldersJSON != "[]" {
			var metadata []holderMetadata
			if err := json.Unmarshal([]byte(row.TopHoldersJSON), &metadata); err != nil {
				return nil, nil, errors.Wrapf(err, "failed to parse top holders JSON for token %v", row.ExternalAddress)
			}
			tokenHoldersMetadata[row.ExternalAddress] = metadata
		}
	}
	rankingsCmds := make(map[string]*redis.ZSliceCmd, len(tokenHoldersMetadata))
	if responses, txErr := t.processedDataDB.TxPipelined(ctx, func(pipeliner redis.Pipeliner) error {
		for tokenAddr := range tokenHoldersMetadata {
			key := keyUserPositionOfToken(tokenAddr)
			rankingsCmds[tokenAddr] = pipeliner.ZRevRangeWithScores(ctx, key, 0, limit-1)
		}
		return nil
	}); txErr != nil {
		return nil, nil, errors.Wrap(txErr, "failed to fetch top holders rankings from Redis")
	} else {
		for _, response := range responses {
			if rerr := response.Err(); rerr != nil && !errors.Is(rerr, redis.Nil) {
				return nil, nil, errors.Wrapf(rerr, "failed to `%v`", response.FullName())
			}
		}
	}

	return tokenHoldersMetadata, rankingsCmds, nil
}

func (t *tokenAnalytics) buildTopHoldersFromRankings(row *tokenRowWithTopHolders, tokenHoldersMetadata map[string][]holderMetadata, rankingsCmds map[string]*redis.ZSliceCmd) ([]HolderPosition, error) {
	topHolders := make([]HolderPosition, 0)
	metadata, hasMetadata := tokenHoldersMetadata[row.ExternalAddress]
	if !hasMetadata {
		return topHolders, nil
	}
	rankingsCmd, hasRankings := rankingsCmds[row.ExternalAddress]
	if !hasRankings {
		log.Warn(fmt.Sprintf("No rankings command found for token %v", row.ExternalAddress))
		return topHolders, nil
	}
	rankings, err := rankingsCmd.Result()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get rankings result for token %v", row.ExternalAddress)
	}
	holderMetadataMap := make(map[string]*holderMetadata, len(metadata))
	for i := range metadata {
		holderMetadataMap[metadata[i].HolderExternalAddress] = &metadata[i]
	}

	totalSupplyFloat, err := parseTotalSupply(row.TotalSupply, row.ExternalAddress)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse total supply for token %v", row.ExternalAddress)
	}

	for rank, z := range rankings {
		userExternalAddress, ok := z.Member.(string)
		if !ok {
			continue
		}
		holderMeta, exists := holderMetadataMap[userExternalAddress]
		if !exists {
			log.Warn(fmt.Sprintf("Holder metadata not found for external_address: %v", userExternalAddress))
			continue
		}

		amountTokens := z.Score
		amountUSD := amountTokens * row.PriceUSD
		supplyShare := calculateSupplyShare(amountTokens, totalSupplyFloat)

		topHolders = append(topHolders, HolderPosition{
			Holder: User{
				Username:  holderMeta.HolderUsername,
				Display:   holderMeta.HolderDisplay,
				Verified:  holderMeta.HolderVerified,
				Avatar:    holderMeta.HolderAvatar,
				Addresses: buildAddressesFromExternalAddress(holderMeta.HolderExternalAddress),
			},
			Rank:        uint64(rank + 1),
			Amount:      uint64(amountTokens),
			AmountUSD:   amountUSD,
			SupplyShare: supplyShare,
		})
	}

	return topHolders, nil
}

func parseTotalSupply(totalSupply, tokenAddress string) (float64, error) {
	totalSupplyBigInt := new(big.Int)
	if _, ok := totalSupplyBigInt.SetString(totalSupply, 10); !ok {
		return 0, errors.Errorf("failed to parse total supply for token %v", tokenAddress)
	}

	return bigIntToFloat(totalSupplyBigInt), nil
}

func calculateSupplyShare(amountTokens, totalSupply float64) float64 {
	if totalSupply > 0 {
		return (amountTokens / totalSupply) * 100.0
	}

	return 0.0
}
