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

func (t *tokenAnalytics) GetCommunityTokensByExternalAddresses(ctx context.Context, externalAddresses []string, requestorMasterPubkey string, includeTopPlatformHolders *uint32, keyword string, limit, offset uint64) ([]*CommunityToken, error) {
	if len(externalAddresses) == 0 {
		return []*CommunityToken{}, nil
	}
	if keyword != "" {
		return t.searchCommunityTokens(ctx, externalAddresses, requestorMasterPubkey, keyword, limit, offset)
	}

	if includeTopPlatformHolders != nil && *includeTopPlatformHolders > 0 {
		return t.getCommunityTokensWithTopPlatformHolders(ctx, externalAddresses, requestorMasterPubkey, includeTopPlatformHolders, keyword, limit, offset)
	}

	query := `
		SELECT 
			t.contract_address,
			t.external_address,
			t.platform as platform,
			t.type,
			creator.username as title,
			COALESCE(creator.display_name, '') as description,
			COALESCE(creator.avatar, '') as image_url,
			t.ticker,
			t.total_supply,
			t.created_at,
			COALESCE(t.creator_master_pubkey, '') as creator_master_pubkey,
			creator.username as creator_username,
			COALESCE(creator.display_name, '') as creator_display,
			creator.verified as creator_verified,
			COALESCE(creator.avatar, '') as creator_avatar,
			creator.external_address as creator_external_address,
			creator.platform_group as creator_platform,
			COALESCE(t.market_cap_usd, 0) as market_cap_usd,
			COALESCE(t.price_usd, 0) as price_usd,
			COALESCE(t.base_token, '') as base_token,
			COALESCE(t.pair_id, '') as pair_id,
			COALESCE(tv.volume_24h / 1e18, 0) as volume_24h,
			COALESCE(t.holders_count, 0) as holders_count,
			COALESCE(tph.holders_count, 0) as platform_holders_count,
			COALESCE(t.bonding_curve_current_amount, '0') as bonding_curve_current_amount,
			COALESCE(t.bonding_curve_goal_amount, '0') as bonding_curve_goal_amount,
			COALESCE(t.bonding_curve_current_amount_usd, 0) as bonding_curve_current_amount_usd,
			COALESCE(t.bonding_curve_goal_amount_usd, 0) as bonding_curve_goal_amount_usd,
			COALESCE((utp.amount::NUMERIC / 1e18) * t.price_usd, 0) as position_amount_usd,
			COALESCE(utp.total_invested_usd, 0) as position_total_invested_usd
		FROM tokens t
		LEFT JOIN users creator ON creator.master_pubkey = t.creator_master_pubkey
		LEFT JOIN user_token_positions utp ON utp.external_address = t.external_address AND utp.master_pubkey = $2
		LEFT JOIN token_volumes_24h tv ON tv.contract_address = t.contract_address
		LEFT JOIN token_platform_holders tph ON tph.external_address = t.external_address 
			AND tph.platform_group = (SELECT platform_group FROM users WHERE master_pubkey = $2)
		WHERE t.external_address = ANY($1)
		ORDER BY t.created_at DESC
	`
	rows, err := storage.Select[tokenRow](ctx, t.ingestedDataDB, query, externalAddresses, requestorMasterPubkey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch community tokens")
	}

	return t.buildCommunityTokensFromRows(ctx, rows, requestorMasterPubkey)
}

func (t *tokenAnalytics) searchCommunityTokens(ctx context.Context, externalAddresses []string, requestorMasterPubkey string, keyword string, limit, offset uint64) ([]*CommunityToken, error) {
	kw := strings.ToLower(keyword)
	query := `
		WITH candidates AS (
			SELECT 
				t.contract_address,
				t.external_address,
				t.platform as platform,
				t.type,
				t.created_at,
				t.creator_master_pubkey,
				t.market_cap_usd,
				t.price_usd,
				t.holders_count,
				tv.volume_24h,
				creator.username,
				creator.display_name,
				creator.verified,
				creator.avatar,
				creator.external_address as creator_external_address,
				creator.platform_group as creator_platform,
				GREATEST(
					similarity(t.lookup, $2),
					word_similarity($2, t.lookup)
				) + 
				CASE 
					WHEN t.lookup LIKE $2 || ' %' THEN 1.0
					WHEN t.lookup LIKE $2 || '%' THEN 0.5
					ELSE 0.0
				END AS relevance_score
			FROM tokens t
			LEFT JOIN users creator ON creator.master_pubkey = t.creator_master_pubkey
			LEFT JOIN token_volumes_24h tv ON tv.contract_address = t.contract_address
			WHERE t.external_address = ANY($1)
			  AND t.lookup LIKE '%' || $2 || '%'
			ORDER BY t.lookup <-> $2
			LIMIT 250
		)
		SELECT 
			contract_address,
			external_address,
			platform,
			type,
			username as title,
			COALESCE(display_name, '') as description,
			COALESCE(avatar, '') as image_url,
			created_at,
			COALESCE(creator_master_pubkey, '') as creator_master_pubkey,
			username as creator_username,
			COALESCE(display_name, '') as creator_display,
			verified as creator_verified,
			COALESCE(avatar, '') as creator_avatar,
			creator_external_address as creator_external_address,
			creator_platform,
			COALESCE(market_cap_usd, 0) as market_cap_usd,
			COALESCE(price_usd, 0) as price_usd,
			COALESCE(volume_24h / 1e18, 0) as volume_24h,
			COALESCE(holders_count, 0) as holders_count
		FROM candidates
		ORDER BY relevance_score DESC, volume_24h DESC, created_at DESC`

	args := []interface{}{externalAddresses, kw}
	argIndex := 3

	if limit > 0 {
		query += fmt.Sprintf(` LIMIT $%d`, argIndex)
		args = append(args, limit)
		argIndex++
	}
	if offset > 0 {
		query += fmt.Sprintf(` OFFSET $%d`, argIndex)
		args = append(args, offset)
	}

	rows, err := storage.Select[tokenRow](ctx, t.ingestedDataDB, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to search community tokens")
	}
	tokens := make([]*CommunityToken, 0, len(rows))
	for _, row := range rows {
		tokenAddresses, err := buildAddressesFromExternalAddressAndPlatform(row.ExternalAddress, row.Platform)
		if err != nil {
			return nil, fmt.Errorf("failed to build addresses from external_address %s (platform %s): %w", row.ExternalAddress, row.Platform, err)
		}
		creatorAddresses, err := buildAddressesFromExternalAddressAndPlatform(row.CreatorExternalAddress, row.CreatorPlatform)
		if err != nil {
			return nil, fmt.Errorf("failed to build creator addresses from external_address %s (platform %s): %w", row.CreatorExternalAddress, row.CreatorPlatform, err)
		}

		token := &CommunityToken{
			Type:        row.Type,
			Title:       row.Title,
			Description: row.Description,
			ImageURL:    row.ImageURL,
			CreatedAt:   *row.CreatedAt.Time,
			Addresses:   tokenAddresses,
			Creator: User{
				Username:  row.CreatorUsername,
				Display:   row.CreatorDisplay,
				Verified:  row.CreatorVerified,
				Avatar:    row.CreatorAvatar,
				Addresses: creatorAddresses,
			},
			MarketData: MarketData{
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

func (t *tokenAnalytics) buildCommunityTokensFromRows(ctx context.Context, rows []*tokenRow, requestorMasterPubkey string) ([]*CommunityToken, error) {
	tokens := make([]*CommunityToken, 0, len(rows))
	for _, row := range rows {
		log.Debug(fmt.Sprintf("Row data: contract=%v, position_amount_usd=%v, position_invested=%v",
			row.ContractAddress, row.PositionAmountUSD, row.PositionTotalInvestedUSD))
		var bondingCurveProgress *BondingCurveProgress
		if row.BondingCurveCurrentAmount != "" && row.BondingCurveCurrentAmount != "0" && row.BondingCurveGoalAmount != "" && row.BondingCurveGoalAmount != "0" {
			currentAmount, _ := new(big.Int).SetString(row.BondingCurveCurrentAmount, 10)
			goalAmount, _ := new(big.Int).SetString(row.BondingCurveGoalAmount, 10)
			bondingCurveProgress = &BondingCurveProgress{
				CurrentAmount:    weiToUint64FromBigInt(currentAmount),
				GoalAmount:       weiToUint64FromBigInt(goalAmount),
				CurrentAmountUSD: row.BondingCurveCurrentAmountUSD,
				GoalAmountUSD:    row.BondingCurveGoalAmountUSD,
			}
		}

		marketData := MarketData{
			Ticker:               row.Ticker,
			MarketCap:            row.MarketCapUSD,
			Volume:               row.Volume24h,
			Holders:              uint64(row.HoldersCount),
			PlatformHolders:      uint64(row.PlatformHoldersCount),
			PriceUSD:             row.PriceUSD,
			BondingCurveProgress: bondingCurveProgress,
		}

		if row.PositionAmountUSD > 0 {
			externalAddress := BuildProfileExternalAddress(requestorMasterPubkey)
			position, err := t.getUserTokenPositionRanking(ctx, externalAddress, row.ExternalAddress, row.PositionAmountUSD, row.PositionTotalInvestedUSD)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to get user position ranking for token %v", row.ExternalAddress)
			}
			if position != nil {
				marketData.Position = *position
			}
		}
		tokenAddresses, err := buildAddressesFromExternalAddressAndPlatform(row.ExternalAddress, row.Platform)
		if err != nil {
			return nil, fmt.Errorf("failed to build addresses from external_address %s (platform %s): %w", row.ExternalAddress, row.Platform, err)
		}
		creatorAddresses, err := buildAddressesFromExternalAddressAndPlatform(row.CreatorExternalAddress, row.CreatorPlatform)
		if err != nil {
			return nil, fmt.Errorf("failed to build creator addresses from external_address %s (platform %s): %w", row.CreatorExternalAddress, row.CreatorPlatform, err)
		}
		token := &CommunityToken{
			Type:        row.Type,
			Title:       row.Title,
			Description: row.Description,
			ImageURL:    row.ImageURL,
			Addresses:   tokenAddresses,
			Creator: User{
				Username:  row.CreatorUsername,
				Display:   row.CreatorDisplay,
				Verified:  row.CreatorVerified,
				Avatar:    row.CreatorAvatar,
				Addresses: creatorAddresses,
			},
			MarketData: marketData,
		}
		tokens = append(tokens, token)
	}

	return tokens, nil
}

func (t *tokenAnalytics) getCommunityTokensWithTopPlatformHolders(ctx context.Context, externalAddresses []string, requestorMasterPubkey string, includeTopPlatformHolders *uint32, keyword string, limit, offset uint64) ([]*CommunityToken, error) {
	const (
		requestorPlatformCTE = `WITH requestor_platform AS (
				SELECT platform_group FROM users WHERE master_pubkey = $2 LIMIT 1
			)`

		selectClause = `SELECT 
			t.contract_address,
			t.external_address,
			t.platform as platform,
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
				creator.external_address as creator_external_address,
				creator.platform_group as creator_platform,
				COALESCE(t.market_cap_usd, 0) as market_cap_usd,
				COALESCE(t.price_usd, 0) as price_usd,
				COALESCE(tv.volume_24h / 1e18, 0) as volume_24h,
				COALESCE(t.holders_count, 0) as holders_count,
				COALESCE(tph.holders_count, 0) as platform_holders_count,
				COALESCE(t.bonding_curve_current_amount, '0') as bonding_curve_current_amount,
				COALESCE(t.bonding_curve_goal_amount, '0') as bonding_curve_goal_amount,
				COALESCE(t.bonding_curve_current_amount_usd, 0) as bonding_curve_current_amount_usd,
				COALESCE(t.bonding_curve_goal_amount_usd, 0) as bonding_curve_goal_amount_usd,
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
							'holder_external_address', holder_external_address,
							'holder_platform', holder_platform
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
							COALESCE(holder.platform_group, 'ionconnect') as holder_platform,
							utp_holders.amount as amount
						FROM user_token_positions utp_holders
						LEFT JOIN users holder ON holder.master_pubkey = utp_holders.master_pubkey
						LEFT JOIN requestor_platform rp ON true
						WHERE utp_holders.external_address = t.external_address
						  AND (rp.platform_group IS NULL OR holder.platform_group = rp.platform_group)
						ORDER BY utp_holders.amount DESC
						LIMIT $3
					) top_holders_subquery
					), '[]'::JSON
				) as top_platform_holders_json`

		fromJoinsClause = `FROM %s t
			LEFT JOIN requestor_platform rp ON true
			LEFT JOIN users creator ON creator.master_pubkey = t.creator_master_pubkey
			LEFT JOIN user_token_positions utp ON utp.external_address = t.external_address AND utp.master_pubkey = $2
			LEFT JOIN token_volumes_24h tv ON tv.contract_address = t.contract_address
			LEFT JOIN token_platform_holders tph ON tph.external_address = t.external_address 
				AND (rp.platform_group IS NULL OR tph.platform_group = rp.platform_group)`
	)

	var query string
	args := []interface{}{externalAddresses, requestorMasterPubkey, *includeTopPlatformHolders}
	argIndex := 4

	if keyword != "" {
		kw := strings.ToLower(keyword)
		query = requestorPlatformCTE + `,
			candidates AS (
			SELECT 
					t.contract_address,
					t.external_address,
					t.platform,
					t.type,
					t.ticker,
					t.total_supply,
					t.creator_master_pubkey,
					t.market_cap_usd,
					t.price_usd,
					t.holders_count,
					t.bonding_curve_current_amount,
					t.bonding_curve_goal_amount,
					t.bonding_curve_current_amount_usd,
					t.bonding_curve_goal_amount_usd,
					t.created_at,
					GREATEST(
						similarity(t.lookup, $4),
						word_similarity($4, t.lookup)
					) + 
					CASE 
						WHEN t.lookup LIKE $4 || ' %' THEN 1.0
						WHEN t.lookup LIKE $4 || '%' THEN 0.5
						ELSE 0.0
					END AS relevance_score
				FROM tokens t
				WHERE t.external_address = ANY($1)
				  AND t.lookup LIKE '%' || $4 || '%'
				ORDER BY t.lookup <-> $4
				LIMIT 250
			)
			` + selectClause + `
			` + fmt.Sprintf(fromJoinsClause, "candidates") + `
			ORDER BY t.relevance_score DESC, t.created_at DESC`
		args = append(args, kw)
		argIndex++
	} else {
		query = requestorPlatformCTE + `
			` + selectClause + `
			` + fmt.Sprintf(fromJoinsClause, "tokens") + `
			WHERE t.external_address = ANY($1)
			ORDER BY t.created_at DESC`
	}

	if keyword != "" {
		if limit > 0 {
			query += fmt.Sprintf(` LIMIT $%d`, argIndex)
			args = append(args, limit)
			argIndex++
		}
		if offset > 0 {
			query += fmt.Sprintf(` OFFSET $%d`, argIndex)
			args = append(args, offset)
		}
	}

	rows, err := storage.Select[tokenRowWithTopPlatformHolders](ctx, t.ingestedDataDB, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch community tokens with top holders")
	}

	tokenHoldersMetadata, rankingsCmds, err := t.fetchTopPlatformHoldersRankingsBatch(ctx, rows, int64(*includeTopPlatformHolders))
	if err != nil {
		return nil, err
	}

	tokens := make([]*CommunityToken, 0, len(rows))
	for _, row := range rows {
		log.Debug(fmt.Sprintf("Row data: contract=%v, position_amount_usd=%v, position_invested=%v",
			row.ContractAddress, row.PositionAmountUSD, row.PositionTotalInvestedUSD))

		topPlatformHolders, err := t.buildTopPlatformHoldersFromRankings(row, tokenHoldersMetadata, rankingsCmds)
		if err != nil {
			return nil, err
		}
		marketData := MarketData{
			Ticker:             row.Ticker,
			MarketCap:          row.MarketCapUSD,
			Volume:             row.Volume24h,
			Holders:            uint64(row.HoldersCount),
			PlatformHolders:    uint64(row.PlatformHoldersCount),
			PriceUSD:           row.PriceUSD,
			TopPlatformHolders: topPlatformHolders,
		}
		if row.PositionAmountUSD > 0 {
			externalAddress := BuildProfileExternalAddress(requestorMasterPubkey)
			position, err := t.getUserTokenPositionRanking(ctx, externalAddress, row.ExternalAddress, row.PositionAmountUSD, row.PositionTotalInvestedUSD)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to get user position ranking for token %v", row.ExternalAddress)
			}
			if position != nil {
				marketData.Position = *position
			}
		}
		tokenAddresses, err := buildAddressesFromExternalAddressAndPlatform(row.ExternalAddress, row.Platform)
		if err != nil {
			return nil, fmt.Errorf("failed to build addresses from external_address %s (platform %s): %w", row.ExternalAddress, row.Platform, err)
		}
		creatorAddresses, err := buildAddressesFromExternalAddressAndPlatform(row.CreatorExternalAddress, row.CreatorPlatform)
		if err != nil {
			return nil, fmt.Errorf("failed to build creator addresses from external_address %s (platform %s): %w", row.CreatorExternalAddress, row.CreatorPlatform, err)
		}
		token := &CommunityToken{
			Type:        row.Type,
			Title:       row.Title,
			Description: row.Description,
			ImageURL:    row.ImageURL,
			Addresses:   tokenAddresses,
			Creator: User{
				Username:  row.CreatorUsername,
				Display:   row.CreatorDisplay,
				Verified:  row.CreatorVerified,
				Avatar:    row.CreatorAvatar,
				Addresses: creatorAddresses,
			},
			MarketData: marketData,
		}
		tokens = append(tokens, token)
	}

	return tokens, nil
}

func (t *tokenAnalytics) getUserTokenPositionRanking(ctx context.Context, userExternalAddress, tokenExternalAddress string, amountUSD, totalInvested float64) (*Position, error) {
	key := keyUserPositionOfToken(tokenExternalAddress)
	balanceFloat, err := t.processedDataDB.ZScore(ctx, key, userExternalAddress).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, errors.Wrap(err, "failed to get balance from DragonflyDB")
	}
	if balanceFloat == 0 {
		return nil, nil
	}
	rank, err := t.processedDataDB.ZRevRank(ctx, key, userExternalAddress).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			rank = 0
		} else {
			return nil, errors.Wrap(err, "failed to get rank from DragonflyDB")
		}
	}
	pnl, pnlPercentage := calculatePnL(amountUSD, totalInvested)
	balanceUint64 := uint64(balanceFloat)

	return &Position{
		Rank:          uint64(rank + 1),
		Amount:        balanceUint64,
		AmountUSD:     amountUSD,
		PnL:           pnl,
		PnLPercentage: pnlPercentage,
	}, nil
}
