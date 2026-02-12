// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"strings"
	stdlibtime "time"

	"github.com/cockroachdb/errors"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func (t *tokenAnalytics) GetCommunityTokensByType(ctx context.Context, viewType string, tokenType *string, keyword string, limit, offset uint64) ([]*CommunityToken, error) {
	switch viewType {
	case TokenTypeLatest:
		return t.getCommunityTokensByLatest(ctx, keyword, limit, offset, tokenType)
	case TokenTypeFeatured:
		return t.getCommunityTokensByFeatured(ctx, limit, offset, tokenType)
	default:
		return nil, errors.New("unsupported view type")
	}
}

func (t *tokenAnalytics) getCommunityTokensByLatest(ctx context.Context, keyword string, limit, offset uint64, tokenType *string) ([]*CommunityToken, error) {
	var query string
	args := []interface{}{}
	argIndex := 1

	const (
		selectClause = `SELECT 
			t.contract_address,
			t.external_address,
			t.platform as platform,
			t.type,
			t.created_at,
			COALESCE(t.title, '') as title,
			COALESCE(t.description, '') as description,
			COALESCE(t.image_url, '') as image_url,
			t.ticker,
			t.total_supply,
			t.content_author_id as content_author_id,
			t.ion_connect_address,
			creator.username as creator_username,
			creator.display_name as creator_display,
			creator.verified as creator_verified,
			creator.avatar as creator_avatar,
			creator.external_address as creator_external_address,
			creator.platform_group as creator_platform,
			t.content_author_id as creator_bnb_bsc_address,
			COALESCE(t.market_cap_usd, 0) as market_cap_usd,
			COALESCE(t.price_usd, 0) as price_usd,
			COALESCE(tv.volume_24h / 1e18, 0) as volume_24h,
			COALESCE(t.holders_count, 0) as holders_count,
			COALESCE(t.bonding_curve_current_amount, '0') as bonding_curve_current_amount,
			COALESCE(t.bonding_curve_goal_amount, '0') as bonding_curve_goal_amount,
			COALESCE(t.bonding_curve_current_amount_usd, 0) as bonding_curve_current_amount_usd,
			COALESCE(t.bonding_curve_goal_amount_usd, 0) as bonding_curve_goal_amount_usd,
			creator_token.ticker as creator_token_ticker,
			creator_token.title as creator_token_title,
			creator_token.description as creator_token_description,
			creator_token.image_url as creator_token_image_url,
			creator_token.created_at as creator_token_created_at,
			creator_token.contract_address as creator_token_contract_address,
			creator_token.external_address as creator_token_external_address,
			creator_token.platform as creator_token_platform,
			creator_token.ion_connect_address as creator_token_ion_connect_address`

		fromJoinsClause = `FROM %s t
	LEFT JOIN user_bsc_addresses creator_addr ON creator_addr.bsc_address = t.content_author_id
	LEFT JOIN users creator ON creator.id = creator_addr.user_id
	LEFT JOIN token_volumes_24h tv ON tv.contract_address = t.contract_address
	LEFT JOIN tokens creator_token ON creator_token.contract_address = t.base_token AND creator_token.type = 'profile'`
	)

	if keyword != "" {
		kw := strings.ToLower(keyword)
		whereClause := "WHERE t.ticker IS NOT NULL"
		if tokenType != nil && *tokenType != "" {
			if *tokenType == TokenTypeAnyPost {
				whereClause += ` AND t.type IN ('post', 'video', 'article')`
			} else {
				whereClause += fmt.Sprintf(` AND t.type = $%d`, argIndex)
				args = append(args, *tokenType)
				argIndex++
			}
		}
		whereClause += fmt.Sprintf(` AND t.lookup LIKE '%%' || $%d || '%%'`, argIndex)
		keywordArgIndex := argIndex
		args = append(args, kw)
		argIndex++

		query = fmt.Sprintf(`
			WITH candidates AS (
				SELECT 
					t.contract_address,
					t.external_address,
					t.platform,
					t.type,
					t.created_at,
					t.ticker,
					t.total_supply,
				t.content_author_id,
				t.ion_connect_address,
				t.base_token,
				t.market_cap_usd,
					t.price_usd,
					t.holders_count,
					t.bonding_curve_current_amount,
					t.bonding_curve_goal_amount,
					t.bonding_curve_current_amount_usd,
					t.bonding_curve_goal_amount_usd,
					COALESCE(t.title, '') as title,
					COALESCE(t.description, '') as description,
					COALESCE(t.image_url, '') as image_url,
					GREATEST(
						similarity(t.lookup, $%d),
						word_similarity($%d, t.lookup)
					) + 
					CASE 
						WHEN t.lookup LIKE $%d || ' %%' THEN 1.0
						WHEN t.lookup LIKE $%d || '%%' THEN 0.5
						ELSE 0.0
					END AS relevance_score
				FROM tokens t
				%s
				ORDER BY t.lookup <-> $%d
				LIMIT 250
			)
			%s
			`+fromJoinsClause+`
			ORDER BY t.relevance_score DESC, t.created_at DESC
			LIMIT $%d OFFSET $%d`,
			keywordArgIndex, keywordArgIndex, keywordArgIndex, keywordArgIndex, whereClause, keywordArgIndex,
			selectClause, "candidates", argIndex, argIndex+1)
		args = append(args, limit, offset)
	} else {
		query = selectClause + `
		` + fmt.Sprintf(fromJoinsClause, "tokens") + `
		WHERE t.ticker IS NOT NULL`

		if tokenType != nil && *tokenType != "" {
			query += fmt.Sprintf(` AND t.type = $%d`, argIndex)
			args = append(args, *tokenType)
			argIndex++
		}
		query += " ORDER BY t.created_at DESC"
		query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIndex, argIndex+1)
		args = append(args, limit, offset)
	}
	rows, err := storage.Select[tokenRow](ctx, t.ingestedDataDB, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch community tokens by type")
	}

	tokens := make([]*CommunityToken, 0, len(rows))
	for _, row := range rows {
		tokenAddresses, creatorAddresses, err := buildTokenAndCreatorAddresses(TokenAndCreatorAddressesParams{
			TokenContractAddress:   row.ContractAddress,
			TokenExternalAddress:   row.ExternalAddress,
			TokenPlatform:          row.Platform,
			TokenIonConnectAddress: row.IonConnectAddress,
			CreatorExternalAddress: strVal(row.CreatorExternalAddress),
			CreatorPlatform:        strVal(row.CreatorPlatform),
			CreatorBnbBscAddress:   row.CreatorBnbBscAddress,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to build token and creator addresses: %w", err)
		}

		var bondingCurveProgress *BondingCurveProgress
		if row.BondingCurveCurrentAmount != "" && row.BondingCurveCurrentAmount != "0" && row.BondingCurveGoalAmount != "" && row.BondingCurveGoalAmount != "0" {
			bondingCurveProgress = &BondingCurveProgress{
				CurrentAmount:    row.BondingCurveCurrentAmount,
				GoalAmount:       row.BondingCurveGoalAmount,
				CurrentAmountUSD: row.BondingCurveCurrentAmountUSD,
				GoalAmountUSD:    row.BondingCurveGoalAmountUSD,
			}
		}

		token := &CommunityToken{
			Type:        row.Type,
			Title:       row.Title,
			Description: row.Description,
			ImageURL:    row.ImageURL,
			CreatedAt:   row.CreatedAt,
			Addresses:   tokenAddresses,
			Creator: User{
				Username:  row.CreatorUsername,
				Display:   row.CreatorDisplay,
				Verified:  row.CreatorVerified,
				Avatar:    row.CreatorAvatar,
				Addresses: creatorAddresses,
				Token:     buildCreatorToken(row),
			},
			MarketData: MarketData{
				Ticker:               row.Ticker,
				MarketCap:            row.MarketCapUSD,
				Volume:               row.Volume24h,
				Holders:              uint64(row.HoldersCount),
				PriceUSD:             row.PriceUSD,
				BondingCurveProgress: bondingCurveProgress,
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
			t.platform,
			t.type,
			t.created_at,
			COALESCE(t.title, '') as title,
			COALESCE(t.description, '') as description,
			COALESCE(t.image_url, '') as image_url,
			t.ticker,
			t.total_supply,
			t.content_author_id as content_author_id,
			t.ion_connect_address,
			creator.username as creator_username,
			creator.display_name as creator_display,
			creator.verified as creator_verified,
			creator.avatar as creator_avatar,
			creator.external_address as creator_external_address,
			creator.platform_group as creator_platform,
			t.content_author_id as creator_bnb_bsc_address,
			COALESCE(t.market_cap_usd, 0) as market_cap_usd,
			COALESCE(t.price_usd, 0) as price_usd,
			COALESCE(tv.volume_24h / 1e18, 0) as volume_24h,
			COALESCE(t.holders_count, 0) as holders_count,
			COALESCE(t.bonding_curve_current_amount, '0') as bonding_curve_current_amount,
			COALESCE(t.bonding_curve_goal_amount, '0') as bonding_curve_goal_amount,
			COALESCE(t.bonding_curve_current_amount_usd, 0) as bonding_curve_current_amount_usd,
			COALESCE(t.bonding_curve_goal_amount_usd, 0) as bonding_curve_goal_amount_usd,
			creator_token.ticker as creator_token_ticker,
			creator_token.title as creator_token_title,
			creator_token.description as creator_token_description,
			creator_token.image_url as creator_token_image_url,
			creator_token.created_at as creator_token_created_at,
			creator_token.contract_address as creator_token_contract_address,
			creator_token.external_address as creator_token_external_address,
			creator_token.platform as creator_token_platform,
			creator_token.ion_connect_address as creator_token_ion_connect_address
	FROM tokens t
	INNER JOIN tokens_featured tf ON tf.external_address = t.external_address
	LEFT JOIN user_bsc_addresses creator_addr ON creator_addr.bsc_address = t.content_author_id
	LEFT JOIN users creator ON creator.id = creator_addr.user_id
	LEFT JOIN token_volumes_24h tv ON tv.contract_address = t.contract_address
	LEFT JOIN tokens creator_token ON creator_token.contract_address = t.base_token AND creator_token.type = 'profile'
	WHERE t.ticker IS NOT NULL
	`

	args := []interface{}{}
	argIndex := 1

	if tokenType != nil && *tokenType != "" {
		if *tokenType == TokenTypeAnyPost {
			query += ` AND t.type IN ('post', 'video', 'article')`
		} else {
			query += fmt.Sprintf(` AND t.type = $%d`, argIndex)
			args = append(args, *tokenType)
			argIndex++
		}
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
		tokenAddresses, creatorAddresses, err := buildTokenAndCreatorAddresses(TokenAndCreatorAddressesParams{
			TokenContractAddress:   row.ContractAddress,
			TokenExternalAddress:   row.ExternalAddress,
			TokenPlatform:          row.Platform,
			TokenIonConnectAddress: row.IonConnectAddress,
			CreatorExternalAddress: strVal(row.CreatorExternalAddress),
			CreatorPlatform:        strVal(row.CreatorPlatform),
			CreatorBnbBscAddress:   row.CreatorBnbBscAddress,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to build token and creator addresses: %w", err)
		}

		var bondingCurveProgress *BondingCurveProgress
		if row.BondingCurveCurrentAmount != "" && row.BondingCurveCurrentAmount != "0" && row.BondingCurveGoalAmount != "" && row.BondingCurveGoalAmount != "0" {
			bondingCurveProgress = &BondingCurveProgress{
				CurrentAmount:    row.BondingCurveCurrentAmount,
				GoalAmount:       row.BondingCurveGoalAmount,
				CurrentAmountUSD: row.BondingCurveCurrentAmountUSD,
				GoalAmountUSD:    row.BondingCurveGoalAmountUSD,
			}
		}

		token := &CommunityToken{
			Type:        row.Type,
			Title:       row.Title,
			Description: row.Description,
			ImageURL:    row.ImageURL,
			CreatedAt:   row.CreatedAt,
			Addresses:   tokenAddresses,
			Creator: User{
				Username:  row.CreatorUsername,
				Display:   row.CreatorDisplay,
				Verified:  row.CreatorVerified,
				Avatar:    row.CreatorAvatar,
				Addresses: creatorAddresses,
				Token:     buildCreatorToken(row),
			},
			MarketData: MarketData{
				Ticker:               row.Ticker,
				MarketCap:            row.MarketCapUSD,
				Supply:               row.TotalSupply,
				Volume:               row.Volume24h,
				Holders:              uint64(row.HoldersCount),
				PriceUSD:             row.PriceUSD,
				BondingCurveProgress: bondingCurveProgress,
			},
		}
		tokens = append(tokens, token)
	}

	return tokens, nil
}

func (t *tokenAnalytics) GetCommunityTokensByRewardsDistribution(ctx context.Context, referenceDate stdlibtime.Time, limit, offset uint64) ([]*CommunityToken, error) {
	_ = referenceDate.Truncate(stdlibtime.Hour)
	if limit == 0 {
		limit = 100
	}
	if limit > 100 {
		limit = 100
	}

	tokenData, err := t.processedDataDB.ZRevRangeWithScores(ctx, globalTrendingSetKey, int64(offset), int64(offset+limit-1)).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get trending tokens from Redis: %w", err)
	}
	if len(tokenData) == 0 {
		return make([]*CommunityToken, 0), nil
	}

	tokenAddresses := make([]string, len(tokenData))
	scoresMap := make(map[string]float64, len(tokenData))
	for i, z := range tokenData {
		addr := z.Member.(string)
		tokenAddresses[i] = addr
		scoresMap[addr] = z.Score
	}

	return t.getTokenDetailsWithScoresMapWithType(ctx, sessionTypeTrending, "", tokenAddresses, scoresMap)
}
