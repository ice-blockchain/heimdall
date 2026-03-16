// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"strings"
	stdlibtime "time"

	"github.com/cockroachdb/errors"

	"github.com/ice-blockchain/heimdall/token-analytics/internal/questdb"
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
			creator.master_pubkey as creator_external_address,
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
			switch *tokenType {
			case TokenTypeAnyPost:
				whereClause += ` AND t.type IN ('post', 'video', 'article')`
			case TokenTypeXcom:
				whereClause += ` AND t.platform = 'xcom'`
			case TokenTypeXcomCombined:
				whereClause += ` AND (t.platform = 'xcom' OR (t.platform = 'ionconnect' AND t.type = 'profile'))`
			case TokenTypeOnlinePlusCreator:
				whereClause += ` AND t.platform = 'ionconnect' AND t.type = 'profile'`
			case TokenTypeOnlinePlusContent:
				whereClause += ` AND t.platform = 'ionconnect' AND t.type IN ('post', 'video', 'article')`
			default:
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
			switch *tokenType {
			case TokenTypeAnyPost:
				query += ` AND t.type IN ('post', 'video', 'article')`
			case TokenTypeXcom:
				query += ` AND t.platform = 'xcom'`
			case TokenTypeXcomCombined:
				query += ` AND (t.platform = 'xcom' OR (t.platform = 'ionconnect' AND t.type = 'profile'))`
			case TokenTypeOnlinePlusCreator:
				query += ` AND t.platform = 'ionconnect' AND t.type = 'profile'`
			case TokenTypeOnlinePlusContent:
				query += ` AND t.platform = 'ionconnect' AND t.type IN ('post', 'video', 'article')`
			default:
				query += fmt.Sprintf(` AND t.type = $%d`, argIndex)
				args = append(args, *tokenType)
				argIndex++
			}
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

		creatorToken, err := buildCreatorToken(row)
		if err != nil {
			return nil, fmt.Errorf("failed to build creator token for %s: %w", row.ContractAddress, err)
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
				Token:     creatorToken,
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
			creator.master_pubkey as creator_external_address,
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
		switch *tokenType {
		case TokenTypeAnyPost:
			query += ` AND t.type IN ('post', 'video', 'article')`
		case TokenTypeXcom:
			query += ` AND t.platform = 'xcom'`
		case TokenTypeOnlinePlusCreator:
			query += ` AND t.platform = 'ionconnect' AND t.type = 'profile'`
		case TokenTypeOnlinePlusContent:
			query += ` AND t.platform = 'ionconnect' AND t.type IN ('post', 'video', 'article')`
		default:
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

		creatorToken, err := buildCreatorToken(row)
		if err != nil {
			return nil, fmt.Errorf("failed to build creator token for %s: %w", row.ContractAddress, err)
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
				Token:     creatorToken,
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
	targetHour := referenceDate.UTC().Truncate(stdlibtime.Hour)
	rankings, err := questdb.Select[hourlyTokenRanking](ctx, t.questDB,
		`SELECT
			external_address,
			volume_1h
		 FROM token_volume_1h
		 WHERE timestamp = $1 AND volume_1h > 0
		 ORDER BY volume_1h DESC
		 LIMIT $2, $2+$3`, targetHour, offset, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get hourly rankings from QuestDB for %v: %w", targetHour, err)
	}
	if len(rankings) == 0 {
		return make([]*CommunityToken, 0), nil
	}
	tokenAddresses := make([]string, 0, len(rankings))
	scoresMap := make(map[string]float64, len(rankings))
	for _, r := range rankings {
		tokenAddresses = append(tokenAddresses, r.ExternalAddress)
		scoresMap[r.ExternalAddress] = r.Volume1h
	}

	return t.getTokenDetailsWithScoresMapWithType(ctx, sessionTypeTrending, "", tokenAddresses, scoresMap)
}
