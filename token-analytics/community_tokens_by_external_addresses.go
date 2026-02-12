// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/redis/go-redis/v9"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) GetCommunityTokensByExternalAddresses(ctx context.Context, externalAddresses []string, requestorMasterPubkey string, includeTopPlatformHolders *uint32, keyword string, limit, offset uint64) ([]*CommunityToken, error) {
	if keyword != "" {
		return t.searchCommunityTokens(ctx, externalAddresses, requestorMasterPubkey, keyword, limit, offset)
	}
	if len(externalAddresses) == 0 {
		return []*CommunityToken{}, nil
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
			COALESCE(t.title, '') as title,
			COALESCE(t.description, '') as description,
			COALESCE(t.image_url, '') as image_url,
			t.ticker,
			COALESCE(t.total_supply, '0') as total_supply,
			t.created_at,
			t.content_author_id,
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
			t.liquidity_usd,
			COALESCE(t.base_token, '') as base_token,
			COALESCE(t.price_model, '') as price_model,
			COALESCE(t.pair_id, '') as pair_id,
			COALESCE(tv.volume_24h / 1e18, 0) as volume_24h,
			COALESCE(t.holders_count, 0) as holders_count,
			COALESCE(tph.holders_count, 0) as platform_holders_count,
			COALESCE(t.bonding_curve_current_amount, '0') as bonding_curve_current_amount,
			COALESCE(t.bonding_curve_goal_amount, '0') as bonding_curve_goal_amount,
			COALESCE(t.bonding_curve_current_amount_usd, 0) as bonding_curve_current_amount_usd,
			COALESCE(t.bonding_curve_goal_amount_usd, 0) as bonding_curve_goal_amount_usd,
			COALESCE(t.bonding_curve_migrated, FALSE) as bonding_curve_migrated,
			COALESCE(t.bonding_curve_raised_amount, 0) as bonding_curve_raised_amount,
			COALESCE(utp.amount, '0') as position_amount,
			COALESCE((utp.amount::NUMERIC / 1e18) * t.price_usd, 0) as position_amount_usd,
			COALESCE(utp.total_invested_usd, 0) as position_total_invested_usd,
			COALESCE(utp.total_realized_usd, 0) as position_total_realized_usd,
			launcher.username as launcher_username,
			launcher.display_name as launcher_display,
			launcher.verified as launcher_verified,
			launcher.avatar as launcher_avatar,
			launcher.external_address as launcher_external_address,
			launcher.platform_group as launcher_platform,
			first_swap.user_blockchain_address as launcher_blockchain_address,
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
		LEFT JOIN user_bsc_addresses creator_addr ON creator_addr.bsc_address = t.content_author_id
		LEFT JOIN users creator ON creator.id = creator_addr.user_id
		LEFT JOIN user_token_positions utp ON utp.external_address = t.external_address AND utp.user_blockchain_address = (SELECT uba.bsc_address FROM user_bsc_addresses uba JOIN users u ON u.id = uba.user_id WHERE u.master_pubkey = $2 LIMIT 1)
		LEFT JOIN token_volumes_24h tv ON tv.contract_address = t.contract_address
		LEFT JOIN token_platform_holders tph ON tph.external_address = t.external_address 
			AND tph.platform_group = (SELECT platform_group FROM users WHERE master_pubkey = $2 LIMIT 1)
		LEFT JOIN LATERAL (
			SELECT user_blockchain_address
			FROM token_swaps
			WHERE token_swaps.contract_address = t.contract_address
				AND direction = false
			ORDER BY created_at ASC
			LIMIT 1
		) first_swap ON t.platform = 'xcom'
		LEFT JOIN user_bsc_addresses launcher_addr ON launcher_addr.bsc_address = first_swap.user_blockchain_address
		LEFT JOIN users launcher ON launcher.id = launcher_addr.user_id
		LEFT JOIN tokens creator_token ON creator_token.contract_address = t.base_token AND creator_token.type = 'profile'
		WHERE t.external_address = ANY($1)
		  AND t.ticker IS NOT NULL
		ORDER BY t.created_at DESC
	`
	rows, err := storage.Select[tokenRow](ctx, t.ingestedDataDB, query, externalAddresses, requestorMasterPubkey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch community tokens")
	}
	requestorExternalAddress := BuildProfileExternalAddress(requestorMasterPubkey)

	return t.buildCommunityTokensFromRows(ctx, rows, requestorExternalAddress)
}

func (t *tokenAnalytics) searchCommunityTokens(ctx context.Context, externalAddresses []string, requestorMasterPubkey string, keyword string, limit, offset uint64) ([]*CommunityToken, error) {
	kw := strings.ToLower(keyword)
	var whereClause string
	args := []interface{}{}
	argIndex := 1

	if len(externalAddresses) > 0 {
		whereClause = `WHERE t.external_address = ANY($` + strconv.Itoa(argIndex) + `) AND t.lookup LIKE '%%' || $` + strconv.Itoa(argIndex+1) + ` || '%%' AND t.ticker IS NOT NULL`
		args = append(args, externalAddresses, kw)
		argIndex += 2
	} else {
		whereClause = `WHERE t.lookup LIKE '%%' || $` + strconv.Itoa(argIndex) + ` || '%%' AND t.ticker IS NOT NULL`
		args = append(args, kw)
		argIndex++
	}

	kwParam := strconv.Itoa(argIndex - 1)
	query := `
		WITH candidates AS (
			SELECT 
				t.contract_address,
				t.external_address,
				t.platform as platform,
				t.type,
				t.ticker,
				t.created_at,
				t.content_author_id,
				t.ion_connect_address,
				t.market_cap_usd,
				t.price_usd,
				t.liquidity_usd,
				t.holders_count,
				t.total_supply,
				COALESCE(t.bonding_curve_current_amount, '0') as bonding_curve_current_amount,
				COALESCE(t.bonding_curve_goal_amount, '0') as bonding_curve_goal_amount,
				COALESCE(t.bonding_curve_current_amount_usd, 0) as bonding_curve_current_amount_usd,
				COALESCE(t.bonding_curve_goal_amount_usd, 0) as bonding_curve_goal_amount_usd,
				COALESCE(t.title, '') as title,
				COALESCE(t.description, '') as description,
				COALESCE(t.image_url, '') as image_url,
				tv.volume_24h,
				creator.username as creator_username,
				creator.display_name as creator_display,
				creator.verified as creator_verified,
				creator.avatar as creator_avatar,
				creator.external_address as creator_external_address,
				creator.platform_group as creator_platform,
				t.content_author_id as creator_bnb_bsc_address,
				launcher.username as launcher_username,
				launcher.display_name as launcher_display,
				launcher.verified as launcher_verified,
				launcher.avatar as launcher_avatar,
				launcher.external_address as launcher_external_address,
				launcher.platform_group as launcher_platform,
				first_swap.user_blockchain_address as launcher_blockchain_address,
				creator_token.ticker as creator_token_ticker,
				creator_token.title as creator_token_title,
				creator_token.description as creator_token_description,
				creator_token.image_url as creator_token_image_url,
				creator_token.created_at as creator_token_created_at,
				creator_token.contract_address as creator_token_contract_address,
				creator_token.external_address as creator_token_external_address,
				creator_token.platform as creator_token_platform,
				creator_token.ion_connect_address as creator_token_ion_connect_address,
				GREATEST(
					similarity(t.lookup, $` + kwParam + `),
					word_similarity($` + kwParam + `, t.lookup)
				) + 
				CASE 
					WHEN t.lookup LIKE $` + kwParam + ` || ' %' THEN 1.0
					WHEN t.lookup LIKE $` + kwParam + ` || '%' THEN 0.5
					ELSE 0.0
				END AS relevance_score
			FROM tokens t
			LEFT JOIN user_bsc_addresses creator_addr ON creator_addr.bsc_address = t.content_author_id
			LEFT JOIN users creator ON creator.id = creator_addr.user_id
			LEFT JOIN token_volumes_24h tv ON tv.contract_address = t.contract_address
			LEFT JOIN LATERAL (
				SELECT user_blockchain_address
				FROM token_swaps
				WHERE token_swaps.contract_address = t.contract_address
					AND direction = false
				ORDER BY created_at ASC
				LIMIT 1
			) first_swap ON t.platform = 'xcom'
			LEFT JOIN user_bsc_addresses launcher_addr ON launcher_addr.bsc_address = first_swap.user_blockchain_address
			LEFT JOIN users launcher ON launcher.id = launcher_addr.user_id
			LEFT JOIN tokens creator_token ON creator_token.contract_address = t.base_token AND creator_token.type = 'profile'
			` + whereClause + `
			ORDER BY t.lookup <-> $` + kwParam + `
			LIMIT 250
		)
		SELECT 
			contract_address,
			external_address,
			platform,
			type,
			ticker,
			title,
			description,
			image_url,
			created_at,
			content_author_id as content_author_id,
			ion_connect_address,
			creator_username,
			creator_display,
			creator_verified,
			creator_avatar,
			creator_external_address,
			creator_platform,
			creator_bnb_bsc_address,
			launcher_username,
			launcher_display,
			launcher_verified,
			launcher_avatar,
			launcher_external_address,
			launcher_platform,
			launcher_blockchain_address,
			COALESCE(market_cap_usd, 0) as market_cap_usd,
			COALESCE(price_usd, 0) as price_usd,
			liquidity_usd,
			COALESCE(volume_24h / 1e18, 0) as volume_24h,
			COALESCE(total_supply, '0') as total_supply,
			COALESCE(holders_count, 0) as holders_count,
			bonding_curve_current_amount,
			bonding_curve_goal_amount,
			bonding_curve_current_amount_usd,
			bonding_curve_goal_amount_usd,
			creator_token_ticker,
			creator_token_title,
			creator_token_description,
			creator_token_image_url,
			creator_token_created_at,
			creator_token_contract_address,
			creator_token_external_address,
			creator_token_platform,
			creator_token_ion_connect_address
		FROM candidates
		ORDER BY relevance_score DESC, volume_24h DESC, created_at DESC`

	if limit > 0 {
		query += ` LIMIT $` + strconv.Itoa(argIndex)
		args = append(args, limit)
		argIndex++
	}
	if offset > 0 {
		query += ` OFFSET $` + strconv.Itoa(argIndex)
		args = append(args, offset)
	}

	rows, err := storage.Select[tokenRow](ctx, t.ingestedDataDB, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to search community tokens")
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
		if row.BondingCurveCurrentAmount != "" && row.BondingCurveCurrentAmount != "0" &&
			row.BondingCurveGoalAmount != "" && row.BondingCurveGoalAmount != "0" {
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
				LiquidityUSD:         row.LiquidityUSD,
				BondingCurveProgress: bondingCurveProgress,
			},
		}
		tokens = append(tokens, token)
	}

	return tokens, nil
}

func (t *tokenAnalytics) buildCommunityTokensFromRows(ctx context.Context, rows []*tokenRow, positionHolderExternalAddress string) ([]*CommunityToken, error) {
	tokens := make([]*CommunityToken, 0, len(rows))
	for _, row := range rows {
		var bondingCurveProgress *BondingCurveProgress
		if row.BondingCurveCurrentAmount != "" && row.BondingCurveCurrentAmount != "0" && row.BondingCurveGoalAmount != "" && row.BondingCurveGoalAmount != "0" {
			bondingCurveProgress = &BondingCurveProgress{
				CurrentAmount:    row.BondingCurveCurrentAmount,
				GoalAmount:       row.BondingCurveGoalAmount,
				CurrentAmountUSD: row.BondingCurveCurrentAmountUSD,
				GoalAmountUSD:    row.BondingCurveGoalAmountUSD,
				RaisedAmount:     row.BondingCurveRaisedAmount,
				Migrated:         row.BondingCurveMigrated,
			}
		}

		marketData := MarketData{
			Ticker:               row.Ticker,
			MarketCap:            row.MarketCapUSD,
			Supply:               row.TotalSupply,
			Volume:               row.Volume24h,
			Holders:              uint64(row.HoldersCount),
			PlatformHolders:      uint64(row.PlatformHoldersCount),
			PriceUSD:             row.PriceUSD,
			LiquidityUSD:         row.LiquidityUSD,
			BondingCurveProgress: bondingCurveProgress,
		}

		if row.PositionAmount != "" && row.PositionAmount != "0" && positionHolderExternalAddress != "" {
			position, err := t.getUserTokenPositionRanking(ctx, positionHolderExternalAddress, row.ExternalAddress, row.PositionAmount, row.PositionAmountUSD, row.PositionTotalInvestedUSD, row.PositionTotalRealizedUSD)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to get user position ranking for token %v", row.ExternalAddress)
			}
			if position != nil {
				marketData.Position = position
			}
		}
		tokenAddresses, err := buildTokenAddressesFromContractAndExternalAddress(row.ContractAddress, row.ExternalAddress, row.Platform, strVal(row.IonConnectAddress))
		if err != nil {
			return nil, fmt.Errorf("failed to build token addresses from contract_address %s, external_address %s (platform %s): %w", row.ContractAddress, row.ExternalAddress, row.Platform, err)
		}
		var ionConnectPubkey string
		if row.IonConnectAddress != nil && strVal(row.IonConnectAddress) != "" && row.Platform == PlatformGroupXCom {
			ionConnectPubkey = extractIonConnectFromTokenExternalAddress(strVal(row.IonConnectAddress), row.Platform)
		}
		creatorAddresses, err := buildUserAddressesFromExternalAddressAndPlatform(strVal(row.CreatorExternalAddress), strVal(row.CreatorPlatform), strVal(row.CreatorBnbBscAddress), ionConnectPubkey)
		if err != nil {
			return nil, fmt.Errorf("failed to build creator addresses from external_address %s (platform %s): %w", strVal(row.CreatorExternalAddress), strVal(row.CreatorPlatform), err)
		}
		var launcher *User
		if row.Platform == PlatformGroupXCom && row.LauncherBlockchainAddress != nil && strVal(row.LauncherBlockchainAddress) != "" {
			launcherPlatform := strVal(row.LauncherPlatform)
			if launcherPlatform == "" {
				launcherPlatform = row.Platform
			}
			launcherAddresses, err := buildAddressesFromExternalAddressAndPlatform(
				strVal(row.LauncherExternalAddress),
				launcherPlatform,
				strVal(row.LauncherBlockchainAddress),
				"",
			)
			if err != nil {
				return nil, fmt.Errorf("failed to build launcher addresses from external_address %s (platform %s): %w", strVal(row.LauncherExternalAddress), launcherPlatform, err)
			}

			launcher = &User{
				Username:  row.LauncherUsername,
				Display:   row.LauncherDisplay,
				Verified:  row.LauncherVerified,
				Avatar:    row.LauncherAvatar,
				Addresses: launcherAddresses,
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
			Launcher:   launcher,
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
				COALESCE(t.title, '') as title,
				COALESCE(t.description, '') as description,
				COALESCE(t.image_url, '') as image_url,
				t.ticker,
				COALESCE(t.total_supply, '0') as total_supply,
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
				t.liquidity_usd as liquidity_usd,
				COALESCE(tv.volume_24h / 1e18, 0) as volume_24h,
				COALESCE(t.holders_count, 0) as holders_count,
				COALESCE(tph.holders_count, 0) as platform_holders_count,
				COALESCE(t.bonding_curve_current_amount, '0') as bonding_curve_current_amount,
				COALESCE(t.bonding_curve_goal_amount, '0') as bonding_curve_goal_amount,
				COALESCE(t.bonding_curve_current_amount_usd, 0) as bonding_curve_current_amount_usd,
				COALESCE(t.bonding_curve_goal_amount_usd, 0) as bonding_curve_goal_amount_usd,
				COALESCE(utp.amount, '0') as position_amount,
				COALESCE((utp.amount::NUMERIC / 1e18) * t.price_usd, 0) as position_amount_usd,
				COALESCE(utp.total_invested_usd, 0) as position_total_invested_usd,
				COALESCE(utp.total_realized_usd, 0) as position_total_realized_usd,
				launcher.username as launcher_username,
				launcher.display_name as launcher_display,
				launcher.verified as launcher_verified,
				launcher.avatar as launcher_avatar,
				launcher.external_address as launcher_external_address,
				launcher.platform_group as launcher_platform,
				first_swap.user_blockchain_address as launcher_blockchain_address,
				creator_token.ticker as creator_token_ticker,
				creator_token.title as creator_token_title,
				creator_token.description as creator_token_description,
				creator_token.image_url as creator_token_image_url,
				creator_token.created_at as creator_token_created_at,
				creator_token.contract_address as creator_token_contract_address,
				creator_token.external_address as creator_token_external_address,
				creator_token.platform as creator_token_platform,
				creator_token.ion_connect_address as creator_token_ion_connect_address,
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
							holder.username as holder_username,
							holder.display_name as holder_display,
							holder.verified as holder_verified,
							holder.avatar as holder_avatar,
							holder.external_address as holder_external_address,
							holder.platform_group as holder_platform,
							utp_holders.amount as amount
						FROM user_token_positions utp_holders
						LEFT JOIN user_bsc_addresses holder_addr ON holder_addr.bsc_address = utp_holders.user_blockchain_address
						LEFT JOIN users holder ON holder.id = holder_addr.user_id
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
			LEFT JOIN user_bsc_addresses creator_addr ON creator_addr.bsc_address = t.content_author_id
			LEFT JOIN users creator ON creator.id = creator_addr.user_id
			LEFT JOIN user_token_positions utp ON utp.external_address = t.external_address AND utp.user_blockchain_address = (SELECT uba.bsc_address FROM user_bsc_addresses uba JOIN users u ON u.id = uba.user_id WHERE u.master_pubkey = $2 LIMIT 1)
			LEFT JOIN token_volumes_24h tv ON tv.contract_address = t.contract_address
			LEFT JOIN token_platform_holders tph ON tph.external_address = t.external_address
				AND (rp.platform_group IS NULL OR tph.platform_group = rp.platform_group)
			LEFT JOIN LATERAL (
				SELECT user_blockchain_address
				FROM token_swaps
				WHERE token_swaps.contract_address = t.contract_address
					AND direction = false
				ORDER BY created_at ASC
				LIMIT 1
			) first_swap ON t.platform = 'xcom'
			LEFT JOIN user_bsc_addresses launcher_addr ON launcher_addr.bsc_address = first_swap.user_blockchain_address
			LEFT JOIN users launcher ON launcher.id = launcher_addr.user_id
			LEFT JOIN tokens creator_token ON creator_token.contract_address = t.base_token AND creator_token.type = 'profile'`
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
					t.content_author_id,
					t.ion_connect_address,
					t.title,
					t.description,
					t.image_url,
					t.market_cap_usd,
					t.price_usd,
					t.liquidity_usd,
					t.holders_count,
					t.bonding_curve_current_amount,
					t.bonding_curve_goal_amount,
					t.bonding_curve_current_amount_usd,
					t.bonding_curve_goal_amount_usd,
					t.created_at,
					t.base_token,
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
				  AND t.ticker IS NOT NULL
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
			  AND t.ticker IS NOT NULL
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

		var bondingCurveProgress *BondingCurveProgress
		if row.BondingCurveCurrentAmount != "" && row.BondingCurveCurrentAmount != "0" && row.BondingCurveGoalAmount != "" && row.BondingCurveGoalAmount != "0" {
			bondingCurveProgress = &BondingCurveProgress{
				CurrentAmount:    row.BondingCurveCurrentAmount,
				GoalAmount:       row.BondingCurveGoalAmount,
				CurrentAmountUSD: row.BondingCurveCurrentAmountUSD,
				GoalAmountUSD:    row.BondingCurveGoalAmountUSD,
			}
		}

		marketData := MarketData{
			Ticker:               row.Ticker,
			MarketCap:            row.MarketCapUSD,
			Supply:               row.TotalSupply,
			Volume:               row.Volume24h,
			Holders:              uint64(row.HoldersCount),
			PlatformHolders:      uint64(row.PlatformHoldersCount),
			PriceUSD:             row.PriceUSD,
			LiquidityUSD:         row.LiquidityUSD,
			TopPlatformHolders:   topPlatformHolders,
			BondingCurveProgress: bondingCurveProgress,
		}
		if row.PositionAmount != "" && row.PositionAmount != "0" {
			externalAddress := BuildProfileExternalAddress(requestorMasterPubkey)
			position, err := t.getUserTokenPositionRanking(ctx, externalAddress, row.ExternalAddress, row.PositionAmount, row.PositionAmountUSD, row.PositionTotalInvestedUSD, row.PositionTotalRealizedUSD)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to get user position ranking for token %v", row.ExternalAddress)
			}
			if position != nil {
				marketData.Position = position
			}
		}
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
			},
			MarketData: marketData,
		}
		tokens = append(tokens, token)
	}

	return tokens, nil
}

func (t *tokenAnalytics) getUserTokenPositionRanking(ctx context.Context, userExternalAddress, tokenExternalAddress, amountWei string, amountUSD, totalInvested, totalRealized float64) (*Position, error) {
	key := keyUserPositionOfToken(tokenExternalAddress)
	balanceFloat, err := t.processedDataDB.ZScore(ctx, key, userExternalAddress).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			log.Debug(fmt.Sprintf("Redis returned Nil for key=%s, member=%s, amountWei=%s", key, userExternalAddress, amountWei))

			return nil, nil
		}
		return nil, errors.Wrap(err, "failed to get balance from DragonflyDB")
	}
	if balanceFloat == 0 {
		log.Debug(fmt.Sprintf("Balance for user %s on token %s is 0, returning nil, amountWei=%s", userExternalAddress, tokenExternalAddress, amountWei))

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
	pnl, pnlPercentage := calculatePnL(amountUSD, totalInvested, totalRealized)

	return &Position{
		Rank:          uint64(rank + 1),
		Amount:        amountWei,
		AmountUSD:     amountUSD,
		PnL:           pnl,
		PnLPercentage: pnlPercentage,
	}, nil
}
