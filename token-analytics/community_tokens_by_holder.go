// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"

	"github.com/cockroachdb/errors"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func (t *tokenAnalytics) GetCommunityTokensByHolder(ctx context.Context, holderExternalAddress, requestorMasterPubkey string, limit, offset uint64) ([]*CommunityToken, uint64, error) {
	if holderExternalAddress == "" {
		return []*CommunityToken{}, 0, nil
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
			COALESCE(holder_user.token_holdings_count, 0) as token_holdings_count
		FROM user_token_positions utp
		INNER JOIN tokens t ON t.external_address = utp.external_address
		LEFT JOIN users holder_user ON holder_user.external_address = $1
		LEFT JOIN users creator ON LOWER(creator.content_author_id) = LOWER(t.content_author_id)
		LEFT JOIN token_volumes_24h tv ON tv.contract_address = t.contract_address
		LEFT JOIN token_platform_holders tph ON tph.external_address = t.external_address 
			AND tph.platform_group = holder_user.platform_group
		LEFT JOIN LATERAL (
			SELECT user_blockchain_address
			FROM token_swaps
			WHERE token_swaps.contract_address = t.contract_address
				AND direction = false
			ORDER BY created_at ASC
			LIMIT 1
		) first_swap ON t.platform = 'xcom'
		LEFT JOIN users launcher ON LOWER(launcher.content_author_id) = LOWER(first_swap.user_blockchain_address)
		WHERE utp.user_external_address = $1
		  AND utp.amount > '0'
		ORDER BY utp.amount DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := storage.Select[tokenRow](ctx, t.ingestedDataDB, query, holderExternalAddress, limit, offset)
	if err != nil {
		return nil, 0, errors.Wrap(err, "failed to fetch token details for holder")
	}
	var totalCount uint64
	if len(rows) > 0 {
		totalCount = rows[0].TokenHoldingsCount
	} else {
		countQuery := `SELECT COALESCE(token_holdings_count, 0) as count FROM users WHERE external_address = $1`
		countResult, countErr := storage.Get[struct{ Count uint64 }](ctx, t.ingestedDataDB, countQuery, holderExternalAddress)
		if countErr != nil && !storage.IsErr(countErr, storage.ErrNotFound) {
			return nil, 0, errors.Wrap(countErr, "failed to fetch token holdings count for holder")
		}
		if countResult != nil {
			totalCount = countResult.Count
		}
	}
	if err := t.updateBondingProgressForRows(ctx, rows); err != nil {
		return nil, 0, errors.Wrap(err, "failed to update bonding progress for rows")
	}
	tokens, err := t.buildCommunityTokensFromRows(ctx, rows, requestorMasterPubkey)
	if err != nil {
		return nil, 0, errors.Wrap(err, "failed to build community tokens from rows")
	}

	return tokens, totalCount, nil
}
