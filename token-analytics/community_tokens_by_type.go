// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"strings"

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
		return nil, errors.New("unsupported token type")
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
			COALESCE(t.holders_count, 0) as holders_count`

		fromJoinsClause = `FROM %s t
		LEFT JOIN users creator ON LOWER(creator.content_author_id) = LOWER(t.content_author_id)
		LEFT JOIN token_volumes_24h tv ON tv.contract_address = t.contract_address`
	)

	if keyword != "" {
		kw := strings.ToLower(keyword)
		whereClause := "WHERE 1=1"
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
					t.market_cap_usd,
					t.price_usd,
					t.holders_count,
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
		WHERE 1=1`

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
		tokenAddresses, err := buildAddressesFromExternalAddressAndPlatform(row.ExternalAddress, row.Platform, "")
		if err != nil {
			return nil, fmt.Errorf("failed to build addresses from external_address %s (platform %s): %w", row.ExternalAddress, row.Platform, err)
		}
		creatorAddresses, err := buildAddressesFromExternalAddressAndPlatform(strVal(row.CreatorExternalAddress), strVal(row.CreatorPlatform), strVal(row.CreatorBnbBscAddress), strVal(row.IonConnectAddress))
		if err != nil {
			return nil, fmt.Errorf("failed to build creator addresses from external_address %s (platform %s): %w", strVal(row.CreatorExternalAddress), strVal(row.CreatorPlatform), err)
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
			COALESCE(t.holders_count, 0) as holders_count
		FROM tokens t
		INNER JOIN tokens_featured tf ON tf.external_address = t.external_address
		LEFT JOIN users creator ON LOWER(creator.content_author_id) = LOWER(t.content_author_id)
		LEFT JOIN token_volumes_24h tv ON tv.contract_address = t.contract_address
	`

	args := []interface{}{}
	argIndex := 1

	if tokenType != nil && *tokenType != "" {
		if *tokenType == TokenTypeAnyPost {
			query += ` WHERE t.type IN ('post', 'video', 'article')`
		} else {
			query += fmt.Sprintf(` WHERE t.type = $%d`, argIndex)
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
		tokenAddresses, err := buildTokenAddressesFromContractAndExternalAddress(row.ContractAddress, row.ExternalAddress, row.Platform, strVal(row.IonConnectAddress))
		if err != nil {
			return nil, fmt.Errorf("failed to build addresses from external_address %s (platform %s): %w", row.ExternalAddress, row.Platform, err)
		}
		var ionConnectPubkey string
		if row.IonConnectAddress != nil && strVal(row.IonConnectAddress) != "" && row.Platform == PlatformGroupXCom {
			ionConnectPubkey = extractIonConnectFromTokenExternalAddress(strVal(row.IonConnectAddress), row.Platform)
		}
		creatorAddresses, err := buildAddressesFromExternalAddressAndPlatform(strVal(row.CreatorExternalAddress), strVal(row.CreatorPlatform), strVal(row.CreatorBnbBscAddress), ionConnectPubkey)
		if err != nil {
			return nil, fmt.Errorf("failed to build creator addresses from external_address %s (platform %s): %w", strVal(row.CreatorExternalAddress), strVal(row.CreatorPlatform), err)
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
			MarketData: MarketData{
				Ticker:    row.Ticker,
				MarketCap: row.MarketCapUSD,
				Supply:    row.TotalSupply,
				Volume:    row.Volume24h,
				Holders:   uint64(row.HoldersCount),
				PriceUSD:  row.PriceUSD,
			},
		}
		tokens = append(tokens, token)
	}

	return tokens, nil
}
