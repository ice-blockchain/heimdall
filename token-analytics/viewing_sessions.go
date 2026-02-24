// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) CreateViewingSession(ctx context.Context, sessionType, clientIP, deviceKey string, tokenType *string) (string, uint64, error) {
	userIdentifier := fmt.Sprintf("%s:%s", clientIP, deviceKey)
	if tokenType != nil && *tokenType != "" {
		userIdentifier = fmt.Sprintf("%s:%s", userIdentifier, *tokenType)
	}

	mapKey := userMapKey(sessionType, userIdentifier)
	oldSessionID, err := t.processedDataDB.Get(ctx, mapKey).Result()
	if err != nil && err != redis.Nil {
		return "", 0, fmt.Errorf("failed to get old session ID: %w", err)
	}
	if oldSessionID != "" {
		oldSessionKey := sessionKey(sessionType, oldSessionID)
		oldSessionMetaKey := sessionMetadataKey(sessionType, oldSessionID)
		if err := t.processedDataDB.Del(ctx, oldSessionKey, oldSessionMetaKey).Err(); err != nil {
			return "", 0, fmt.Errorf("failed to delete old session keys: %w", err)
		}
	}
	sessionID := uuid.New().String()
	sessKey := sessionKey(sessionType, sessionID)
	sessMetaKey := sessionMetadataKey(sessionType, sessionID)
	globalKey, err := getGlobalSetKey(sessionType, tokenType)
	if err != nil {
		return "", 0, err
	}

	tokenTypeValue := ""
	if tokenType != nil {
		tokenTypeValue = *tokenType
	}

	if responses, txErr := t.processedDataDB.TxPipelined(ctx, func(pipeliner redis.Pipeliner) error {
		if pErr := pipeliner.ZUnionStore(ctx, sessKey, &redis.ZStore{Keys: []string{globalKey}}).Err(); pErr != nil {
			return pErr
		}
		if pErr := pipeliner.Expire(ctx, sessKey, defaultViewingSessionTTL).Err(); pErr != nil {
			return pErr
		}
		if pErr := pipeliner.Set(ctx, sessMetaKey, tokenTypeValue, defaultViewingSessionTTL).Err(); pErr != nil {
			return pErr
		}
		if pErr := pipeliner.Set(ctx, mapKey, sessionID, defaultViewingSessionTTL).Err(); pErr != nil {
			return pErr
		}
		return nil
	}); txErr != nil {
		return "", 0, fmt.Errorf("failed to create viewing session: %w", txErr)
	} else {
		for _, response := range responses {
			if rerr := response.Err(); rerr != nil {
				return "", 0, fmt.Errorf("failed to `%v`: %w", response.FullName(), rerr)
			}
		}
	}

	ttlSeconds := uint64(defaultViewingSessionTTL.Seconds())
	log.Debug(fmt.Sprintf("Created viewing session: sessionID=%s, type=%s, userIdentifier=%s, TTL=%v", sessionID, sessionType, userIdentifier, defaultViewingSessionTTL))

	return sessionID, ttlSeconds, nil
}

func (t *tokenAnalytics) GetTokensFromViewingSession(ctx context.Context, sessionType, sessionID, keyword string, limit, offset uint64) ([]*CommunityToken, error) {
	sessKey := sessionKey(sessionType, sessionID)
	sessMetaKey := sessionMetadataKey(sessionType, sessionID)

	tokenType, err := t.processedDataDB.Get(ctx, sessMetaKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrSessionNotFound
		}

		return nil, fmt.Errorf("failed to check session existence: %w", err)
	}

	if keyword != "" {
		return t.getTokensWithKeywordFilter(ctx, sessKey, sessionType, tokenType, keyword, limit, offset)
	}
	tokenData, err := t.processedDataDB.ZRevRangeWithScores(ctx, sessKey, int64(offset), int64(offset+limit-1)).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get tokens from viewing session: %w", err)
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
	tokens, err := t.getTokenDetailsWithScoresMapWithType(ctx, sessionType, tokenType, tokenAddresses, scoresMap)
	if err != nil {
		return nil, fmt.Errorf("failed to get token details: %w", err)
	}

	return tokens, nil
}

func (t *tokenAnalytics) getTokensWithKeywordFilter(ctx context.Context, sessionKey, sessionType, tokenType, keyword string, limit, offset uint64) ([]*CommunityToken, error) {
	matchedAddresses, err := t.searchTokensByLookup(ctx, keyword)
	if err != nil {
		return nil, fmt.Errorf("failed to search tokens by lookup: %w", err)
	}
	if len(matchedAddresses) == 0 {
		return make([]*CommunityToken, 0), nil
	}

	scoresMap := make(map[string]float64)
	for _, addr := range matchedAddresses {
		score, err := t.processedDataDB.ZScore(ctx, sessionKey, addr).Result()
		if err == nil {
			scoresMap[addr] = score
		}
	}
	validAddresses := make([]string, 0, len(scoresMap))
	for addr := range scoresMap {
		validAddresses = append(validAddresses, addr)
	}

	if len(validAddresses) == 0 {
		return make([]*CommunityToken, 0), nil
	}
	type addrScore struct {
		addr  string
		score float64
	}
	sorted := make([]addrScore, 0, len(validAddresses))
	for _, addr := range validAddresses {
		sorted = append(sorted, addrScore{addr, scoresMap[addr]})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].score > sorted[j].score
	})
	start := int(offset)
	end := start + int(limit)
	if start >= len(sorted) {
		return make([]*CommunityToken, 0), nil
	}
	if end > len(sorted) {
		end = len(sorted)
	}

	paginatedAddresses := make([]string, 0, end-start)
	paginatedScores := make(map[string]float64)
	for i := start; i < end; i++ {
		paginatedAddresses = append(paginatedAddresses, sorted[i].addr)
		paginatedScores[sorted[i].addr] = sorted[i].score
	}

	return t.getTokenDetailsWithScoresMapWithType(ctx, sessionType, tokenType, paginatedAddresses, paginatedScores)
}

func (t *tokenAnalytics) getTokenDetailsWithScoresMapWithType(ctx context.Context, sessionType, tokenType string, externalAddresses []string, scoresMap map[string]float64) ([]*CommunityToken, error) {
	if len(externalAddresses) == 0 {
		return []*CommunityToken{}, nil
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
			t.created_at,
			t.ticker,
			t.total_supply,
			t.content_author_id as content_author_id,
			t.ion_connect_address,
			COALESCE(t.pair_id, '') as pair_id,
			creator.username as creator_username,
			creator.display_name as creator_display,
			creator.verified as creator_verified,
			creator.avatar as creator_avatar,
			creator.platform_group as creator_platform,
			t.content_author_id as creator_bnb_bsc_address,
			creator.external_address as creator_external_address,
			COALESCE(t.price_usd, 0) as price_usd,
			COALESCE(t.holders_count, 0) as holders_count,
			COALESCE(t.market_cap_usd, 0) as market_cap_usd,
			COALESCE(t.bonding_curve_current_amount, '0') as bonding_curve_current_amount,
			COALESCE(t.bonding_curve_goal_amount, '0') as bonding_curve_goal_amount,
			COALESCE(t.bonding_curve_current_amount_usd, 0) as bonding_curve_current_amount_usd,
			COALESCE(t.bonding_curve_goal_amount_usd, 0) as bonding_curve_goal_amount_usd,
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
			COALESCE(creator_token.pair_id, '') as creator_token_pair_id
		FROM tokens t
		LEFT JOIN user_bsc_addresses creator_addr ON creator_addr.bsc_address = t.content_author_id
		LEFT JOIN users creator ON creator.id = creator_addr.user_id
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
	`
	tokensPtr, err := storage.Select[tokenRow](ctx, t.ingestedDataDB, query, externalAddresses)
	if err != nil {
		return nil, fmt.Errorf("failed to get token details: %w", err)
	}
	tokensMap := make(map[string]*tokenRow)
	for i := range tokensPtr {
		tokensMap[tokensPtr[i].ExternalAddress] = tokensPtr[i]
	}
	secondaryMetrics, err := t.fetchAdditionalMetricsFromRedis(ctx, sessionType, tokenType, externalAddresses)
	if err != nil {
		return nil, err
	}
	var volumeFromTrending map[string]float64
	if sessionType == sessionTypeBondingCurveProgress {
		volumeFromTrending, err = t.fetchAdditionalMetricsFromRedis(ctx, sessionTypeTop, tokenType, externalAddresses)
		if err != nil {
			return nil, err
		}
	}

	result := make([]*CommunityToken, 0, len(externalAddresses))
	for _, addr := range externalAddresses {
		token, exists := tokensMap[addr]
		if !exists {
			continue
		}

		var marketCap, volume float64
		switch sessionType {
		case sessionTypeTop:
			// scoresMap has market cap, secondaryMetrics has volume
			marketCap = scoresMap[addr]
			volume = secondaryMetrics[addr] / 1e18
		case sessionTypeBondingCurveProgress:
			// scoresMap has bonding curve progress (not used), secondaryMetrics has market cap, volumeFromTrending has volume
			marketCap = secondaryMetrics[addr]
			volume = volumeFromTrending[addr] / 1e18
		case sessionTypeTrending:
			// scoresMap has volume, secondaryMetrics has market cap
			volume = scoresMap[addr] / 1e18
			marketCap = secondaryMetrics[addr]
		}

		tokenExternalAddresses, creatorExternalAddresses, err := buildTokenAndCreatorAddresses(TokenAndCreatorAddressesParams{
			CreatorBnbBscAddress:   token.CreatorBnbBscAddress,
			TokenIonConnectAddress: token.IonConnectAddress,
			TokenContractAddress:   token.ContractAddress,
			TokenExternalAddress:   token.ExternalAddress,
			TokenPlatform:          token.Platform,
			TokenPairId:            token.PairId,
			CreatorExternalAddress: strVal(token.CreatorExternalAddress),
			CreatorPlatform:        strVal(token.CreatorPlatform),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to build token and creator addresses: %w", err)
		}

		var bondingCurveProgress *BondingCurveProgress
		if token.BondingCurveCurrentAmount != "" && token.BondingCurveGoalAmount != "" {
			bondingCurveProgress = &BondingCurveProgress{
				CurrentAmount:    token.BondingCurveCurrentAmount,
				GoalAmount:       token.BondingCurveGoalAmount,
				CurrentAmountUSD: token.BondingCurveCurrentAmountUSD,
				GoalAmountUSD:    token.BondingCurveGoalAmountUSD,
			}
		}
		creatorToken, err := buildCreatorToken(token)
		if err != nil {
			return nil, fmt.Errorf("failed to build creator token for %s: %w", token.ContractAddress, err)
		}

		var launcher *User
		if token.Platform == PlatformGroupXCom && token.LauncherBlockchainAddress != nil && strVal(token.LauncherBlockchainAddress) != "" {
			launcherPlatform := strVal(token.LauncherPlatform)
			if launcherPlatform == "" {
				launcherPlatform = token.Platform
			}
			launcherAddresses, err := buildAddressesFromExternalAddressAndPlatform(
				strVal(token.LauncherExternalAddress),
				launcherPlatform,
				strVal(token.LauncherBlockchainAddress),
				"",
			)
			if err != nil {
				return nil, fmt.Errorf("failed to build launcher addresses from external_address %s (platform %s): %w", strVal(token.LauncherExternalAddress), launcherPlatform, err)
			}

			launcher = &User{
				Username:  token.LauncherUsername,
				Display:   token.LauncherDisplay,
				Verified:  token.LauncherVerified,
				Avatar:    token.LauncherAvatar,
				Addresses: launcherAddresses,
			}
		}

		result = append(result, &CommunityToken{
			Type:        token.Type,
			Title:       token.Title,
			Description: token.Description,
			ImageURL:    token.ImageURL,
			CreatedAt:   token.CreatedAt,
			Addresses:   tokenExternalAddresses,
			Creator: User{
				Username:  token.CreatorUsername,
				Display:   token.CreatorDisplay,
				Verified:  token.CreatorVerified,
				Avatar:    token.CreatorAvatar,
				Addresses: creatorExternalAddresses,
				Token:     creatorToken,
			},
			Launcher: launcher,
			MarketData: MarketData{
				Ticker:               token.Ticker,
				MarketCap:            marketCap,
				Supply:               token.TotalSupply,
				Volume:               volume,
				Holders:              uint64(token.HoldersCount),
				PriceUSD:             token.PriceUSD,
				BondingCurveProgress: bondingCurveProgress,
			},
		})
	}
	log.Debug(fmt.Sprintf("Retrieved %d token details", len(result)))

	return result, nil
}

func (t *tokenAnalytics) fetchAdditionalMetricsFromRedis(ctx context.Context, sessionType, tokenType string, externalAddresses []string) (map[string]float64, error) {
	pipe := t.processedDataDB.Pipeline()
	cmds := make(map[string]*redis.FloatCmd, len(externalAddresses))

	if sessionType == sessionTypeTop {
		// For "top": need to fetch volume from global trending set
		trendingKey := globalTrendingSetKey
		if tokenType != "" {
			if typeSpecificKey, err := getGlobalSetKey(sessionTypeTrending, &tokenType); err == nil {
				trendingKey = typeSpecificKey
			}
		}
		for _, addr := range externalAddresses {
			cmds[addr] = pipe.ZScore(ctx, trendingKey, addr)
		}
	} else {
		// For "trending" and "bondingCurveProgress": need to fetch market cap from global top set
		topKey := globalTopSetKey
		if tokenType != "" {
			if typeSpecificKey, err := getGlobalSetKey(sessionTypeTop, &tokenType); err == nil {
				topKey = typeSpecificKey
			}
		}
		for _, addr := range externalAddresses {
			cmds[addr] = pipe.ZScore(ctx, topKey, addr)
		}
	}
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("failed to fetch metrics from Redis: %w", err)
	}

	result := make(map[string]float64, len(externalAddresses))
	for addr, cmd := range cmds {
		if score, err := cmd.Result(); err == nil {
			result[addr] = score
		}
	}

	return result, nil
}

func (t *tokenAnalytics) searchTokensByLookup(ctx context.Context, keyword string) ([]string, error) {
	searchQuery := `
		SELECT t.external_address
		FROM tokens t
		WHERE t.lookup ILIKE $1
	`
	searchPattern := "%" + keyword + "%"
	type tokenAddr struct {
		ExternalAddress string `db:"external_address"`
	}
	matchedTokens, err := storage.Select[tokenAddr](ctx, t.ingestedDataDB, searchQuery, searchPattern)
	if err != nil {
		return nil, fmt.Errorf("failed to search tokens by lookup: %w", err)
	}
	addresses := make([]string, len(matchedTokens))
	for i, mt := range matchedTokens {
		addresses[i] = mt.ExternalAddress
	}
	return addresses, nil
}

func sessionKey(sessionType, sessionID string) string {
	return fmt.Sprintf(userSessionKeyPrefix, sessionType, sessionID)
}

func userMapKey(sessionType, userIdentifier string) string {
	return fmt.Sprintf(userIdentifierMapPrefix, sessionType, userIdentifier)
}

func sessionMetadataKey(sessionType, sessionID string) string {
	return fmt.Sprintf("token_analytics:session_meta:%s:%s", sessionType, sessionID)
}

func getGlobalSetKey(sessionType string, tokenType *string) (string, error) {
	switch sessionType {
	case sessionTypeTop:
		if tokenType != nil && *tokenType != "" {
			switch *tokenType {
			case TokenTypeProfile:
				return globalTopProfileSetKey, nil
			case TokenTypePost:
				return globalTopPostSetKey, nil
			case TokenTypeVideo:
				return globalTopVideoSetKey, nil
			case TokenTypeArticle:
				return globalTopArticleSetKey, nil
			case TokenTypeAnyPost:
				return globalTopAnyPostSetKey, nil
			case TokenTypeXcom:
				return globalTopXcomSetKey, nil
			default:
				return "", fmt.Errorf("unsupported token type: %s", *tokenType)
			}
		}
		return globalTopSetKey, nil
	case sessionTypeTrending:
		if tokenType != nil && *tokenType != "" {
			switch *tokenType {
			case TokenTypeProfile:
				return globalTrendingProfileSetKey, nil
			case TokenTypePost:
				return globalTrendingPostSetKey, nil
			case TokenTypeVideo:
				return globalTrendingVideoSetKey, nil
			case TokenTypeArticle:
				return globalTrendingArticleSetKey, nil
			case TokenTypeAnyPost:
				return globalTrendingAnyPostSetKey, nil
			case TokenTypeXcom:
				return globalTrendingXcomSetKey, nil
			default:
				return "", fmt.Errorf("unsupported token type: %s", *tokenType)
			}
		}
		return globalTrendingSetKey, nil
	case sessionTypeBondingCurveProgress:
		if tokenType != nil && *tokenType != "" {
			switch *tokenType {
			case TokenTypeProfile:
				return globalBondingCurveProgressProfileSetKey, nil
			case TokenTypePost:
				return globalBondingCurveProgressPostSetKey, nil
			case TokenTypeVideo:
				return globalBondingCurveProgressVideoSetKey, nil
			case TokenTypeArticle:
				return globalBondingCurveProgressArticleSetKey, nil
			case TokenTypeAnyPost:
				return globalBondingCurveProgressAnyPostSetKey, nil
			case TokenTypeXcom:
				return globalBondingCurveProgressXcomSetKey, nil
			default:
				return "", fmt.Errorf("unsupported token type: %s", *tokenType)
			}
		}
		return globalBondingCurveProgressSetKey, nil
	default:
		return "", fmt.Errorf("unsupported session type: %s", sessionType)
	}
}
