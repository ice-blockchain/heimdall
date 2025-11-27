// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) CreateViewingSession(ctx context.Context, sessionType, clientIP, deviceKey string, tokenType *string) (string, uint64, error) {
	// TODO: use tokenType for filtering when implementing logic
	userIdentifier := fmt.Sprintf("%s:%s", clientIP, deviceKey)

	mapKey := userMapKey(sessionType, userIdentifier)
	oldSessionID, err := t.processedDataDB.Get(ctx, mapKey).Result()
	if err != nil && err != redis.Nil {
		return "", 0, fmt.Errorf("failed to get old session ID: %w", err)
	}
	if oldSessionID != "" {
		oldSessionKey := sessionKey(sessionType, oldSessionID)
		if err := t.processedDataDB.Del(ctx, oldSessionKey).Err(); err != nil {
			return "", 0, fmt.Errorf("failed to delete old session key: %w", err)
		}
	}
	sessionID := uuid.New().String()
	sessKey := sessionKey(sessionType, sessionID)

	var globalKey string
	switch sessionType {
	case sessionTypeTop:
		globalKey = globalTopSetKey
	case sessionTypeTrending:
		globalKey = globalTrendingSetKey
	case sessionTypeBondingCurveProgress:
		globalKey = globalBondingCurveProgressSetKey
	default:
		return "", 0, fmt.Errorf("unsupported session type: %s", sessionType)
	}
	pipe := t.processedDataDB.TxPipeline()
	pipe.ZUnionStore(ctx, sessKey, &redis.ZStore{Keys: []string{globalKey}})
	pipe.Expire(ctx, sessKey, defaultViewingSessionTTL)
	pipe.Set(ctx, mapKey, sessionID, defaultViewingSessionTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		return "", 0, fmt.Errorf("failed to create viewing session: %w", err)
	}

	ttlSeconds := uint64(defaultViewingSessionTTL.Seconds())
	log.Debug(fmt.Sprintf("Created viewing session: sessionID=%s, type=%s, userIdentifier=%s, TTL=%v", sessionID, sessionType, userIdentifier, defaultViewingSessionTTL))

	return sessionID, ttlSeconds, nil
}

func (t *tokenAnalytics) GetTokensFromViewingSession(ctx context.Context, sessionType, sessionID, keyword string, limit, offset uint64) ([]*CommunityToken, error) {
	sessKey := sessionKey(sessionType, sessionID)
	exists, err := t.processedDataDB.Exists(ctx, sessKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to check session existence: %w", err)
	}
	if exists == 0 {
		return nil, ErrSessionNotFound
	}

	if keyword != "" {
		return t.getTokensWithKeywordFilter(ctx, sessKey, sessionType, keyword, limit, offset)
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
	tokens, err := t.getTokenDetailsWithScoresMap(ctx, sessionType, tokenAddresses, scoresMap)
	if err != nil {
		return nil, fmt.Errorf("failed to get token details: %w", err)
	}

	return tokens, nil
}

func (t *tokenAnalytics) getTokensWithKeywordFilter(ctx context.Context, sessionKey, sessionType, keyword string, limit, offset uint64) ([]*CommunityToken, error) {
	matchedAddresses, err := t.searchTokensByCreatorLookup(ctx, keyword)
	if err != nil {
		return nil, fmt.Errorf("failed to search tokens by creator username: %w", err)
	}
	if len(matchedAddresses) == 0 {
		return make([]*CommunityToken, 0), nil
	}
	filteredAddresses, err := t.filterTokensBySession(ctx, sessionKey, matchedAddresses)
	if err != nil {
		return nil, err
	}
	if len(filteredAddresses) == 0 {
		return make([]*CommunityToken, 0), nil
	}
	paginatedAddresses := applyPagination(filteredAddresses, int64(limit), int64(offset))
	if len(paginatedAddresses) == 0 {
		return make([]*CommunityToken, 0), nil
	}

	tokens, err := t.getTokenDetailsWithScores(ctx, sessionKey, sessionType, paginatedAddresses)
	if err != nil {
		return nil, fmt.Errorf("failed to get token details: %w", err)
	}

	return tokens, nil
}

func (t *tokenAnalytics) getTokenDetailsWithScores(ctx context.Context, sessionKey, sessionType string, ionConnectAddresses []string) ([]*CommunityToken, error) {
	scoresMap := make(map[string]float64)
	for _, addr := range ionConnectAddresses {
		score, err := t.processedDataDB.ZScore(ctx, sessionKey, addr).Result()
		if err != nil {
			return nil, fmt.Errorf("failed to get score for token %s: %w", addr, err)
		}
		scoresMap[addr] = score
	}

	return t.getTokenDetailsWithScoresMap(ctx, sessionType, ionConnectAddresses, scoresMap)
}

func (t *tokenAnalytics) getTokenDetailsWithScoresMap(ctx context.Context, sessionType string, ionConnectAddresses []string, scoresMap map[string]float64) ([]*CommunityToken, error) {
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
		t.created_at,
		t.ticker,
		t.total_supply,
		COALESCE(t.creator_master_pubkey, '') as creator_master_pubkey,
		creator.username as creator_username,
		COALESCE(creator.display_name, '') as creator_display,
		creator.verified as creator_verified,
		COALESCE(creator.avatar, '') as creator_avatar,
		COALESCE(t.price_usd, 0) as price_usd,
		COALESCE(t.holders_count, 0) as holders_count,
		COALESCE(t.market_cap_usd, 0) as market_cap_usd
		FROM tokens t
		LEFT JOIN users creator ON creator.master_pubkey = t.creator_master_pubkey
		WHERE t.ion_connect_address = ANY($1)
	`
	tokensPtr, err := storage.Select[tokenRow](ctx, t.ingestedDataDB, query, ionConnectAddresses)
	if err != nil {
		return nil, fmt.Errorf("failed to get token details: %w", err)
	}
	tokensMap := make(map[string]*tokenRow)
	for i := range tokensPtr {
		tokensMap[tokensPtr[i].IONConnectAddress] = tokensPtr[i]
	}
	additionalMetrics, err := t.fetchAdditionalMetricsFromRedis(ctx, sessionType, ionConnectAddresses)
	if err != nil {
		return nil, err
	}
	result := make([]*CommunityToken, 0, len(ionConnectAddresses))
	for _, addr := range ionConnectAddresses {
		token, exists := tokensMap[addr]
		if !exists {
			continue
		}
		var marketCap, volume int
		if sessionType == sessionTypeTop {
			marketCap = int(scoresMap[addr])
			volume = additionalMetrics[addr]
		} else {
			volume = int(scoresMap[addr])
			marketCap = additionalMetrics[addr]
		}

		result = append(result, &CommunityToken{
			Type:        token.Type,
			Title:       token.Title,
			Description: token.Description,
			ImageURL:    token.ImageURL,
			CreatedAt:   *token.CreatedAt.Time,
			Addresses: Addresses{
				IonConnect: token.IONConnectAddress,
			},
			Creator: User{
				Username: token.CreatorUsername,
				Display:  token.CreatorDisplay,
				Verified: token.CreatorVerified,
				Avatar:   token.CreatorAvatar,
				Addresses: Addresses{
					IonConnect: token.CreatorMasterPubkey,
				},
			},
			MarketData: MarketData{
				MarketCap: float64(marketCap),
				Volume:    float64(volume),
				Holders:   uint64(token.HoldersCount),
				PriceUSD:  token.PriceUSD,
			},
		})
	}
	log.Debug(fmt.Sprintf("Retrieved %d token details", len(result)))

	return result, nil
}

func (t *tokenAnalytics) fetchAdditionalMetricsFromRedis(ctx context.Context, sessionType string, ionConnectAddresses []string) (map[string]int, error) {
	pipe := t.processedDataDB.Pipeline()
	cmds := make(map[string]*redis.FloatCmd, len(ionConnectAddresses))
	if sessionType == sessionTypeTop {
		// For "top": need to fetch volume from global trending set
		for _, addr := range ionConnectAddresses {
			cmds[addr] = pipe.ZScore(ctx, globalTrendingSetKey, addr)
		}
	} else {
		// For "trending": need to fetch market cap from global top set
		for _, addr := range ionConnectAddresses {
			cmds[addr] = pipe.ZScore(ctx, globalTopSetKey, addr)
		}
	}
	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		return nil, fmt.Errorf("failed to fetch metrics from Redis: %w", err)
	}
	result := make(map[string]int, len(ionConnectAddresses))
	for addr, cmd := range cmds {
		if score, err := cmd.Result(); err == nil {
			result[addr] = int(score)
		}
	}

	return result, nil
}

func (t *tokenAnalytics) searchTokensByCreatorLookup(ctx context.Context, keyword string) ([]string, error) {
	searchQuery := `
		SELECT t.ion_connect_address
		FROM tokens t
		INNER JOIN users u ON u.master_pubkey = t.creator_master_pubkey
		WHERE u.lookup ILIKE $1
	`
	searchPattern := "%" + keyword + "%"
	type tokenAddr struct {
		IONConnectAddress string `db:"ion_connect_address"`
	}
	matchedTokens, err := storage.Select[tokenAddr](ctx, t.ingestedDataDB, searchQuery, searchPattern)
	if err != nil {
		return nil, fmt.Errorf("failed to search tokens by creator lookup: %w", err)
	}
	addresses := make([]string, len(matchedTokens))
	for i, mt := range matchedTokens {
		addresses[i] = mt.IONConnectAddress
	}
	return addresses, nil
}

func (t *tokenAnalytics) filterTokensBySession(ctx context.Context, sessionKey string, candidateAddresses []string) ([]string, error) {
	allSessionTokens, err := t.processedDataDB.ZRevRange(ctx, sessionKey, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get session tokens: %w", err)
	}
	sessionTokensMap := make(map[string]bool, len(allSessionTokens))
	for _, addr := range allSessionTokens {
		sessionTokensMap[addr] = true
	}
	filteredAddresses := make([]string, 0, len(candidateAddresses))
	for _, addr := range candidateAddresses {
		if sessionTokensMap[addr] {
			filteredAddresses = append(filteredAddresses, addr)
		}
	}

	return filteredAddresses, nil
}

func applyPagination(addresses []string, limit, offset int64) []string {
	start := int(offset)
	if start >= len(addresses) {
		return []string{}
	}
	end := start + int(limit)
	if end > len(addresses) {
		end = len(addresses)
	}

	return addresses[start:end]
}

func sessionKey(sessionType, sessionID string) string {
	return fmt.Sprintf(userSessionKeyPrefix, sessionType, sessionID)
}

func userMapKey(sessionType, userIdentifier string) string {
	return fmt.Sprintf(userIdentifierMapPrefix, sessionType, userIdentifier)
}
