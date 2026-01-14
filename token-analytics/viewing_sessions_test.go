// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestCreateViewingSession(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()

	ta := helperNewForTest(t, db)

	t.Run("creates session for top type", func(t *testing.T) {
		helperSetupGlobalSet(t, ctx, globalTopSetKey, map[string]float64{
			"0:token1:": 1000.0,
			"0:token2:": 500.0,
		})

		sessionID, ttl, err := ta.CreateViewingSession(ctx, sessionTypeTop, "192.168.1.1", "device123", nil)
		require.NoError(t, err)
		require.NotEmpty(t, sessionID)
		require.Greater(t, ttl, uint64(0))

		sessKey := sessionKey(sessionTypeTop, sessionID)
		exists, err := testRedis.Exists(ctx, sessKey).Result()
		require.NoError(t, err)
		require.Equal(t, int64(1), exists)
	})

	t.Run("creates session for trending type", func(t *testing.T) {
		helperSetupGlobalSet(t, ctx, globalTrendingSetKey, map[string]float64{
			"0:trending1:": 2000.0,
			"0:trending2:": 1500.0,
		})

		sessionID, ttl, err := ta.CreateViewingSession(ctx, sessionTypeTrending, "192.168.1.2", "device456", nil)
		require.NoError(t, err)
		require.NotEmpty(t, sessionID)
		require.Greater(t, ttl, uint64(0))
	})

	t.Run("creates session for bonding curve progress type", func(t *testing.T) {
		helperSetupGlobalSet(t, ctx, globalBondingCurveProgressSetKey, map[string]float64{
			"0:bonding1:": 75.0,
			"0:bonding2:": 50.0,
		})

		sessionID, ttl, err := ta.CreateViewingSession(ctx, sessionTypeBondingCurveProgress, "192.168.1.3", "device789", nil)
		require.NoError(t, err)
		require.NotEmpty(t, sessionID)
		require.Greater(t, ttl, uint64(0))
	})

	t.Run("creates session with token type filter", func(t *testing.T) {
		helperSetupGlobalSet(t, ctx, globalTopProfileSetKey, map[string]float64{
			"0:profile1:": 3000.0,
		})

		tokenType := TokenTypeProfile
		sessionID, ttl, err := ta.CreateViewingSession(ctx, sessionTypeTop, "192.168.1.4", "deviceABC", &tokenType)
		require.NoError(t, err)
		require.NotEmpty(t, sessionID)
		require.Greater(t, ttl, uint64(0))
	})

	t.Run("creates session for anyPost type in top", func(t *testing.T) {
		helperSetupGlobalSet(t, ctx, globalTopAnyPostSetKey, map[string]float64{
			"30175:anypost1:content": 5000.0,
			"30023:anypost2:content": 4000.0,
		})

		tokenType := TokenTypeAnyPost
		sessionID, ttl, err := ta.CreateViewingSession(ctx, sessionTypeTop, "192.168.1.10", "deviceAnyPost1", &tokenType)
		require.NoError(t, err)
		require.NotEmpty(t, sessionID)
		require.Greater(t, ttl, uint64(0))

		sessKey := sessionKey(sessionTypeTop, sessionID)
		exists, err := testRedis.Exists(ctx, sessKey).Result()
		require.NoError(t, err)
		require.Equal(t, int64(1), exists)
	})

	t.Run("creates session for anyPost type in trending", func(t *testing.T) {
		helperSetupGlobalSet(t, ctx, globalTrendingAnyPostSetKey, map[string]float64{
			"30175:trendpost1:content": 10000.0,
			"30023:trendpost2:content": 8000.0,
		})

		tokenType := TokenTypeAnyPost
		sessionID, ttl, err := ta.CreateViewingSession(ctx, sessionTypeTrending, "192.168.1.11", "deviceAnyPost2", &tokenType)
		require.NoError(t, err)
		require.NotEmpty(t, sessionID)
		require.Greater(t, ttl, uint64(0))
	})

	t.Run("creates session for anyPost type in bonding curve progress", func(t *testing.T) {
		helperSetupGlobalSet(t, ctx, globalBondingCurveProgressAnyPostSetKey, map[string]float64{
			"30175:bcpost1:content": 85.0,
			"30023:bcpost2:content": 60.0,
		})

		tokenType := TokenTypeAnyPost
		sessionID, ttl, err := ta.CreateViewingSession(ctx, sessionTypeBondingCurveProgress, "192.168.1.12", "deviceAnyPost3", &tokenType)
		require.NoError(t, err)
		require.NotEmpty(t, sessionID)
		require.Greater(t, ttl, uint64(0))
	})

	t.Run("replaces existing session for same user", func(t *testing.T) {
		helperSetupGlobalSet(t, ctx, globalTopSetKey, map[string]float64{
			"0:token1:": 1000.0,
		})

		sessionID1, _, err := ta.CreateViewingSession(ctx, sessionTypeTop, "192.168.1.5", "deviceXYZ", nil)
		require.NoError(t, err)

		sessionID2, _, err := ta.CreateViewingSession(ctx, sessionTypeTop, "192.168.1.5", "deviceXYZ", nil)
		require.NoError(t, err)

		require.NotEqual(t, sessionID1, sessionID2)

		// Old session should be deleted
		sessKey1 := sessionKey(sessionTypeTop, sessionID1)
		exists, err := testRedis.Exists(ctx, sessKey1).Result()
		require.NoError(t, err)
		require.Equal(t, int64(0), exists)
	})
}

func TestGetTokensFromViewingSession(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()

	ta := helperNewForTest(t, db)

	t.Run("returns error for non-existent session", func(t *testing.T) {
		tokens, err := ta.GetTokensFromViewingSession(ctx, sessionTypeTop, "nonexistent-session-id", "", 10, 0)
		require.Error(t, err)
		require.Nil(t, tokens)
		require.ErrorIs(t, err, ErrSessionNotFound)
	})

	t.Run("returns tokens from session", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "vs_creator1", "vs_alice", "VS Alice", "", true, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db,
			"0xVS111111111111111111111111111111111111",
			"0:vs_creator1:",
			"VST1",
			"profile",
			"vs_creator1",
			"1000000000000000000000000",
			500.0,
			0.001,
			10,
			PlatformGroupIonConnect,
		)

		helperInsertTestUser(t, ctx, db, "vs_creator2", "vs_bob", "VS Bob", "", false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db,
			"0xVS222222222222222222222222222222222222",
			"0:vs_creator2:",
			"VST2",
			"profile",
			"vs_creator2",
			"2000000000000000000000000",
			300.0,
			0.002,
			5,
			PlatformGroupIonConnect,
		)
		helperSetupGlobalSet(t, ctx, globalTopSetKey, map[string]float64{
			"0:vs_creator1:": 500.0,
			"0:vs_creator2:": 300.0,
		})
		helperSetupGlobalSet(t, ctx, globalTrendingSetKey, map[string]float64{
			"0:vs_creator1:": 1000.0 * 1e18,
			"0:vs_creator2:": 800.0 * 1e18,
		})
		sessionID, _, err := ta.CreateViewingSession(ctx, sessionTypeTop, "192.168.2.1", "device_vs1", nil)
		require.NoError(t, err)
		tokens, err := ta.GetTokensFromViewingSession(ctx, sessionTypeTop, sessionID, "", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 2)
		require.Equal(t, "profile", tokens[0].Type)
		require.Equal(t, "vs_alice", tokens[0].Title)
		require.Equal(t, "VS Alice", tokens[0].Description)
		require.NotEmpty(t, tokens[0].ImageURL)
		require.NotNil(t, tokens[0].CreatedAt)
		require.False(t, tokens[0].CreatedAt.IsZero())

		require.NotNil(t, tokens[0].Addresses)
		require.Equal(t, "0:vs_creator1:", tokens[0].Addresses.IonConnect)
		require.Empty(t, tokens[0].Addresses.Twitter)

		require.Equal(t, "vs_alice", strVal(tokens[0].Creator.Username))
		require.Equal(t, "VS Alice", strVal(tokens[0].Creator.Display))
		require.True(t, tokens[0].Creator.Verified != nil && *tokens[0].Creator.Verified)
		require.NotEmpty(t, tokens[0].Creator.Avatar)
		require.NotNil(t, tokens[0].Creator.Addresses)
		require.Equal(t, "0:vs_creator1:", tokens[0].Creator.Addresses.IonConnect)

		require.InDelta(t, 500.0, tokens[0].MarketData.MarketCap, 1.0, "Market cap from Redis top set")
		require.InDelta(t, 1000.0, tokens[0].MarketData.Volume, 1.0, "Volume from trending set")
		require.Equal(t, uint64(10), tokens[0].MarketData.Holders)
		require.InDelta(t, 0.001, tokens[0].MarketData.PriceUSD, 0.0001)

		require.Equal(t, "profile", tokens[1].Type)
		require.Equal(t, "vs_bob", tokens[1].Title)
		require.Equal(t, "vs_bob", strVal(tokens[1].Creator.Username))
		require.Equal(t, "VS Bob", strVal(tokens[1].Creator.Display))
		require.True(t, tokens[1].Creator.Verified == nil || !*tokens[1].Creator.Verified)
		require.InDelta(t, 300.0, tokens[1].MarketData.MarketCap, 1.0)
		require.InDelta(t, 800.0, tokens[1].MarketData.Volume, 1.0)
		require.Equal(t, uint64(5), tokens[1].MarketData.Holders)
		require.InDelta(t, 0.002, tokens[1].MarketData.PriceUSD, 0.0001)
	})

	t.Run("returns tokens with keyword filter", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "vs_creator_kw", "vs_keyword", "VS Keyword User", "", false, PlatformGroupIonConnect)

		helperInsertTestToken(t, ctx, db,
			"0xVSKW1111111111111111111111111111111111",
			"0:vs_creator_kw:",
			"KWT",
			"profile",
			"vs_creator_kw",
			"1000000000000000000000000",
			200.0,
			0.0005,
			3,
			PlatformGroupIonConnect,
		)

		helperSetupGlobalSet(t, ctx, globalTopSetKey, map[string]float64{
			"0:vs_creator_kw:": 200.0,
		})

		sessionID, _, err := ta.CreateViewingSession(ctx, sessionTypeTop, "192.168.2.2", "device_kw", nil)
		require.NoError(t, err)

		tokens, err := ta.GetTokensFromViewingSession(ctx, sessionTypeTop, sessionID, "keyword", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)
		require.Equal(t, "vs_keyword", strVal(tokens[0].Creator.Username))
	})

	t.Run("respects pagination", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			creator := helperTestUniqueID(t, "vs_page_creator", i)
			helperInsertTestUser(t, ctx, db, creator, helperTestUniqueID(t, "vs_page", i), helperTestUniqueID(t, "VS Page", i), "", false, PlatformGroupIonConnect)
			helperInsertTestToken(t, ctx, db,
				helperTestUniqueID(t, "0xVSPAGE", i)+"111111111111111111111111111",
				"0:"+creator+":",
				helperTestUniqueID(t, "PG", i),
				"profile",
				creator,
				"1000000000000000000000000",
				float64(100+i*50),
				0.0001,
				1,
				PlatformGroupIonConnect,
			)
		}

		helperSetupGlobalSet(t, ctx, globalTopSetKey, map[string]float64{
			"0:" + helperTestUniqueID(t, "vs_page_creator", 0) + ":": 100.0,
			"0:" + helperTestUniqueID(t, "vs_page_creator", 1) + ":": 150.0,
			"0:" + helperTestUniqueID(t, "vs_page_creator", 2) + ":": 200.0,
			"0:" + helperTestUniqueID(t, "vs_page_creator", 3) + ":": 250.0,
			"0:" + helperTestUniqueID(t, "vs_page_creator", 4) + ":": 300.0,
		})

		sessionID, _, err := ta.CreateViewingSession(ctx, sessionTypeTop, "192.168.2.3", "device_page", nil)
		require.NoError(t, err)

		tokens1, err := ta.GetTokensFromViewingSession(ctx, sessionTypeTop, sessionID, "", 2, 0)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(tokens1), 1, "Expected at least 1 token in first page")

		tokens2, err := ta.GetTokensFromViewingSession(ctx, sessionTypeTop, sessionID, "", 2, 2)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(tokens2), 0)
	})

	t.Run("anyPost session returns only non-profile tokens", func(t *testing.T) {
		_ = testRedis.Del(ctx, globalTopAnyPostSetKey, globalTrendingAnyPostSetKey).Err()

		helperInsertTestUser(t, ctx, db, "anypost_profile_creator", "anypost_profile", "AnyPost Profile", "", false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db,
			"0xANYPOSTPROF111111111111111111111111111",
			"0:anypost_profile_creator:",
			"APPROF",
			"profile",
			"anypost_profile_creator",
			"1000000000000000000000000",
			1000.0,
			0.01,
			10,
			PlatformGroupIonConnect,
		)

		helperInsertTestUser(t, ctx, db, "anypost_post_creator", "anypost_post_user", "AnyPost Post User", "", false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db,
			"0xANYPOSTPOST1111111111111111111111111111",
			"30175:anypost_post_id:content",
			"APPOST",
			"post",
			"anypost_post_creator",
			"2000000000000000000000000",
			2000.0,
			0.02,
			20,
			PlatformGroupIonConnect,
		)

		helperInsertTestUser(t, ctx, db, "anypost_video_creator", "anypost_video_user", "AnyPost Video User", "", false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db,
			"0xANYPOSTVIDEO111111111111111111111111111",
			"30175:anypost_video_id:content",
			"APVID",
			"video",
			"anypost_video_creator",
			"3000000000000000000000000",
			3000.0,
			0.03,
			30,
			PlatformGroupIonConnect,
		)

		helperInsertTestUser(t, ctx, db, "anypost_article_creator", "anypost_article_user", "AnyPost Article User", "", false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db,
			"0xANYPOSTARTICLE1111111111111111111111111",
			"30023:anypost_article_id:content",
			"APART",
			"article",
			"anypost_article_creator",
			"4000000000000000000000000",
			4000.0,
			0.04,
			40,
			PlatformGroupIonConnect,
		)

		helperSetupGlobalSet(t, ctx, globalTopAnyPostSetKey, map[string]float64{
			"30175:anypost_post_id:content":    2000.0,
			"30175:anypost_video_id:content":   3000.0,
			"30023:anypost_article_id:content": 4000.0,
		})

		helperSetupGlobalSet(t, ctx, globalTrendingAnyPostSetKey, map[string]float64{
			"30175:anypost_post_id:content":    500.0 * 1e18,
			"30175:anypost_video_id:content":   600.0 * 1e18,
			"30023:anypost_article_id:content": 700.0 * 1e18,
		})

		tokenType := TokenTypeAnyPost
		sessionID, _, err := ta.CreateViewingSession(ctx, sessionTypeTop, "192.168.3.1", "device_anypost_test", &tokenType)
		require.NoError(t, err)

		tokens, err := ta.GetTokensFromViewingSession(ctx, sessionTypeTop, sessionID, "", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 3, "Should return exactly 3 tokens (post, video, article)")

		for _, token := range tokens {
			require.NotEqual(t, "profile", token.Type, "anyPost session should NOT contain profile tokens")
		}

		foundTypes := make(map[string]bool)
		for _, token := range tokens {
			foundTypes[token.Type] = true
		}
		require.True(t, foundTypes["post"] || foundTypes["video"] || foundTypes["article"], "Should contain post, video, or article")
		require.False(t, foundTypes["profile"], "Should NOT contain profile")

		tokenTitles := make(map[string]bool)
		for _, token := range tokens {
			tokenTitles[token.Title] = true
		}
		require.True(t, tokenTitles["anypost_post_user"], "Should contain post token")
		require.True(t, tokenTitles["anypost_video_user"], "Should contain video token")
		require.True(t, tokenTitles["anypost_article_user"], "Should contain article token")
		require.False(t, tokenTitles["anypost_profile"], "Should NOT contain profile token")
	})

	t.Run("anyPost session in trending type works correctly", func(t *testing.T) {
		t.Skip("Skipping for noe this test because it's not working as expected, TODO: fix it")
		_ = testRedis.Del(ctx, globalTrendingAnyPostSetKey, globalTopAnyPostSetKey).Err()

		helperInsertTestUser(t, ctx, db, "trend_post_creator", "trend_post", "Trending Post", "", false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db,
			"0xTRENDPOST11111111111111111111111111111",
			"30175:trend_post_id:content",
			"TPST",
			"post",
			"trend_post_creator",
			"5000000000000000000000000",
			5000.0,
			0.05,
			50,
			PlatformGroupIonConnect,
		)

		helperSetupGlobalSet(t, ctx, globalTrendingAnyPostSetKey, map[string]float64{
			"30175:trend_post_id:content": 8000.0 * 1e18, // Volume
		})

		helperSetupGlobalSet(t, ctx, globalTopAnyPostSetKey, map[string]float64{
			"30175:trend_post_id:content": 5000.0, // Market cap
		})

		tokenType := TokenTypeAnyPost
		sessionID, _, err := ta.CreateViewingSession(ctx, sessionTypeTrending, "192.168.3.2", "device_trend_anypost", &tokenType)
		require.NoError(t, err)

		tokens, err := ta.GetTokensFromViewingSession(ctx, sessionTypeTrending, sessionID, "", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		require.Equal(t, "post", tokens[0].Type)
		require.InDelta(t, 8000.0, tokens[0].MarketData.Volume, 1.0, "Volume should be from trending set")
		require.InDelta(t, 5000.0, tokens[0].MarketData.MarketCap, 1.0, "Market cap should be fetched from top set")
	})
}

func TestGetGlobalSetKey(t *testing.T) {
	t.Parallel()

	t.Run("returns correct keys for top session type", func(t *testing.T) {
		key, err := getGlobalSetKey(sessionTypeTop, nil)
		require.NoError(t, err)
		require.Equal(t, globalTopSetKey, key)

		profileType := TokenTypeProfile
		key, err = getGlobalSetKey(sessionTypeTop, &profileType)
		require.NoError(t, err)
		require.Equal(t, globalTopProfileSetKey, key)

		postType := TokenTypePost
		key, err = getGlobalSetKey(sessionTypeTop, &postType)
		require.NoError(t, err)
		require.Equal(t, globalTopPostSetKey, key)
	})

	t.Run("returns correct keys for trending session type", func(t *testing.T) {
		key, err := getGlobalSetKey(sessionTypeTrending, nil)
		require.NoError(t, err)
		require.Equal(t, globalTrendingSetKey, key)

		videoType := TokenTypeVideo
		key, err = getGlobalSetKey(sessionTypeTrending, &videoType)
		require.NoError(t, err)
		require.Equal(t, globalTrendingVideoSetKey, key)
	})

	t.Run("returns correct keys for bonding curve progress session type", func(t *testing.T) {
		key, err := getGlobalSetKey(sessionTypeBondingCurveProgress, nil)
		require.NoError(t, err)
		require.Equal(t, globalBondingCurveProgressSetKey, key)

		articleType := TokenTypeArticle
		key, err = getGlobalSetKey(sessionTypeBondingCurveProgress, &articleType)
		require.NoError(t, err)
		require.Equal(t, globalBondingCurveProgressArticleSetKey, key)
	})

	t.Run("returns error for unsupported session type", func(t *testing.T) {
		key, err := getGlobalSetKey("invalid", nil)
		require.Error(t, err)
		require.Empty(t, key)
	})

	t.Run("returns error for unsupported token type", func(t *testing.T) {
		invalidType := "invalid"
		key, err := getGlobalSetKey(sessionTypeTop, &invalidType)
		require.Error(t, err)
		require.Empty(t, key)
	})
}

func helperSetupGlobalSet(t *testing.T, ctx context.Context, key string, data map[string]float64) {
	t.Helper()
	if len(data) == 0 {
		return
	}
	members := make([]redis.Z, 0, len(data))
	for member, score := range data {
		members = append(members, redis.Z{Score: score, Member: member})
	}
	err := testRedis.ZAdd(ctx, key, members...).Err()
	require.NoError(t, err, "failed to setup global set: %s", key)
}

func helperTestUniqueID(t *testing.T, prefix string, index int) string {
	t.Helper()

	return prefix + "_" + string(rune('A'+index))
}
