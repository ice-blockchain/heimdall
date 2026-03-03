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

	ta := helperNewForTest(t, db, WithoutQuestDB())

	t.Run("creates session for top type", func(t *testing.T) {
		helperSetupGlobalSet(t, ctx, ta.processedDataDB, globalTopSetKey, map[string]float64{
			"0:token1:": 1000.0,
			"0:token2:": 500.0,
		})

		sessionID, ttl, err := ta.CreateViewingSession(ctx, sessionTypeTop, "192.168.1.1", "device123", nil)
		require.NoError(t, err)
		require.NotEmpty(t, sessionID)
		require.Equal(t, uint64(300), ttl)

		sessKey := sessionKey(sessionTypeTop, sessionID)
		exists, err := ta.processedDataDB.Exists(ctx, sessKey).Result()
		require.NoError(t, err)
		require.Equal(t, int64(1), exists)
	})

	t.Run("creates session for trending type", func(t *testing.T) {
		helperSetupGlobalSet(t, ctx, ta.processedDataDB, globalTrendingSetKey, map[string]float64{
			"0:trending1:": 2000.0,
			"0:trending2:": 1500.0,
		})

		sessionID, ttl, err := ta.CreateViewingSession(ctx, sessionTypeTrending, "192.168.1.2", "device456", nil)
		require.NoError(t, err)
		require.NotEmpty(t, sessionID)
		require.Equal(t, uint64(300), ttl)
	})

	t.Run("creates session for bonding curve progress type", func(t *testing.T) {
		helperSetupGlobalSet(t, ctx, ta.processedDataDB, globalBondingCurveProgressSetKey, map[string]float64{
			"0:bonding1:": 75.0,
			"0:bonding2:": 50.0,
		})

		sessionID, ttl, err := ta.CreateViewingSession(ctx, sessionTypeBondingCurveProgress, "192.168.1.3", "device789", nil)
		require.NoError(t, err)
		require.NotEmpty(t, sessionID)
		require.Equal(t, uint64(300), ttl)
	})

	t.Run("creates session with token type filter", func(t *testing.T) {
		helperSetupGlobalSet(t, ctx, ta.processedDataDB, globalTopProfileSetKey, map[string]float64{
			"0:profile1:": 3000.0,
		})

		tokenType := TokenTypeProfile
		sessionID, ttl, err := ta.CreateViewingSession(ctx, sessionTypeTop, "192.168.1.4", "deviceABC", &tokenType)
		require.NoError(t, err)
		require.NotEmpty(t, sessionID)
		require.Equal(t, uint64(300), ttl)
	})

	t.Run("creates session for anyPost type in top", func(t *testing.T) {
		helperSetupGlobalSet(t, ctx, ta.processedDataDB, globalTopAnyPostSetKey, map[string]float64{
			"30175:anypost1:content": 5000.0,
			"30023:anypost2:content": 4000.0,
		})

		tokenType := TokenTypeAnyPost
		sessionID, ttl, err := ta.CreateViewingSession(ctx, sessionTypeTop, "192.168.1.10", "deviceAnyPost1", &tokenType)
		require.NoError(t, err)
		require.NotEmpty(t, sessionID)
		require.Equal(t, uint64(300), ttl)

		sessKey := sessionKey(sessionTypeTop, sessionID)
		exists, err := ta.processedDataDB.Exists(ctx, sessKey).Result()
		require.NoError(t, err)
		require.Equal(t, int64(1), exists)
	})

	t.Run("creates session for anyPost type in trending", func(t *testing.T) {
		helperSetupGlobalSet(t, ctx, ta.processedDataDB, globalTrendingAnyPostSetKey, map[string]float64{
			"30175:trendpost1:content": 10000.0,
			"30023:trendpost2:content": 8000.0,
		})

		tokenType := TokenTypeAnyPost
		sessionID, ttl, err := ta.CreateViewingSession(ctx, sessionTypeTrending, "192.168.1.11", "deviceAnyPost2", &tokenType)
		require.NoError(t, err)
		require.NotEmpty(t, sessionID)
		require.Equal(t, uint64(300), ttl)
	})

	t.Run("creates session for anyPost type in bonding curve progress", func(t *testing.T) {
		helperSetupGlobalSet(t, ctx, ta.processedDataDB, globalBondingCurveProgressAnyPostSetKey, map[string]float64{
			"30175:bcpost1:content": 85.0,
			"30023:bcpost2:content": 60.0,
		})

		tokenType := TokenTypeAnyPost
		sessionID, ttl, err := ta.CreateViewingSession(ctx, sessionTypeBondingCurveProgress, "192.168.1.12", "deviceAnyPost3", &tokenType)
		require.NoError(t, err)
		require.NotEmpty(t, sessionID)
		require.Equal(t, uint64(300), ttl)
	})

	t.Run("replaces existing session for same user", func(t *testing.T) {
		helperSetupGlobalSet(t, ctx, ta.processedDataDB, globalTopSetKey, map[string]float64{
			"0:token1:": 1000.0,
		})

		sessionID1, _, err := ta.CreateViewingSession(ctx, sessionTypeTop, "192.168.1.5", "deviceXYZ", nil)
		require.NoError(t, err)

		sessionID2, _, err := ta.CreateViewingSession(ctx, sessionTypeTop, "192.168.1.5", "deviceXYZ", nil)
		require.NoError(t, err)

		require.NotEqual(t, sessionID1, sessionID2)

		// Old session should be deleted
		sessKey1 := sessionKey(sessionTypeTop, sessionID1)
		exists, err := ta.processedDataDB.Exists(ctx, sessKey1).Result()
		require.NoError(t, err)
		require.Equal(t, int64(0), exists)
	})
}

func TestGetTokensFromViewingSession(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()

	ta := helperNewForTest(t, db, WithoutQuestDB())

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
		helperUpdateTokenBondingCurve(t, ctx, db,
			"0:vs_creator1:",
			"90000000000000000000000",  // 90k tokens current
			"180000000000000000000000", // 180k tokens goal
			180.0,                      // $180 USD current
			360.0,                      // $360 USD goal
			"150000000000000000000",    // 150 tokens raised (wei)
			false,                      // not migrated
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
		helperSetupGlobalSet(t, ctx, ta.processedDataDB, globalTopSetKey, map[string]float64{
			"0:vs_creator1:": 500.0,
			"0:vs_creator2:": 300.0,
		})
		helperSetupGlobalSet(t, ctx, ta.processedDataDB, globalTrendingSetKey, map[string]float64{
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
		require.Equal(t, "0xVS111111111111111111111111111111111111", tokens[0].Addresses.Blockchain)

		require.Equal(t, "vs_alice", strVal(tokens[0].Creator.Username))
		require.Equal(t, "VS Alice", strVal(tokens[0].Creator.Display))
		require.True(t, tokens[0].Creator.Verified != nil && *tokens[0].Creator.Verified)
		require.NotEmpty(t, tokens[0].Creator.Avatar)

		require.NotNil(t, tokens[0].Creator.Addresses)
		require.Equal(t, "vs_creator1", tokens[0].Creator.Addresses.IonConnect)
		require.Empty(t, tokens[0].Creator.Addresses.Twitter)
		require.Equal(t, "0x00000000000000000000000000000vs_creator1", tokens[0].Creator.Addresses.Blockchain)
		require.Nil(t, tokens[0].Creator.Token, "Profile token should not have creator.token")

		require.InDelta(t, 500.0, tokens[0].MarketData.MarketCap, 1.0, "Market cap from Redis top set")
		require.InDelta(t, 1000.0, tokens[0].MarketData.Volume, 1.0, "Volume from trending set")
		require.Equal(t, uint64(10), tokens[0].MarketData.Holders)
		require.InDelta(t, 0.001, tokens[0].MarketData.PriceUSD, 0.0001)

		require.NotNil(t, tokens[0].MarketData.BondingCurveProgress)
		require.Equal(t, "90000000000000000000000", tokens[0].MarketData.BondingCurveProgress.CurrentAmount)
		require.Equal(t, "180000000000000000000000", tokens[0].MarketData.BondingCurveProgress.GoalAmount)
		require.InDelta(t, 180.0, tokens[0].MarketData.BondingCurveProgress.CurrentAmountUSD, 0.01)
		require.InDelta(t, 360.0, tokens[0].MarketData.BondingCurveProgress.GoalAmountUSD, 0.01)

		require.Equal(t, "profile", tokens[1].Type)
		require.Equal(t, "vs_bob", tokens[1].Title)
		require.Equal(t, "vs_bob", strVal(tokens[1].Creator.Username))
		require.Equal(t, "VS Bob", strVal(tokens[1].Creator.Display))
		require.True(t, tokens[1].Creator.Verified == nil || !*tokens[1].Creator.Verified)
		require.Nil(t, tokens[1].Creator.Token, "Profile token should not have creator.token")
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

		helperSetupGlobalSet(t, ctx, ta.processedDataDB, globalTopSetKey, map[string]float64{
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
		_ = ta.processedDataDB.Del(ctx, globalTopSetKey, globalTrendingSetKey).Err()

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

		helperSetupGlobalSet(t, ctx, ta.processedDataDB, globalTopSetKey, map[string]float64{
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
		require.Equal(t, 2, len(tokens1), "Expected 2 tokens in first page")

		tokens2, err := ta.GetTokensFromViewingSession(ctx, sessionTypeTop, sessionID, "", 2, 2)
		require.NoError(t, err)
		require.Equal(t, 2, len(tokens2), "Expected 2 tokens in second page")
	})

	t.Run("anyPost session returns only non-profile tokens", func(t *testing.T) {
		_ = ta.processedDataDB.Del(ctx, globalTopAnyPostSetKey, globalTrendingAnyPostSetKey).Err()

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
			"0xAPPOSTPROFILE11111111111111111111111111",
			"0:anypost_post_creator:",
			"APPPROF",
			"profile",
			"anypost_post_creator",
			"500000000000000000000000",
			50.0,
			0.00005,
			2,
			PlatformGroupIonConnect,
		)
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
		helperSetTokenBaseToken(t, ctx, db, "30175:anypost_post_id:content", "0xAPPOSTPROFILE11111111111111111111111111")

		helperInsertTestUser(t, ctx, db, "anypost_video_creator", "anypost_video_user", "AnyPost Video User", "", false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db,
			"0xAPVIDPROFILE11111111111111111111111111",
			"0:anypost_video_creator:",
			"APVPROF",
			"profile",
			"anypost_video_creator",
			"600000000000000000000000",
			60.0,
			0.00006,
			3,
			PlatformGroupIonConnect,
		)
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
		helperSetTokenBaseToken(t, ctx, db, "30175:anypost_video_id:content", "0xAPVIDPROFILE11111111111111111111111111")

		helperInsertTestUser(t, ctx, db, "anypost_article_creator", "anypost_article_user", "AnyPost Article User", "", false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db,
			"0xAPARTPROFILE1111111111111111111111111",
			"0:anypost_article_creator:",
			"APARTPROF",
			"profile",
			"anypost_article_creator",
			"700000000000000000000000",
			70.0,
			0.00007,
			4,
			PlatformGroupIonConnect,
		)
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
		helperSetTokenBaseToken(t, ctx, db, "30023:anypost_article_id:content", "0xAPARTPROFILE1111111111111111111111111")

		helperSetupGlobalSet(t, ctx, ta.processedDataDB, globalTopAnyPostSetKey, map[string]float64{
			"30175:anypost_post_id:content":    2000.0,
			"30175:anypost_video_id:content":   3000.0,
			"30023:anypost_article_id:content": 4000.0,
		})

		helperSetupGlobalSet(t, ctx, ta.processedDataDB, globalTrendingAnyPostSetKey, map[string]float64{
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
			require.NotNil(t, token.Creator.Token, "Content token (%s) should have creator.token", token.Type)
			require.NotEmpty(t, token.Creator.Token.Ticker, "Creator token ticker should not be empty")
			require.NotNil(t, token.Creator.Token.Addresses, "Creator token addresses should not be nil")
			require.NotEmpty(t, token.Creator.Token.Addresses.Blockchain, "Creator token blockchain address should not be empty")
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
		_ = ta.processedDataDB.Del(ctx, globalTrendingAnyPostSetKey, globalTopAnyPostSetKey).Err()

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

		helperSetupGlobalSet(t, ctx, ta.processedDataDB, globalTrendingAnyPostSetKey, map[string]float64{
			"30175:trend_post_id:content": 8000.0 * 1e18, // Volume
		})

		helperSetupGlobalSet(t, ctx, ta.processedDataDB, globalTopAnyPostSetKey, map[string]float64{
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

func TestCreateViewingSessionWithEmptyGlobalSet(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()

	ta := helperNewForTest(t, db, WithoutQuestDB())

	t.Run("creates_and_retrieves_session_with_empty_xcom_top_set", func(t *testing.T) {
		_ = ta.processedDataDB.Del(ctx, globalTopXcomSetKey, globalTrendingXcomSetKey).Err()

		tokenType := TokenTypeXcom
		sessionID, ttl, err := ta.CreateViewingSession(ctx, sessionTypeTop, "192.168.20.1", "device_empty_xcom", &tokenType)
		require.NoError(t, err)
		require.NotEmpty(t, sessionID)
		require.Equal(t, uint64(300), ttl)

		tokens, err := ta.GetTokensFromViewingSession(ctx, sessionTypeTop, sessionID, "", 10, 0)
		require.NoError(t, err)
		require.Empty(t, tokens, "Should return empty array, not error")
	})

	t.Run("creates_and_retrieves_session_with_empty_global_top_set", func(t *testing.T) {
		_ = ta.processedDataDB.Del(ctx, globalTopSetKey, globalTrendingSetKey).Err()

		sessionID, ttl, err := ta.CreateViewingSession(ctx, sessionTypeTop, "192.168.20.2", "device_empty_global", nil)
		require.NoError(t, err)
		require.NotEmpty(t, sessionID)
		require.Equal(t, uint64(300), ttl)

		tokens, err := ta.GetTokensFromViewingSession(ctx, sessionTypeTop, sessionID, "", 10, 0)
		require.NoError(t, err)
		require.Empty(t, tokens, "Should return empty array, not error")
	})
}

func TestViewingSessionsXcomSupport(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()

	ta := helperNewForTest(t, db, WithoutQuestDB())

	t.Run("creates_and_retrieves_xcom_session_for_top", func(t *testing.T) {
		_ = ta.processedDataDB.Del(ctx, globalTopXcomSetKey, globalTrendingXcomSetKey).Err()

		helperInsertTestUser(t, ctx, db, "xcom_top_creator", "xcom_top", "XCom Top", "", true, PlatformGroupXCom)
		helperInsertTestToken(t, ctx, db,
			"0xXCOMTOP11111111111111111111111111111111",
			"xcom_top_token",
			"XTOP",
			TokenTypeProfile,
			"xcom_top_creator",
			"1000000000000000000000000",
			500.0,
			0.001,
			10,
			PlatformGroupXCom,
		)

		helperSetupGlobalSet(t, ctx, ta.processedDataDB, globalTopXcomSetKey, map[string]float64{
			"xcom_top_token": 500.0,
		})
		helperSetupGlobalSet(t, ctx, ta.processedDataDB, globalTrendingXcomSetKey, map[string]float64{
			"xcom_top_token": 1000.0 * 1e18,
		})

		tokenType := TokenTypeXcom
		sessionID, ttl, err := ta.CreateViewingSession(ctx, sessionTypeTop, "192.168.10.1", "device_xcom_top", &tokenType)
		require.NoError(t, err)
		require.NotEmpty(t, sessionID)
		require.Equal(t, uint64(300), ttl)

		tokens, err := ta.GetTokensFromViewingSession(ctx, sessionTypeTop, sessionID, "", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		require.Equal(t, "profile", tokens[0].Type)
		require.Equal(t, "xcom_top", tokens[0].Title)
		require.InDelta(t, 500.0, tokens[0].MarketData.MarketCap, 1.0, "Market cap from xcom top set")
		require.InDelta(t, 1000.0, tokens[0].MarketData.Volume, 1.0, "Volume from xcom trending set")
	})

	t.Run("creates_and_retrieves_xcom_session_for_trending", func(t *testing.T) {
		_ = ta.processedDataDB.Del(ctx, globalTrendingXcomSetKey, globalTopXcomSetKey).Err()

		helperInsertTestUser(t, ctx, db, "xcom_trend_creator", "xcom_trend", "XCom Trend", "", false, PlatformGroupXCom)
		helperInsertTestToken(t, ctx, db,
			"0xXCOMTREND1111111111111111111111111111111",
			"xcom_trend_token",
			"XTREND",
			TokenTypeProfile,
			"xcom_trend_creator",
			"2000000000000000000000000",
			300.0,
			0.002,
			5,
			PlatformGroupXCom,
		)

		helperSetupGlobalSet(t, ctx, ta.processedDataDB, globalTrendingXcomSetKey, map[string]float64{
			"xcom_trend_token": 2000.0 * 1e18,
		})
		helperSetupGlobalSet(t, ctx, ta.processedDataDB, globalTopXcomSetKey, map[string]float64{
			"xcom_trend_token": 300.0,
		})

		tokenType := TokenTypeXcom
		sessionID, ttl, err := ta.CreateViewingSession(ctx, sessionTypeTrending, "192.168.10.2", "device_xcom_trend", &tokenType)
		require.NoError(t, err)
		require.NotEmpty(t, sessionID)
		require.Equal(t, uint64(300), ttl)

		tokens, err := ta.GetTokensFromViewingSession(ctx, sessionTypeTrending, sessionID, "", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		require.InDelta(t, 2000.0, tokens[0].MarketData.Volume, 1.0, "Volume from xcom trending set")
		require.InDelta(t, 300.0, tokens[0].MarketData.MarketCap, 1.0, "Market cap from xcom top set")
	})

	t.Run("creates_and_retrieves_xcom_session_for_bonding_curve", func(t *testing.T) {
		_ = ta.processedDataDB.Del(ctx, globalBondingCurveProgressXcomSetKey, globalTrendingXcomSetKey).Err()

		helperInsertTestUser(t, ctx, db, "xcom_bc_creator", "xcom_bc", "XCom BC", "", false, PlatformGroupXCom)
		helperInsertTestToken(t, ctx, db,
			"0xXCOMBC111111111111111111111111111111111",
			"xcom_bc_token",
			"XBC",
			TokenTypeProfile,
			"xcom_bc_creator",
			"3000000000000000000000000",
			200.0,
			0.003,
			8,
			PlatformGroupXCom,
		)

		helperUpdateTokenBondingCurve(t, ctx, db, "xcom_bc_token",
			"90000000000000000000", "200000000000000000000",
			1.5, 3.5, "12000000000000000000", false)

		helperSetupGlobalSet(t, ctx, ta.processedDataDB, globalBondingCurveProgressXcomSetKey, map[string]float64{
			"xcom_bc_token": 90000000000000000000.0,
		})
		helperSetupGlobalSet(t, ctx, ta.processedDataDB, globalTrendingXcomSetKey, map[string]float64{
			"xcom_bc_token": 1500.0 * 1e18,
		})

		tokenType := TokenTypeXcom
		sessionID, ttl, err := ta.CreateViewingSession(ctx, sessionTypeBondingCurveProgress, "192.168.10.3", "device_xcom_bc", &tokenType)
		require.NoError(t, err)
		require.NotEmpty(t, sessionID)
		require.Equal(t, uint64(300), ttl)

		tokens, err := ta.GetTokensFromViewingSession(ctx, sessionTypeBondingCurveProgress, sessionID, "", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		require.NotNil(t, tokens[0].MarketData.BondingCurveProgress)
		require.Equal(t, "90000000000000000000", tokens[0].MarketData.BondingCurveProgress.CurrentAmount)
		require.InDelta(t, 1500.0, tokens[0].MarketData.Volume, 1.0, "Volume from xcom trending set")
	})

	t.Run("xcom_session_does_not_mix_with_ionconnect", func(t *testing.T) {
		_ = ta.processedDataDB.Del(ctx, globalTopXcomSetKey, globalTopProfileSetKey, globalTopSetKey).Err()

		helperInsertTestUser(t, ctx, db, "xcom_mix_creator", "xcom_mix", "XCom Mix", "", true, PlatformGroupXCom)
		helperInsertTestToken(t, ctx, db,
			"0xXCOMMIX11111111111111111111111111111111",
			"xcom_mix_token",
			"XMIX",
			TokenTypeProfile,
			"xcom_mix_creator",
			"1000000000000000000000000",
			1000.0,
			0.01,
			10,
			PlatformGroupXCom,
		)

		helperInsertTestUser(t, ctx, db, "ion_mix_creator", "ion_mix", "Ion Mix", "", true, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db,
			"0xIONMIX111111111111111111111111111111111",
			"0:ion_mix_creator:",
			"IMIX",
			TokenTypeProfile,
			"ion_mix_creator",
			"2000000000000000000000000",
			2000.0,
			0.02,
			20,
			PlatformGroupIonConnect,
		)

		helperSetupGlobalSet(t, ctx, ta.processedDataDB, globalTopXcomSetKey, map[string]float64{
			"xcom_mix_token": 1000.0,
		})
		helperSetupGlobalSet(t, ctx, ta.processedDataDB, globalTopProfileSetKey, map[string]float64{
			"0:ion_mix_creator:": 2000.0,
		})

		tokenTypeXcom := TokenTypeXcom
		xcomSessionID, _, err := ta.CreateViewingSession(ctx, sessionTypeTop, "192.168.11.1", "device_xcom_mix", &tokenTypeXcom)
		require.NoError(t, err)

		xcomTokens, err := ta.GetTokensFromViewingSession(ctx, sessionTypeTop, xcomSessionID, "", 10, 0)
		require.NoError(t, err)
		require.Len(t, xcomTokens, 1, "Xcom session should only contain xcom tokens")
		require.Equal(t, "xcom_mix", xcomTokens[0].Title)

		tokenTypeProfile := TokenTypeProfile
		profileSessionID, _, err := ta.CreateViewingSession(ctx, sessionTypeTop, "192.168.11.2", "device_profile_mix", &tokenTypeProfile)
		require.NoError(t, err)

		profileTokens, err := ta.GetTokensFromViewingSession(ctx, sessionTypeTop, profileSessionID, "", 10, 0)
		require.NoError(t, err)
		require.Len(t, profileTokens, 1, "Profile session should only contain ionconnect profile tokens")
		require.Equal(t, "ion_mix", profileTokens[0].Title)
	})
}

func helperSetupGlobalSet(t *testing.T, ctx context.Context, rdb redis.Cmdable, key string, data map[string]float64) {
	t.Helper()
	if len(data) == 0 {
		return
	}
	members := make([]redis.Z, 0, len(data))
	for member, score := range data {
		members = append(members, redis.Z{Score: score, Member: member})
	}
	err := rdb.ZAdd(ctx, key, members...).Err()
	require.NoError(t, err, "failed to setup global set: %s", key)
}

func helperTestUniqueID(t *testing.T, prefix string, index int) string {
	t.Helper()

	return prefix + "_" + string(rune('A'+index))
}
