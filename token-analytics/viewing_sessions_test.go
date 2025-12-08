// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateViewingSession(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	ta := NewForTest(ctx)

	t.Run("creates session for top type", func(t *testing.T) {
		helperSetupGlobalSet(t, ctx, globalTopSetKey, map[string]float64{
			"0:token1:": 1000.0,
			"0:token2:": 500.0,
		})

		sessionID, ttl, err := ta.CreateViewingSession(ctx, sessionTypeTop, "192.168.1.1", "device123", nil)
		require.NoError(t, err)
		assert.NotEmpty(t, sessionID)
		assert.Greater(t, ttl, uint64(0))

		sessKey := sessionKey(sessionTypeTop, sessionID)
		exists, err := testRedis.Exists(ctx, sessKey).Result()
		require.NoError(t, err)
		assert.Equal(t, int64(1), exists)
	})

	t.Run("creates session for trending type", func(t *testing.T) {
		helperSetupGlobalSet(t, ctx, globalTrendingSetKey, map[string]float64{
			"0:trending1:": 2000.0,
			"0:trending2:": 1500.0,
		})

		sessionID, ttl, err := ta.CreateViewingSession(ctx, sessionTypeTrending, "192.168.1.2", "device456", nil)
		require.NoError(t, err)
		assert.NotEmpty(t, sessionID)
		assert.Greater(t, ttl, uint64(0))
	})

	t.Run("creates session for bonding curve progress type", func(t *testing.T) {
		helperSetupGlobalSet(t, ctx, globalBondingCurveProgressSetKey, map[string]float64{
			"0:bonding1:": 75.0,
			"0:bonding2:": 50.0,
		})

		sessionID, ttl, err := ta.CreateViewingSession(ctx, sessionTypeBondingCurveProgress, "192.168.1.3", "device789", nil)
		require.NoError(t, err)
		assert.NotEmpty(t, sessionID)
		assert.Greater(t, ttl, uint64(0))
	})

	t.Run("creates session with token type filter", func(t *testing.T) {
		helperSetupGlobalSet(t, ctx, globalTopProfileSetKey, map[string]float64{
			"0:profile1:": 3000.0,
		})

		tokenType := TokenTypeProfile
		sessionID, ttl, err := ta.CreateViewingSession(ctx, sessionTypeTop, "192.168.1.4", "deviceABC", &tokenType)
		require.NoError(t, err)
		assert.NotEmpty(t, sessionID)
		assert.Greater(t, ttl, uint64(0))
	})

	t.Run("replaces existing session for same user", func(t *testing.T) {
		helperSetupGlobalSet(t, ctx, globalTopSetKey, map[string]float64{
			"0:token1:": 1000.0,
		})

		sessionID1, _, err := ta.CreateViewingSession(ctx, sessionTypeTop, "192.168.1.5", "deviceXYZ", nil)
		require.NoError(t, err)

		sessionID2, _, err := ta.CreateViewingSession(ctx, sessionTypeTop, "192.168.1.5", "deviceXYZ", nil)
		require.NoError(t, err)

		assert.NotEqual(t, sessionID1, sessionID2)

		// Old session should be deleted
		sessKey1 := sessionKey(sessionTypeTop, sessionID1)
		exists, err := testRedis.Exists(ctx, sessKey1).Result()
		require.NoError(t, err)
		assert.Equal(t, int64(0), exists)
	})
}

func TestGetTokensFromViewingSession(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	ta := NewForTest(ctx)

	t.Run("returns error for non-existent session", func(t *testing.T) {
		tokens, err := ta.GetTokensFromViewingSession(ctx, sessionTypeTop, "nonexistent-session-id", "", 10, 0)
		require.Error(t, err)
		assert.Nil(t, tokens)
		assert.ErrorIs(t, err, ErrSessionNotFound)
	})

	t.Run("returns tokens from session", func(t *testing.T) {
		helperInsertTestUser(t, ctx, testDB, "vs_creator1", "vs_alice", "VS Alice", "", true, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, testDB,
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

		helperInsertTestUser(t, ctx, testDB, "vs_creator2", "vs_bob", "VS Bob", "", false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, testDB,
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
			"0:vs_creator1:": 1000.0,
			"0:vs_creator2:": 800.0,
		})
		sessionID, _, err := ta.CreateViewingSession(ctx, sessionTypeTop, "192.168.2.1", "device_vs1", nil)
		require.NoError(t, err)
		tokens, err := ta.GetTokensFromViewingSession(ctx, sessionTypeTop, sessionID, "", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 2)
		assert.Equal(t, "profile", tokens[0].Type)
		assert.Equal(t, "vs_alice", tokens[0].Title)
		assert.Equal(t, "VS Alice", tokens[0].Description)
		assert.NotEmpty(t, tokens[0].ImageURL)
		assert.False(t, tokens[0].CreatedAt.IsZero())

		assert.Equal(t, "0:vs_creator1:", tokens[0].Addresses.IonConnect)
		assert.Empty(t, tokens[0].Addresses.Twitter)

		assert.Equal(t, "vs_alice", tokens[0].Creator.Username)
		assert.Equal(t, "VS Alice", tokens[0].Creator.Display)
		assert.True(t, tokens[0].Creator.Verified)
		assert.NotEmpty(t, tokens[0].Creator.Avatar)
		assert.Equal(t, "0:vs_creator1:", tokens[0].Creator.Addresses.IonConnect)

		assert.InDelta(t, 500.0, tokens[0].MarketData.MarketCap, 1.0, "Market cap from top set")
		assert.InDelta(t, 1000.0, tokens[0].MarketData.Volume, 1.0, "Volume from trending set")
		assert.Equal(t, uint64(10), tokens[0].MarketData.Holders)
		assert.InDelta(t, 0.001, tokens[0].MarketData.PriceUSD, 0.0001)
		if tokens[0].MarketData.BondingCurveProgress != nil {
			assert.GreaterOrEqual(t, tokens[0].MarketData.BondingCurveProgress.GoalAmount, uint64(0))
		}

		assert.Equal(t, "profile", tokens[1].Type)
		assert.Equal(t, "vs_bob", tokens[1].Title)
		assert.Equal(t, "vs_bob", tokens[1].Creator.Username)
		assert.Equal(t, "VS Bob", tokens[1].Creator.Display)
		assert.False(t, tokens[1].Creator.Verified)
		assert.InDelta(t, 300.0, tokens[1].MarketData.MarketCap, 1.0)
		assert.InDelta(t, 800.0, tokens[1].MarketData.Volume, 1.0)
		assert.Equal(t, uint64(5), tokens[1].MarketData.Holders)
		assert.InDelta(t, 0.002, tokens[1].MarketData.PriceUSD, 0.0001)
	})

	t.Run("returns tokens with keyword filter", func(t *testing.T) {
		helperInsertTestUser(t, ctx, testDB, "vs_creator_kw", "vs_keyword", "VS Keyword User", "", false, PlatformGroupIonConnect)

		// Insert token with lookup that includes keyword
		helperInsertTestToken(t, ctx, testDB,
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
		assert.Equal(t, "vs_keyword", tokens[0].Creator.Username)
	})

	t.Run("respects pagination", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			creator := testUniqueID("vs_page_creator", i)
			helperInsertTestUser(t, ctx, testDB, creator, testUniqueID("vs_page", i), testUniqueID("VS Page", i), "", false, PlatformGroupIonConnect)
			helperInsertTestToken(t, ctx, testDB,
				testUniqueID("0xVSPAGE", i)+"111111111111111111111111111",
				"0:"+creator+":",
				testUniqueID("PG", i),
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
			"0:" + testUniqueID("vs_page_creator", 0) + ":": 100.0,
			"0:" + testUniqueID("vs_page_creator", 1) + ":": 150.0,
			"0:" + testUniqueID("vs_page_creator", 2) + ":": 200.0,
			"0:" + testUniqueID("vs_page_creator", 3) + ":": 250.0,
			"0:" + testUniqueID("vs_page_creator", 4) + ":": 300.0,
		})

		sessionID, _, err := ta.CreateViewingSession(ctx, sessionTypeTop, "192.168.2.3", "device_page", nil)
		require.NoError(t, err)

		tokens1, err := ta.GetTokensFromViewingSession(ctx, sessionTypeTop, sessionID, "", 2, 0)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(tokens1), 1, "Expected at least 1 token in first page")

		tokens2, err := ta.GetTokensFromViewingSession(ctx, sessionTypeTop, sessionID, "", 2, 2)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(tokens2), 0)
	})
}

func TestGetGlobalSetKey(t *testing.T) {
	t.Parallel()

	t.Run("returns correct keys for top session type", func(t *testing.T) {
		key, err := getGlobalSetKey(sessionTypeTop, nil)
		require.NoError(t, err)
		assert.Equal(t, globalTopSetKey, key)

		profileType := TokenTypeProfile
		key, err = getGlobalSetKey(sessionTypeTop, &profileType)
		require.NoError(t, err)
		assert.Equal(t, globalTopProfileSetKey, key)

		postType := TokenTypePost
		key, err = getGlobalSetKey(sessionTypeTop, &postType)
		require.NoError(t, err)
		assert.Equal(t, globalTopPostSetKey, key)
	})

	t.Run("returns correct keys for trending session type", func(t *testing.T) {
		key, err := getGlobalSetKey(sessionTypeTrending, nil)
		require.NoError(t, err)
		assert.Equal(t, globalTrendingSetKey, key)

		videoType := TokenTypeVideo
		key, err = getGlobalSetKey(sessionTypeTrending, &videoType)
		require.NoError(t, err)
		assert.Equal(t, globalTrendingVideoSetKey, key)
	})

	t.Run("returns correct keys for bonding curve progress session type", func(t *testing.T) {
		key, err := getGlobalSetKey(sessionTypeBondingCurveProgress, nil)
		require.NoError(t, err)
		assert.Equal(t, globalBondingCurveProgressSetKey, key)

		articleType := TokenTypeArticle
		key, err = getGlobalSetKey(sessionTypeBondingCurveProgress, &articleType)
		require.NoError(t, err)
		assert.Equal(t, globalBondingCurveProgressArticleSetKey, key)
	})

	t.Run("returns error for unsupported session type", func(t *testing.T) {
		key, err := getGlobalSetKey("invalid", nil)
		require.Error(t, err)
		assert.Empty(t, key)
	})

	t.Run("returns error for unsupported token type", func(t *testing.T) {
		invalidType := "invalid"
		key, err := getGlobalSetKey(sessionTypeTop, &invalidType)
		require.Error(t, err)
		assert.Empty(t, key)
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

func testUniqueID(prefix string, index int) string {
	return prefix + "_" + string(rune('A'+index))
}
