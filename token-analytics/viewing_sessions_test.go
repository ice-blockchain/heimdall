// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateViewingSession(t *testing.T) {
	// NOTE: NOT parallel - sub-tests use shared global Redis keys

	t.Run("creates_new_session_for_top_tokens", func(t *testing.T) {
		ctx := t.Context()
		_ = testRedis.Del(ctx, globalTopSetKey, globalTrendingSetKey).Err()

		token1 := "30001:creator1_session:token1"
		token2 := "30001:creator2_session:token2"
		helperCreateGlobalTopSet(t, ctx, map[string]float64{
			token1: 1000.0,
			token2: 500.0,
		})

		globalCount, err := testRedis.ZCard(ctx, globalTopSetKey).Result()
		require.NoError(t, err)
		require.Equal(t, int64(2), globalCount, "global top set should have 2 tokens before CreateViewingSession")

		ta := New(ctx).(*tokenAnalytics)

		sessionID, ttlSeconds, err := ta.CreateViewingSession(ctx, "top", "192.168.1.1", "device123")
		require.NoError(t, err)
		require.NotEmpty(t, sessionID)
		require.Equal(t, uint64(defaultViewingSessionTTL.Seconds()), ttlSeconds)

		sessKey := sessionKey("top", sessionID)
		count, err := testRedis.ZCard(ctx, sessKey).Result()
		require.NoError(t, err)
		assert.Equal(t, int64(2), count, "session should contain 2 tokens")

		mapKey := userMapKey("top", "192.168.1.1:device123")
		storedSessionID, err := testRedis.Get(ctx, mapKey).Result()
		require.NoError(t, err)
		assert.Equal(t, sessionID, storedSessionID)
	})

	t.Run("creates_new_session_for_trending_tokens", func(t *testing.T) {
		ctx := t.Context()

		_ = testRedis.Del(ctx, globalTopSetKey, globalTrendingSetKey).Err()
		token3 := "30001:creator3_session:token3"
		helperCreateGlobalTrendingSet(t, ctx, map[string]float64{
			token3: 100.0,
		})

		ta := &tokenAnalytics{
			processedDataDB: testRedis,
		}

		sessionID, ttlSeconds, err := ta.CreateViewingSession(ctx, "trending", "10.0.0.1", "device456")
		require.NoError(t, err)
		require.NotEmpty(t, sessionID)
		require.Equal(t, uint64(defaultViewingSessionTTL.Seconds()), ttlSeconds)

		sessKey := sessionKey("trending", sessionID)
		count, err := testRedis.ZCard(ctx, sessKey).Result()
		require.NoError(t, err)
		assert.Equal(t, int64(1), count, "session should contain 1 token")
	})

	t.Run("replaces_old_session_for_same_user", func(t *testing.T) {
		ctx := t.Context()

		_ = testRedis.Del(ctx, globalTopSetKey, globalTrendingSetKey).Err()
		token4 := "30001:creator4_session:token4"
		helperCreateGlobalTopSet(t, ctx, map[string]float64{
			token4: 1000.0,
		})

		ta := &tokenAnalytics{
			processedDataDB: testRedis,
		}

		sessionID1, _, err := ta.CreateViewingSession(ctx, "top", "172.16.0.1", "device789")
		require.NoError(t, err)

		sessionKey1 := sessionKey("top", sessionID1)
		count1, err := testRedis.ZCard(ctx, sessionKey1).Result()
		require.NoError(t, err)
		assert.Equal(t, int64(1), count1, "first session should contain 1 token")

		sessionID2, _, err := ta.CreateViewingSession(ctx, "top", "172.16.0.1", "device789")
		require.NoError(t, err)
		assert.NotEqual(t, sessionID1, sessionID2, "should create new session ID")

		count, err := testRedis.ZCard(ctx, sessionKey1).Result()
		require.NoError(t, err)
		assert.Equal(t, int64(0), count, "old session should be deleted")

		sessionKey2 := sessionKey("top", sessionID2)
		count2, err := testRedis.ZCard(ctx, sessionKey2).Result()
		require.NoError(t, err)
		assert.Equal(t, int64(1), count2, "new session should exist and contain 1 token")
	})

	t.Run("creates_separate_sessions_for_different_device_keys", func(t *testing.T) {
		ctx := t.Context()

		_ = testRedis.Del(ctx, globalTopSetKey, globalTrendingSetKey).Err()

		token5 := "30001:creator5_session:token5"
		helperCreateGlobalTopSet(t, ctx, map[string]float64{
			token5: 1000.0,
		})

		ta := New(ctx).(*tokenAnalytics)

		sessionID1, _, err := ta.CreateViewingSession(ctx, "top", "192.168.1.100", "device_a")
		require.NoError(t, err)

		sessionID2, _, err := ta.CreateViewingSession(ctx, "top", "192.168.1.100", "device_b")
		require.NoError(t, err)

		assert.NotEqual(t, sessionID1, sessionID2, "should create different sessions for different devices")

		sessionKey1 := sessionKey("top", sessionID1)
		sessionKey2 := sessionKey("top", sessionID2)
		count1, _ := testRedis.ZCard(ctx, sessionKey1).Result()
		count2, _ := testRedis.ZCard(ctx, sessionKey2).Result()
		assert.Equal(t, int64(1), count1, "first session should contain 1 token")
		assert.Equal(t, int64(1), count2, "second session should contain 1 token")
	})
}

func TestGetTokensFromViewingSession(t *testing.T) {
	// NOTE: NOT parallel - sub-tests use shared global Redis keys
	ctx := t.Context()

	t.Run("returns_tokens_from_valid_session", func(t *testing.T) {

		helperInsertTestUser(t, ctx, testDB, "creator1", "alice", "Alice Creator", "", true)
		helperInsertTestUser(t, ctx, testDB, "creator2", "bob", "Bob Creator", "", false)

		token1IonConnect := "30001:creator1:token1"
		token2IonConnect := "30001:creator2:token2"
		helperInsertTestToken(t, ctx, testDB, "0xtoken1addr", token1IonConnect, "TK1", "30001", "creator1",
			"1000000000000000000000", 1000.0, 1.0, 10)
		helperInsertTestToken(t, ctx, testDB, "0xtoken2addr", token2IonConnect, "TK2", "30001", "creator2",
			"2000000000000000000000", 500.0, 0.5, 5)

		sessionID := "test-session-123"
		sessKey := sessionKey("top", sessionID)
		err := testRedis.ZAdd(ctx, sessKey, redis.Z{Score: 1000.0, Member: token1IonConnect}).Err()
		require.NoError(t, err)
		err = testRedis.ZAdd(ctx, sessKey, redis.Z{Score: 500.0, Member: token2IonConnect}).Err()
		require.NoError(t, err)
		err = testRedis.Expire(ctx, sessKey, defaultViewingSessionTTL).Err()
		require.NoError(t, err)

		helperCreateGlobalTrendingSet(t, ctx, map[string]float64{
			token1IonConnect: 100.0,
			token2IonConnect: 50.0,
		})

		ta := New(ctx).(*tokenAnalytics)

		tokens, err := ta.GetTokensFromViewingSession(ctx, "top", sessionID, "", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 2)

		assert.Equal(t, token1IonConnect, tokens[0].Addresses.IonConnect)
		assert.Equal(t, "alice", tokens[0].Creator.Username)
		assert.Equal(t, 1000.0, tokens[0].MarketData.MarketCap) // Score from session
		assert.Equal(t, 100.0, tokens[0].MarketData.Volume)     // From trending set
		assert.Equal(t, uint64(10), tokens[0].MarketData.Holders)

		assert.Equal(t, token2IonConnect, tokens[1].Addresses.IonConnect)
		assert.Equal(t, "bob", tokens[1].Creator.Username)
		assert.Equal(t, 500.0, tokens[1].MarketData.MarketCap)
		assert.Equal(t, 50.0, tokens[1].MarketData.Volume)
	})

	t.Run("returns_error_for_non_existent_session", func(t *testing.T) {

		ta := New(ctx).(*tokenAnalytics)

		_, err := ta.GetTokensFromViewingSession(ctx, "top", "non-existent-session", "", 10, 0)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrSessionNotFound)
	})

	t.Run("applies_limit_and_offset_correctly", func(t *testing.T) {
		helperInsertTestUser(t, ctx, testDB, "creator_limit1", "user1", "User One", "", false)
		helperInsertTestUser(t, ctx, testDB, "creator_limit2", "user2", "User Two", "", false)
		helperInsertTestUser(t, ctx, testDB, "creator_limit3", "user3", "User Three", "", false)

		token1 := "30001:creator_limit1:token1"
		token2 := "30001:creator_limit2:token2"
		token3 := "30001:creator_limit3:token3"
		helperInsertTestToken(t, ctx, testDB, "0xlimit1", token1, "L1", "30001", "creator_limit1",
			"1000000000000000000000", 300.0, 1.0, 3)
		helperInsertTestToken(t, ctx, testDB, "0xlimit2", token2, "L2", "30001", "creator_limit2",
			"1000000000000000000000", 200.0, 1.0, 2)
		helperInsertTestToken(t, ctx, testDB, "0xlimit3", token3, "L3", "30001", "creator_limit3",
			"1000000000000000000000", 100.0, 1.0, 1)

		sessionID := "test-session-pagination"
		sessKey := sessionKey("top", sessionID)
		err := testRedis.ZAdd(ctx, sessKey,
			redis.Z{Score: 300.0, Member: token1},
			redis.Z{Score: 200.0, Member: token2},
			redis.Z{Score: 100.0, Member: token3},
		).Err()
		require.NoError(t, err)
		err = testRedis.Expire(ctx, sessKey, defaultViewingSessionTTL).Err()
		require.NoError(t, err)

		helperCreateGlobalTrendingSet(t, ctx, map[string]float64{
			token1: 10.0,
			token2: 5.0,
			token3: 1.0,
		})

		ta := New(ctx).(*tokenAnalytics)

		tokens, err := ta.GetTokensFromViewingSession(ctx, "top", sessionID, "", 2, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 2)
		assert.Equal(t, token1, tokens[0].Addresses.IonConnect) // Highest score
		assert.Equal(t, token2, tokens[1].Addresses.IonConnect)

		tokens, err = ta.GetTokensFromViewingSession(ctx, "top", sessionID, "", 2, 1)
		require.NoError(t, err)
		require.Len(t, tokens, 2)
		assert.Equal(t, token2, tokens[0].Addresses.IonConnect)
		assert.Equal(t, token3, tokens[1].Addresses.IonConnect)

		tokens, err = ta.GetTokensFromViewingSession(ctx, "top", sessionID, "", 1, 2)
		require.NoError(t, err)
		require.Len(t, tokens, 1)
		assert.Equal(t, token3, tokens[0].Addresses.IonConnect)

		tokens, err = ta.GetTokensFromViewingSession(ctx, "top", sessionID, "", 10, 10)
		require.NoError(t, err)
		require.Empty(t, tokens)
	})

	t.Run("filters_tokens_by_creator_keyword", func(t *testing.T) {

		helperInsertTestUser(t, ctx, testDB, "creator_alice", "alice_crypto", "Alice Crypto", "", true)
		helperInsertTestUser(t, ctx, testDB, "creator_bob", "bob_dev", "Bob Developer", "", false)
		helperInsertTestUser(t, ctx, testDB, "creator_charlie", "charlie_trader", "Charlie Trader", "", false)

		tokenAlice := "30001:creator_alice:alice_token"
		tokenBob := "30001:creator_bob:bob_token"
		tokenCharlie := "30001:creator_charlie:charlie_token"
		helperInsertTestToken(t, ctx, testDB, "0xalice", tokenAlice, "ALI", "30001", "creator_alice",
			"1000000000000000000000", 500.0, 1.0, 5)
		helperInsertTestToken(t, ctx, testDB, "0xbob", tokenBob, "BOB", "30001", "creator_bob",
			"1000000000000000000000", 300.0, 1.0, 3)
		helperInsertTestToken(t, ctx, testDB, "0xcharlie", tokenCharlie, "CHA", "30001", "creator_charlie",
			"1000000000000000000000", 100.0, 1.0, 1)

		sessionID := "test-session-keyword"
		sessKey := sessionKey("trending", sessionID)
		err := testRedis.ZAdd(ctx, sessKey,
			redis.Z{Score: 500.0, Member: tokenAlice},
			redis.Z{Score: 300.0, Member: tokenBob},
			redis.Z{Score: 100.0, Member: tokenCharlie},
		).Err()
		require.NoError(t, err)
		err = testRedis.Expire(ctx, sessKey, defaultViewingSessionTTL).Err()
		require.NoError(t, err)

		helperCreateGlobalTopSet(t, ctx, map[string]float64{
			tokenAlice:   1000.0,
			tokenBob:     600.0,
			tokenCharlie: 200.0,
		})

		ta := New(ctx).(*tokenAnalytics)

		tokens, err := ta.GetTokensFromViewingSession(ctx, "trending", sessionID, "alice", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)
		assert.Equal(t, tokenAlice, tokens[0].Addresses.IonConnect)
		assert.Equal(t, "alice_crypto", tokens[0].Creator.Username)

		tokens, err = ta.GetTokensFromViewingSession(ctx, "trending", sessionID, "bob", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)
		assert.Equal(t, tokenBob, tokens[0].Addresses.IonConnect)

		tokens, err = ta.GetTokensFromViewingSession(ctx, "trending", sessionID, "nonexistent", 10, 0)
		require.NoError(t, err)
		require.Empty(t, tokens)
	})
}

func TestApplyPagination(t *testing.T) {
	t.Parallel()

	addresses := []string{"addr1", "addr2", "addr3", "addr4", "addr5"}

	t.Run("returns_first_page", func(t *testing.T) {
		result := applyPagination(addresses, 2, 0)
		require.Equal(t, []string{"addr1", "addr2"}, result)
	})

	t.Run("returns_second_page", func(t *testing.T) {
		result := applyPagination(addresses, 2, 2)
		require.Equal(t, []string{"addr3", "addr4"}, result)
	})

	t.Run("returns_partial_last_page", func(t *testing.T) {
		result := applyPagination(addresses, 2, 4)
		require.Equal(t, []string{"addr5"}, result)
	})

	t.Run("returns_empty_for_offset_beyond_length", func(t *testing.T) {
		result := applyPagination(addresses, 2, 10)
		require.Empty(t, result)
	})

	t.Run("returns_all_when_limit_exceeds_length", func(t *testing.T) {
		result := applyPagination(addresses, 100, 0)
		require.Equal(t, addresses, result)
	})

	t.Run("handles_empty_input", func(t *testing.T) {
		result := applyPagination([]string{}, 10, 0)
		require.Empty(t, result)
	})
}

func TestSearchTokensByCreatorLookup(t *testing.T) {
	t.Run("finds_tokens_by_creator_username", func(t *testing.T) {
		ctx := t.Context()
		cleanupAllTestData(ctx)

		helperInsertTestUser(t, ctx, testDB, "search_creator1", "satoshi_nakamoto", "Satoshi", "", true)
		helperInsertTestUser(t, ctx, testDB, "search_creator2", "vitalik_buterin", "Vitalik", "", true)

		token1 := "30001:search_creator1:btc_token"
		token2 := "30001:search_creator2:eth_token"
		helperInsertTestToken(t, ctx, testDB, "0xsearch1", token1, "BTC", "30001", "search_creator1",
			"1000000000000000000000", 1000.0, 50000.0, 100)
		helperInsertTestToken(t, ctx, testDB, "0xsearch2", token2, "ETH", "30001", "search_creator2",
			"2000000000000000000000", 500.0, 2000.0, 50)

		ta := New(ctx).(*tokenAnalytics)

		addresses, err := ta.searchTokensByCreatorLookup(ctx, "satoshi")
		require.NoError(t, err)
		require.Len(t, addresses, 1)
		assert.Equal(t, token1, addresses[0])

		addresses, err = ta.searchTokensByCreatorLookup(ctx, "vitalik")
		require.NoError(t, err)
		require.Len(t, addresses, 1)
		assert.Equal(t, token2, addresses[0])

		addresses, err = ta.searchTokensByCreatorLookup(ctx, "naka")
		require.NoError(t, err)
		require.Len(t, addresses, 1)
		assert.Equal(t, token1, addresses[0])
	})

	t.Run("returns_empty_for_no_match", func(t *testing.T) {
		ctx := t.Context()
		cleanupAllTestData(ctx)

		ta := New(ctx).(*tokenAnalytics)

		addresses, err := ta.searchTokensByCreatorLookup(ctx, "nonexistent_user_xyz")
		require.NoError(t, err)
		require.Empty(t, addresses)
	})

	t.Run("is_case_insensitive", func(t *testing.T) {
		ctx := t.Context()
		cleanupAllTestData(ctx)

		helperInsertTestUser(t, ctx, testDB, "case_creator", "CamelCaseUser", "Camel User", "", false)
		token := "30001:case_creator:case_token"
		helperInsertTestToken(t, ctx, testDB, "0xcase", token, "CASE", "30001", "case_creator",
			"1000000000000000000000", 100.0, 1.0, 1)

		ta := New(ctx).(*tokenAnalytics)

		addresses1, err := ta.searchTokensByCreatorLookup(ctx, "camelcase")
		require.NoError(t, err)
		require.Len(t, addresses1, 1)

		addresses2, err := ta.searchTokensByCreatorLookup(ctx, "CAMELCASE")
		require.NoError(t, err)
		require.Len(t, addresses2, 1)

		addresses3, err := ta.searchTokensByCreatorLookup(ctx, "CaMeLcAsE")
		require.NoError(t, err)
		require.Len(t, addresses3, 1)

		assert.Equal(t, addresses1[0], addresses2[0])
		assert.Equal(t, addresses2[0], addresses3[0])
	})
}

func TestFilterTokensBySession(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	t.Run("filters_candidates_by_session_tokens", func(t *testing.T) {
		t.Parallel()

		sessKey := sessionKey("test", "filter_session")
		err := testRedis.ZAdd(ctx, sessKey,
			redis.Z{Score: 100.0, Member: "token1"},
			redis.Z{Score: 90.0, Member: "token2"},
			redis.Z{Score: 80.0, Member: "token3"},
		).Err()
		require.NoError(t, err)
		defer testRedis.Del(ctx, sessKey)

		ta := New(ctx).(*tokenAnalytics)

		candidates := []string{"token1", "token_not_in_session", "token3", "another_missing"}
		filtered, err := ta.filterTokensBySession(ctx, sessKey, candidates)
		require.NoError(t, err)
		require.Len(t, filtered, 2)
		assert.Contains(t, filtered, "token1")
		assert.Contains(t, filtered, "token3")
		assert.NotContains(t, filtered, "token_not_in_session")
	})

	t.Run("returns_empty_when_no_candidates_match", func(t *testing.T) {
		t.Parallel()

		sessKey := sessionKey("test", "empty_filter")
		err := testRedis.ZAdd(ctx, sessKey, redis.Z{Score: 100.0, Member: "token_x"}).Err()
		require.NoError(t, err)
		defer testRedis.Del(ctx, sessKey)

		ta := New(ctx).(*tokenAnalytics)

		candidates := []string{"token_a", "token_b", "token_c"}
		filtered, err := ta.filterTokensBySession(ctx, sessKey, candidates)
		require.NoError(t, err)
		require.Empty(t, filtered)
	})

	t.Run("returns_all_candidates_when_all_match", func(t *testing.T) {
		t.Parallel()

		sessKey := sessionKey("test", "all_match")
		err := testRedis.ZAdd(ctx, sessKey,
			redis.Z{Score: 100.0, Member: "token_all1"},
			redis.Z{Score: 90.0, Member: "token_all2"},
			redis.Z{Score: 80.0, Member: "token_all3"},
		).Err()
		require.NoError(t, err)
		defer testRedis.Del(ctx, sessKey)

		ta := New(ctx).(*tokenAnalytics)

		candidates := []string{"token_all1", "token_all2", "token_all3"}
		filtered, err := ta.filterTokensBySession(ctx, sessKey, candidates)
		require.NoError(t, err)
		require.Len(t, filtered, 3)
		assert.Equal(t, candidates, filtered)
	})
}
