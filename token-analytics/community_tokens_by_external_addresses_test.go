// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	storagev3 "github.com/ice-blockchain/wintr/connectors/storage/v3"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCommunityTokensByExternalAddresses(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	ta := NewForTest(ctx)

	t.Run("empty addresses returns empty result", func(t *testing.T) {
		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{}, "requestor123", nil, "", 0, 0)
		require.NoError(t, err)
		assert.Empty(t, tokens)
	})

	t.Run("non-existent addresses returns empty result", func(t *testing.T) {
		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{"0:nonexistent:"}, "requestor123", nil, "", 0, 0)
		require.NoError(t, err)
		assert.Empty(t, tokens)
	})

	t.Run("fetch tokens with basic data", func(t *testing.T) {
		helperInsertTestUser(t, ctx, testDB, "creator_basic", "alice_basic", "Alice Basic", "", true, PlatformGroupIonConnect, "https://avatar1.png")
		helperInsertTestUser(t, ctx, testDB, "requestor_basic", "charlie_basic", "Charlie Basic", "", false, PlatformGroupIonConnect)

		token1Ext := "0:creator_basic:"
		helperInsertTestToken(t, ctx, testDB,
			"0xBASIC1111111111111111111111111111111111",
			token1Ext,
			"BASIC1",
			"profile",
			"creator_basic",
			"1000000000000000000000000",
			100.5,
			0.0001,
			5,
			PlatformGroupIonConnect,
		)

		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{token1Ext}, "requestor_basic", nil, "", 0, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		token := tokens[0]
		assert.Equal(t, "profile", token.Type)
		assert.Equal(t, "alice_basic", token.Title)
		assert.Equal(t, "Alice Basic", token.Description)
		assert.Equal(t, "https://avatar1.png", token.ImageURL)
		if !token.CreatedAt.IsZero() {
			assert.True(t, token.CreatedAt.Before(time.Now().Add(time.Second)))
		}
		assert.Equal(t, token1Ext, token.Addresses.IonConnect)
		assert.Empty(t, token.Addresses.Twitter)

		assert.Equal(t, "alice_basic", token.Creator.Username)
		assert.Equal(t, "Alice Basic", token.Creator.Display)
		assert.Equal(t, "https://avatar1.png", token.Creator.Avatar)
		assert.True(t, token.Creator.Verified)
		assert.Equal(t, token1Ext, token.Creator.Addresses.IonConnect)
		assert.Empty(t, token.Creator.Addresses.Twitter)

		assert.Equal(t, "BASIC1", token.MarketData.Ticker)
		assert.InDelta(t, 100.5, token.MarketData.MarketCap, 0.01)
		assert.GreaterOrEqual(t, token.MarketData.Volume, 0.0)
		assert.InDelta(t, 0.0001, token.MarketData.PriceUSD, 0.00001)
		assert.Equal(t, uint64(5), token.MarketData.Holders)
		assert.Equal(t, uint64(0), token.MarketData.PlatformHolders)
		assert.Nil(t, token.MarketData.BondingCurveProgress)
		assert.Empty(t, token.MarketData.TopPlatformHolders)

		// non-holder position should be zero
		assert.Equal(t, uint64(0), token.MarketData.Position.Rank)
		assert.Equal(t, uint64(0), token.MarketData.Position.Amount)
		assert.Equal(t, 0.0, token.MarketData.Position.AmountUSD)
		assert.Equal(t, 0.0, token.MarketData.Position.PnL)
		assert.Equal(t, 0.0, token.MarketData.Position.PnLPercentage)
	})

	t.Run("fetch tokens with user position", func(t *testing.T) {
		helperInsertTestUser(t, ctx, testDB, "creator_pos", "alice_pos", "Alice Pos", "", true, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, testDB, "requestor_pos", "charlie_pos", "Charlie Pos", "", false, PlatformGroupIonConnect)

		tokenExt := "0:creator_pos:"
		helperInsertTestToken(t, ctx, testDB,
			"0xPOS11111111111111111111111111111111111",
			tokenExt,
			"POS1",
			"profile",
			"creator_pos",
			"1000000000000000000000000",
			100.0,
			0.0001,
			4,
			PlatformGroupIonConnect,
		)
		helperInsertUserTokenPosition(t, ctx, testDB,
			"requestor_pos",
			"0xPOS11111111111111111111111111111111111",
			tokenExt,
			"0:requestor_pos:",
			"3500000000000000000000", // 3500 tokens in wei (3500 * 1e18,
			0.0001,
			0.315,
		)
		helperCreateSwapForVolume(t, ctx, testDB,
			"0xPOS11111111111111111111111111111111111",
			tokenExt,
			"0x0000000000000000000000000000000000000001",
			false,
			"100000000000000000000",  // 100 ION
			"1000000000000000000000", // 1000 tokens
			0.0001,
		)
		helperRefreshVolumeView(t, ctx, testDB)

		helperSetupRedisPositionData(t, ctx, testRedis, tokenExt, map[string]float64{
			"0:top1:":          5000.0,
			"0:top2:":          4000.0,
			"0:requestor_pos:": 3500.0,
			"0:other:":         2000.0,
		})

		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{tokenExt}, "requestor_pos", nil, "", 0, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		token := tokens[0]

		assert.Equal(t, "profile", token.Type)
		assert.Equal(t, "alice_pos", token.Title)
		assert.Equal(t, "Alice Pos", token.Description)
		if !token.CreatedAt.IsZero() {
			assert.True(t, token.CreatedAt.Before(time.Now().Add(time.Second)))
		}

		assert.Equal(t, tokenExt, token.Addresses.IonConnect)
		assert.Empty(t, token.Addresses.Twitter)

		assert.Equal(t, "alice_pos", token.Creator.Username)
		assert.Equal(t, "Alice Pos", token.Creator.Display)
		assert.True(t, token.Creator.Verified)
		assert.Equal(t, tokenExt, token.Creator.Addresses.IonConnect)

		assert.Equal(t, "POS1", token.MarketData.Ticker)
		assert.InDelta(t, 100.0, token.MarketData.MarketCap, 0.01)
		assert.GreaterOrEqual(t, token.MarketData.Volume, 0.0, "Volume should be >= 0")
		assert.InDelta(t, 0.0001, token.MarketData.PriceUSD, 0.00001)
		assert.GreaterOrEqual(t, token.MarketData.Holders, uint64(1), "Should have at least 1 holder")

		assert.Equal(t, uint64(3), token.MarketData.Position.Rank, "Rank from Redis sorted set")
		assert.Equal(t, uint64(3500), token.MarketData.Position.Amount, "Amount = 3500 tokens")
		assert.InDelta(t, 0.35, token.MarketData.Position.AmountUSD, 0.01, "AmountUSD = 3500 * 0.0001 = $0.35")
		assert.InDelta(t, 0.035, token.MarketData.Position.PnL, 0.001, "PnL = $0.35 - $0.315 = $0.035")
		assert.InDelta(t, 11.11, token.MarketData.Position.PnLPercentage, 1.0, "PnL% = 0.035/0.315*100 = 11.11%")
	})
}

func TestGetCommunityTokensByExternalAddresses_WithKeyword(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	ta := NewForTest(ctx)

	t.Run("search by keyword returns simplified response", func(t *testing.T) {
		helperInsertTestUser(t, ctx, testDB, "creator_search", "satoshi_search", "Satoshi Search", "", false, PlatformGroupIonConnect)

		tokenExt := "0:creator_search:"
		helperInsertTestToken(t, ctx, testDB,
			"0xSEARCH11111111111111111111111111111",
			tokenExt,
			"SAT",
			"profile",
			"creator_search",
			"1000000000000000000000000",
			100.0,
			0.0001,
			10,
			PlatformGroupIonConnect,
		)
		helperCreateSwapForVolume(t, ctx, testDB,
			"0xSEARCH11111111111111111111111111111",
			tokenExt,
			"0x0000000000000000000000000000000000000001",
			false,                    // buy
			"500000000000000000000",  // 500 ION input
			"5000000000000000000000", // 5000 tokens output
			0.0001,
		)
		helperRefreshVolumeView(t, ctx, testDB)

		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{tokenExt}, "requestor_search", nil, "SAT", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		token := tokens[0]

		assert.Equal(t, "profile", token.Type)
		assert.Equal(t, "satoshi_search", token.Title)
		assert.Equal(t, "Satoshi Search", token.Description)

		assert.Empty(t, token.MarketData.Ticker, "Ticker should be empty in simplified search response")
		assert.InDelta(t, 100.0, token.MarketData.MarketCap, 0.01)
		assert.Greater(t, token.MarketData.Volume, 0.0, "Volume should be present from materialized view")
		assert.InDelta(t, 0.0001, token.MarketData.PriceUSD, 0.00001)
		assert.Equal(t, uint64(10), token.MarketData.Holders)

		// Position should be empty in search mode
		assert.Equal(t, uint64(0), token.MarketData.Position.Rank)
		assert.Equal(t, uint64(0), token.MarketData.Position.Amount)
		assert.Equal(t, 0.0, token.MarketData.Position.AmountUSD)
	})

	t.Run("search with limit and offset - 250+ tokens for KNN candidates", func(t *testing.T) {
		var allTokenExtAddrs []string
		for i := 0; i < 260; i++ {
			creator := fmt.Sprintf("creator_page_%d", i)
			helperInsertTestUser(t, ctx, testDB, creator, fmt.Sprintf("testknn_%d", i), fmt.Sprintf("Test KNN User %d", i), "", false, PlatformGroupIonConnect)

			tokenExt := fmt.Sprintf("0:%s:", creator)
			allTokenExtAddrs = append(allTokenExtAddrs, tokenExt)

			helperInsertTestToken(t, ctx, testDB,
				fmt.Sprintf("0xKNN%03d111111111111111111111111111", i),
				tokenExt,
				fmt.Sprintf("KNN%d", i),
				"profile",
				creator,
				"1000000000000000000000000",
				float64(100+i),
				0.0001,
				5,
				PlatformGroupIonConnect,
			)
			helperCreateSwapForVolume(t, ctx, testDB,
				fmt.Sprintf("0xKNN%03d111111111111111111111111111", i),
				tokenExt,
				"0x0000000000000000000000000000000000000001",
				false,
				fmt.Sprintf("%d00000000000000000000", 100+i), // Different volumes
				"1000000000000000000000",
				0.0001,
			)
		}
		helperRefreshVolumeView(t, ctx, testDB)

		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx,
			allTokenExtAddrs,
			"requestor_page",
			nil,
			"testknn",
			10,
			0,
		)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(tokens), 10, "Should return at least 10 results from 260+ tokens")

		for _, token := range tokens {
			assert.Contains(t, token.Creator.Username, "testknn", "Creator username should contain search keyword")
		}

		tokens1, err := ta.GetCommunityTokensByExternalAddresses(ctx,
			allTokenExtAddrs,
			"requestor_page",
			nil,
			"testknn",
			2,
			0,
		)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(tokens1), 2)

		tokens2, err := ta.GetCommunityTokensByExternalAddresses(ctx,
			allTokenExtAddrs,
			"requestor_page",
			nil,
			"testknn",
			2,
			2,
		)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(tokens2), 2)

		// Verify no overlap between pages
		if len(tokens1) > 0 && len(tokens2) > 0 {
			for _, t1 := range tokens1 {
				for _, t2 := range tokens2 {
					assert.NotEqual(t, t1.Creator.Username, t2.Creator.Username, "Pages should not overlap")
				}
			}
		}
	})
}

func TestGetCommunityTokensByExternalAddresses_WithAndWithoutKeyword(t *testing.T) {
	ctx := t.Context()
	ta := NewForTest(ctx)

	// Setup test data
	helperInsertTestUser(t, ctx, testDB, "creator_kw1", "alice_kw1", "Alice Keyword One", "", true, PlatformGroupIonConnect, "https://avatar1.png")
	helperInsertTestUser(t, ctx, testDB, "creator_kw2", "bob_kw2", "Bob Keyword Two", "", false, PlatformGroupIonConnect, "https://avatar2.png")
	helperInsertTestUser(t, ctx, testDB, "creator_kw3", "charlie_kw3", "Charlie Keyword Three", "", true, PlatformGroupIonConnect, "https://avatar3.png")
	helperInsertTestUser(t, ctx, testDB, "requestor_kw", "requestor_kw", "Requestor KW", "", false, PlatformGroupIonConnect)

	token1Ext := "0:creator_kw1:"
	token2Ext := "0:creator_kw2:"
	token3Ext := "0:creator_kw3:"

	helperInsertTestToken(t, ctx, testDB, "0xKW1111111111111111111111111111111111111", token1Ext, "TK1", "profile", "creator_kw1", "1000000000000000000000000", 100.0, 0.0001, 5, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, testDB, "0xKW2222222222222222222222222222222222222", token2Ext, "TK2", "profile", "creator_kw2", "2000000000000000000000000", 200.0, 0.0002, 10, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, testDB, "0xKW3333333333333333333333333333333333333", token3Ext, "TK3", "post", "creator_kw3", "3000000000000000000000000", 300.0, 0.0003, 15, PlatformGroupIonConnect)

	helperCreateSwapForVolume(t, ctx, testDB, "0xKW1111111111111111111111111111111111111", token1Ext, "0x0000000000000000000000000000000000000001", false, "100000000000000000000", "1000000000000000000000", 0.0001)
	helperCreateSwapForVolume(t, ctx, testDB, "0xKW2222222222222222222222222222222222222", token2Ext, "0x0000000000000000000000000000000000000002", false, "200000000000000000000", "2000000000000000000000", 0.0002)
	helperCreateSwapForVolume(t, ctx, testDB, "0xKW3333333333333333333333333333333333333", token3Ext, "0x0000000000000000000000000000000000000003", false, "300000000000000000000", "3000000000000000000000", 0.0003)
	helperRefreshVolumeView(t, ctx, testDB)

	t.Run("without keyword - returns full data with ticker", func(t *testing.T) {
		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{token1Ext, token2Ext, token3Ext}, "requestor_kw", nil, "", 0, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 3)

		for _, token := range tokens {
			assert.NotEmpty(t, token.MarketData.Ticker, "Ticker should be present without keyword")
			assert.Greater(t, token.MarketData.MarketCap, 0.0, "MarketCap should be present")
			assert.Greater(t, token.MarketData.Volume, 0.0, "Volume should be present from materialized view")
		}
	})

	t.Run("with keyword - returns simplified data without ticker", func(t *testing.T) {
		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{token1Ext, token2Ext, token3Ext}, "requestor_kw", nil, "alice", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		token := tokens[0]
		assert.Equal(t, "profile", token.Type)
		assert.Equal(t, "alice_kw1", token.Title)
		assert.Equal(t, "Alice Keyword One", token.Description)
		assert.Equal(t, "https://avatar1.png", token.ImageURL)

		assert.Empty(t, token.MarketData.Ticker, "Ticker should be empty in simplified search response")
		assert.InDelta(t, 100.0, token.MarketData.MarketCap, 0.01)
		assert.Greater(t, token.MarketData.Volume, 0.0, "Volume should be present")
		assert.InDelta(t, 0.0001, token.MarketData.PriceUSD, 0.00001)
		assert.Equal(t, uint64(5), token.MarketData.Holders)

		// Position empty in search mode
		assert.Equal(t, uint64(0), token.MarketData.Position.Rank, "Position should be empty in search mode")
		assert.Equal(t, uint64(0), token.MarketData.Position.Amount)
		assert.Equal(t, 0.0, token.MarketData.Position.AmountUSD)
	})

	t.Run("with keyword - uses KNN search and similarity ranking", func(t *testing.T) {
		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{token1Ext, token2Ext, token3Ext}, "requestor_kw", nil, "keyword", 10, 0)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(tokens), 1, "Should find tokens with keyword in lookup")

		for _, token := range tokens {
			assert.Empty(t, token.MarketData.Ticker, "All search results should be simplified")
		}
	})

	t.Run("with keyword - pagination works correctly", func(t *testing.T) {
		tokens1, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{token1Ext, token2Ext, token3Ext}, "requestor_kw", nil, "k", 2, 0)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(tokens1), 2)

		tokens2, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{token1Ext, token2Ext, token3Ext}, "requestor_kw", nil, "k", 2, 2)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(tokens2), 2)

		if len(tokens1) > 0 && len(tokens2) > 0 {
			assert.NotEqual(t, tokens1[0].Addresses.IonConnect, tokens2[0].Addresses.IonConnect)
		}
	})
}

func TestGetCommunityTokensWithTopPlatformHolders_WithAndWithoutKeyword(t *testing.T) {
	ctx := t.Context()
	ta := NewForTest(ctx)

	helperInsertTestUser(t, ctx, testDB, "creator_tph1", "creator_tph1", "Creator TPH One", "", true, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, testDB, "creator_tph2", "creator_tph2", "Creator TPH Two", "", false, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, testDB, "holder_tph1", "holder_tph1", "Holder TPH One", "", false, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, testDB, "holder_tph2", "holder_tph2", "Holder TPH Two", "", true, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, testDB, "requestor_tph", "requestor_tph", "Requestor TPH", "", false, PlatformGroupIonConnect)

	token1Ext := "0:creator_tph1:"
	token2Ext := "0:creator_tph2:"

	helperInsertTestToken(t, ctx, testDB, "0xTPH1111111111111111111111111111111111111", token1Ext, "TPH1", "profile", "creator_tph1", "1000000000000000000000000", 100.0, 0.0001, 2, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, testDB, "0xTPH2222222222222222222222222222222222222", token2Ext, "TPH2", "profile", "creator_tph2", "2000000000000000000000000", 200.0, 0.0002, 2, PlatformGroupIonConnect)

	helperInsertUserTokenPosition(t, ctx, testDB, "holder_tph1", "0xTPH1111111111111111111111111111111111111", token1Ext, "0:holder_tph1:", "5000000000000000000000", 0.00009, 0.45)
	helperInsertUserTokenPosition(t, ctx, testDB, "holder_tph2", "0xTPH1111111111111111111111111111111111111", token1Ext, "0:holder_tph2:", "3000000000000000000000", 0.00009, 0.27)
	helperInsertUserTokenPosition(t, ctx, testDB, "requestor_tph", "0xTPH1111111111111111111111111111111111111", token1Ext, "0:requestor_tph:", "1000000000000000000000", 0.00009, 0.09)

	helperSetupRedisPositionData(t, ctx, testRedis, token1Ext, map[string]float64{
		"0:holder_tph1:":   5000.0,
		"0:holder_tph2:":   3000.0,
		"0:requestor_tph:": 1000.0,
	})

	includeTop := uint32(2)

	t.Run("without keyword - returns full data with ticker", func(t *testing.T) {
		tokens, err := ta.(*tokenAnalytics).getCommunityTokensWithTopPlatformHolders(ctx, []string{token1Ext, token2Ext}, "requestor_tph", &includeTop, "", 0, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 2, "Should return 2 tokens")

		var token1 *CommunityToken
		for _, t := range tokens {
			if t.Addresses.IonConnect == token1Ext {
				token1 = t
				break
			}
		}
		require.NotNil(t, token1, "Should find token1")

		assert.Equal(t, "profile", token1.Type)
		assert.NotEmpty(t, token1.MarketData.Ticker, "Ticker should be present without keyword")
		assert.Equal(t, "TPH1", token1.MarketData.Ticker)

		require.Len(t, token1.MarketData.TopPlatformHolders, 2, "Should return top 2 platform holders")

		// Verify first holder - ALL fields
		holder1 := token1.MarketData.TopPlatformHolders[0]
		assert.Equal(t, "holder_tph1", holder1.Holder.Username)
		assert.Equal(t, "Holder TPH One", holder1.Holder.Display)
		assert.False(t, holder1.Holder.Verified)
		assert.NotEmpty(t, holder1.Holder.Avatar)
		assert.Equal(t, "0:holder_tph1:", holder1.Holder.Addresses.IonConnect)
		assert.Equal(t, uint64(1), holder1.Rank)
		assert.Equal(t, uint64(5000), holder1.Amount)
		assert.InDelta(t, 0.5, holder1.AmountUSD, 0.01, "5000 * 0.0001 = 0.5")
		assert.InDelta(t, 0.5, holder1.SupplyShare, 0.01, "5000 / 1000000 * 100 = 0.5%")

		// Verify second holder - ALL fields
		holder2 := token1.MarketData.TopPlatformHolders[1]
		assert.Equal(t, "holder_tph2", holder2.Holder.Username)
		assert.Equal(t, "Holder TPH Two", holder2.Holder.Display)
		assert.True(t, holder2.Holder.Verified)
		assert.NotEmpty(t, holder2.Holder.Avatar)
		assert.Equal(t, "0:holder_tph2:", holder2.Holder.Addresses.IonConnect)
		assert.Equal(t, uint64(2), holder2.Rank)
		assert.Equal(t, uint64(3000), holder2.Amount)
		assert.InDelta(t, 0.3, holder2.AmountUSD, 0.01, "3000 * 0.0001 = 0.3")
		assert.InDelta(t, 0.3, holder2.SupplyShare, 0.01, "3000 / 1000000 * 100 = 0.3%")
	})

	t.Run("with keyword - uses CTE candidates and KNN search", func(t *testing.T) {
		tokens, err := ta.(*tokenAnalytics).getCommunityTokensWithTopPlatformHolders(ctx, []string{token1Ext, token2Ext}, "requestor_tph", &includeTop, "creator_tph1", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1, "Should find only matching token")

		token := tokens[0]
		assert.Equal(t, "creator_tph1", token.Creator.Username, "Should find token by creator username")
		require.Len(t, token.MarketData.TopPlatformHolders, 2, "Should return top platform holders even with keyword")

		// Verify top platform holders - ALL fields
		holder1 := token.MarketData.TopPlatformHolders[0]
		assert.Equal(t, "holder_tph1", holder1.Holder.Username)
		assert.Equal(t, "Holder TPH One", holder1.Holder.Display)
		assert.False(t, holder1.Holder.Verified)
		assert.NotEmpty(t, holder1.Holder.Avatar)
		assert.Equal(t, "0:holder_tph1:", holder1.Holder.Addresses.IonConnect)
		assert.Equal(t, uint64(1), holder1.Rank)
		assert.Equal(t, uint64(5000), holder1.Amount)
		assert.InDelta(t, 0.5, holder1.AmountUSD, 0.01)
		assert.InDelta(t, 0.5, holder1.SupplyShare, 0.01)

		holder2 := token.MarketData.TopPlatformHolders[1]
		assert.Equal(t, "holder_tph2", holder2.Holder.Username)
		assert.Equal(t, "Holder TPH Two", holder2.Holder.Display)
		assert.True(t, holder2.Holder.Verified)
		assert.NotEmpty(t, holder2.Holder.Avatar)
		assert.Equal(t, "0:holder_tph2:", holder2.Holder.Addresses.IonConnect)
		assert.Equal(t, uint64(2), holder2.Rank)
		assert.Equal(t, uint64(3000), holder2.Amount)
		assert.InDelta(t, 0.3, holder2.AmountUSD, 0.01)
		assert.InDelta(t, 0.3, holder2.SupplyShare, 0.01)
	})

	t.Run("with keyword - pagination works", func(t *testing.T) {
		tokens1, err := ta.(*tokenAnalytics).getCommunityTokensWithTopPlatformHolders(ctx, []string{token1Ext, token2Ext}, "requestor_tph", &includeTop, "tph", 1, 0)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(tokens1), 1)

		tokens2, err := ta.(*tokenAnalytics).getCommunityTokensWithTopPlatformHolders(ctx, []string{token1Ext, token2Ext}, "requestor_tph", &includeTop, "tph", 1, 1)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(tokens2), 1)
	})
}

func TestGetCommunityTokensByExternalAddresses_WithTopPlatformHolders(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	ta := NewForTest(ctx)

	t.Run("returns top platform holders", func(t *testing.T) {
		helperInsertTestUser(t, ctx, testDB, "creator_top", "alice_top", "Alice Top", "", true, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, testDB, "holder1_top", "holder1", "Holder One", "", false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, testDB, "holder2_top", "holder2", "Holder Two", "", false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, testDB, "requestor_top", "requestor", "Requestor", "", false, PlatformGroupIonConnect)

		tokenExt := "0:creator_top:"
		helperInsertTestToken(t, ctx, testDB,
			"0xTOP111111111111111111111111111111111",
			tokenExt,
			"TOP1",
			"profile",
			"creator_top",
			"10000000000000000000000000",
			1000.0,
			0.0001,
			3,
			PlatformGroupIonConnect,
		)

		helperInsertUserTokenPosition(t, ctx, testDB, "holder1_top", "0xTOP111111111111111111111111111111111", tokenExt, "0:holder1_top:", "5000000000000000000000", 0.00009, 0.45)
		helperInsertUserTokenPosition(t, ctx, testDB, "holder2_top", "0xTOP111111111111111111111111111111111", tokenExt, "0:holder2_top:", "3000000000000000000000", 0.00009, 0.27)
		helperInsertUserTokenPosition(t, ctx, testDB, "requestor_top", "0xTOP111111111111111111111111111111111", tokenExt, "0:requestor_top:", "1000000000000000000000", 0.00009, 0.09)

		helperSetupRedisPositionData(t, ctx, testRedis, tokenExt, map[string]float64{
			"0:holder1_top:":   5000.0,
			"0:holder2_top:":   3000.0,
			"0:requestor_top:": 1000.0,
		})

		topHolders := uint32(2)
		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{tokenExt}, "requestor_top", &topHolders, "", 0, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		token := tokens[0]

		assert.Equal(t, "profile", token.Type)
		assert.Equal(t, "TOP1", token.MarketData.Ticker)

		require.Len(t, token.MarketData.TopPlatformHolders, 2, "Expected 2 top platform holders")

		// Verify first holder - ALL fields
		holder1 := token.MarketData.TopPlatformHolders[0]
		assert.Equal(t, "holder1", holder1.Holder.Username)
		assert.Equal(t, "Holder One", holder1.Holder.Display)
		assert.False(t, holder1.Holder.Verified)
		assert.NotEmpty(t, holder1.Holder.Avatar)
		assert.Equal(t, "0:holder1_top:", holder1.Holder.Addresses.IonConnect)
		assert.Equal(t, uint64(1), holder1.Rank)
		assert.Equal(t, uint64(5000), holder1.Amount)
		assert.InDelta(t, 0.5, holder1.AmountUSD, 0.01, "5000 * 0.0001 = 0.5")
		assert.InDelta(t, 0.05, holder1.SupplyShare, 0.01, "5000 / 10000000 * 100 = 0.05%")

		// Verify second holder - ALL fields
		holder2 := token.MarketData.TopPlatformHolders[1]
		assert.Equal(t, "holder2", holder2.Holder.Username)
		assert.Equal(t, "Holder Two", holder2.Holder.Display)
		assert.False(t, holder2.Holder.Verified)
		assert.NotEmpty(t, holder2.Holder.Avatar)
		assert.Equal(t, "0:holder2_top:", holder2.Holder.Addresses.IonConnect)
		assert.Equal(t, uint64(2), holder2.Rank)
		assert.Equal(t, uint64(3000), holder2.Amount)
		assert.InDelta(t, 0.3, holder2.AmountUSD, 0.01, "3000 * 0.0001 = 0.3")
		assert.InDelta(t, 0.03, holder2.SupplyShare, 0.01, "3000 / 10000000 * 100 = 0.03%")
	})
}

func helperBuildExternalAddress(platform, tokenType, identifier string) string {
	var prefix string
	switch platform {
	case "ionconnect":
		switch tokenType {
		case "profile":
			prefix = "a"
		case "post":
			prefix = "b"
		case "video":
			prefix = "c"
		case "article":
			prefix = "d"
		default:
			prefix = "a"
		}
	case "xcom":
		switch tokenType {
		case "profile":
			prefix = "z"
		case "post":
			prefix = "y"
		case "video":
			prefix = "x"
		case "article":
			prefix = "w"
		default:
			prefix = "z"
		}
	default:
		prefix = "a"
	}

	// For profile type, format is prefix0:identifier:
	if tokenType == "profile" || tokenType == "" {
		return fmt.Sprintf("%s0:%s:", prefix, identifier)
	}
	// For content types, format is prefix<kind>:creator:contentid
	return fmt.Sprintf("%s1:%s:%s", prefix, identifier, "content")
}

func helperBuildProfileExternalAddress(masterPubkey string) string {
	return fmt.Sprintf("0:%s:", masterPubkey)
}

func helperInsertTestUser(t *testing.T, ctx context.Context, db *storage.DB, masterPubkey, username, displayName, blockchainAddr string, verified bool, platformGroup string, avatar ...string) {
	t.Helper()
	externalAddr := helperBuildProfileExternalAddress(masterPubkey)
	if blockchainAddr == "" {
		if len(masterPubkey) >= 40 {
			blockchainAddr = "0x" + masterPubkey[:40]
		} else {
			blockchainAddr = "0x" + masterPubkey + strings.Repeat("0", 40-len(masterPubkey))
		}
	}
	blockchainAddr = strings.ToLower(blockchainAddr)

	avatarURL := "avatar.png"
	if len(avatar) > 0 && avatar[0] != "" {
		avatarURL = avatar[0]
	}

	query := `
		INSERT INTO users (created_at, updated_at, id, master_pubkey, blockchain_address, external_address, username, display_name, avatar, lookup, verified, platform_group)
		VALUES (NOW(), NOW(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (master_pubkey) DO UPDATE SET
			blockchain_address = EXCLUDED.blockchain_address,
			external_address = EXCLUDED.external_address,
			username = EXCLUDED.username,
			display_name = EXCLUDED.display_name,
			avatar = EXCLUDED.avatar,
			lookup = EXCLUDED.lookup,
			verified = EXCLUDED.verified,
			platform_group = EXCLUDED.platform_group,
			updated_at = NOW()
	`
	_, err := storage.Exec(ctx, db, query,
		masterPubkey,
		masterPubkey,
		blockchainAddr,
		externalAddr,
		username,
		displayName,
		avatarURL,
		username+" "+displayName,
		verified,
		platformGroup,
	)
	require.NoError(t, err, "failed to insert test user")
}

func helperInsertTestToken(t *testing.T, ctx context.Context, db *storage.DB,
	contractAddress, externalAddress, ticker, tokenType, creatorPubkey string,
	totalSupply string, marketCapUSD, priceUSD float64, holdersCount int, platform string) {
	t.Helper()

	type userInfo struct {
		Username    string `db:"username"`
		DisplayName string `db:"display_name"`
	}
	users, err := storage.Select[userInfo](ctx, db, "SELECT username, COALESCE(display_name, '') as display_name FROM users WHERE master_pubkey = $1", creatorPubkey)
	var username, displayName string
	if err == nil && len(users) > 0 {
		username = users[0].Username
		displayName = users[0].DisplayName
	}
	lookup := strings.ToLower(strings.TrimSpace(username + " " + displayName + " " + ticker))

	query := `
		INSERT INTO tokens (
			created_at, updated_at, contract_address, external_address, platform,
			ticker, total_supply, creator_master_pubkey, type, 
			market_cap_usd, price_usd, holders_count, lookup
		)
		VALUES (NOW(), NOW(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (contract_address) DO UPDATE SET
			external_address = EXCLUDED.external_address,
			platform = EXCLUDED.platform,
			ticker = EXCLUDED.ticker,
			total_supply = EXCLUDED.total_supply,
			type = EXCLUDED.type,
			market_cap_usd = EXCLUDED.market_cap_usd,
			price_usd = EXCLUDED.price_usd,
			holders_count = EXCLUDED.holders_count,
			lookup = EXCLUDED.lookup
	`
	_, err = storage.Exec(ctx, db, query,
		contractAddress,
		externalAddress,
		platform,
		ticker,
		totalSupply,
		creatorPubkey,
		tokenType,
		marketCapUSD,
		priceUSD,
		holdersCount,
		lookup,
	)
	require.NoError(t, err, "failed to insert test token")
}

func helperInsertUserTokenPosition(t *testing.T, ctx context.Context, db *storage.DB,
	masterPubkey, contractAddress, externalAddress, userExternalAddress string, amount string, avgBuyPriceUSD, totalInvestedUSD float64) {
	t.Helper()
	query := `
		INSERT INTO user_token_positions (
			updated_at, master_pubkey, contract_address, external_address, user_external_address,
			amount, avg_buy_price_usd, total_invested_usd
		)
		VALUES (NOW(), $1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (master_pubkey, contract_address) DO UPDATE SET
			amount = EXCLUDED.amount,
			external_address = EXCLUDED.external_address,
			user_external_address = EXCLUDED.user_external_address,
		    avg_buy_price_usd = EXCLUDED.avg_buy_price_usd,
		    total_invested_usd = EXCLUDED.total_invested_usd,
		    updated_at = NOW()
	`
	_, err := storage.Exec(ctx, db, query,
		masterPubkey,
		contractAddress,
		externalAddress,
		userExternalAddress,
		amount,
		avgBuyPriceUSD,
		totalInvestedUSD,
	)
	require.NoError(t, err, "failed to insert user token position")
}

func helperInsertTokenSwap(t *testing.T, ctx context.Context, db *storage.DB,
	contractAddress, externalAddress, userAddress string,
	txHash string,
	direction bool, inputAmount, outputAmount string, priceUSD float64) {
	t.Helper()

	createdAt := time.Now()

	query := `
		INSERT INTO token_swaps (
			created_at, transaction_hash, contract_address, external_address,
			user_address, direction, input_amount, output_amount, price_usd, fee
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 0)
		ON CONFLICT (transaction_hash, contract_address, user_address) DO NOTHING
	`
	_, err := storage.Exec(ctx, db, query,
		createdAt,
		txHash,
		contractAddress,
		externalAddress,
		userAddress,
		direction,
		inputAmount,
		outputAmount,
		priceUSD,
	)
	require.NoError(t, err, "failed to insert token swap")
}

// helperCreateSwapForVolume creates a swap record for testing volume calculations.
// It creates the swap and refreshes the materialized view.
func helperCreateSwapForVolume(t *testing.T, ctx context.Context, db *storage.DB,
	contractAddress, externalAddress, userAddress string, direction bool, inputAmount, outputAmount string, priceUSD float64) {
	t.Helper()

	txHash := fmt.Sprintf("0x%s%d", contractAddress[2:10], time.Now().UnixNano())
	query := `
		INSERT INTO token_swaps (
			created_at, transaction_hash, contract_address, external_address,
			user_address, direction, input_amount, output_amount, fee, price_usd
		)
		VALUES (NOW(), $1, $2, $3, $4, $5, $6, $7, 0, $8)
		ON CONFLICT DO NOTHING
	`
	_, err := storage.Exec(ctx, db, query,
		txHash,
		contractAddress,
		externalAddress,
		userAddress,
		direction,
		inputAmount,
		outputAmount,
		priceUSD,
	)
	require.NoError(t, err, "failed to insert token swap for volume")
}

func helperRefreshVolumeView(t *testing.T, ctx context.Context, db *storage.DB) {
	t.Helper()
	_, err := storage.Exec(ctx, db, "REFRESH MATERIALIZED VIEW CONCURRENTLY token_volumes_24h")
	if err != nil {
		_, err = storage.Exec(ctx, db, "REFRESH MATERIALIZED VIEW token_volumes_24h")
		require.NoError(t, err, "failed to refresh token_volumes_24h")
	}
}

func helperSetupRedisPositionData(t *testing.T, ctx context.Context, client storagev3.DB,
	externalAddress string, positions map[string]float64) {
	t.Helper()
	key := keyUserPositionOfToken(externalAddress)

	for userExtAddr, balanceFloat := range positions {
		err := client.ZAdd(ctx, key, redis.Z{
			Score:  balanceFloat,
			Member: userExtAddr,
		}).Err()
		require.NoError(t, err, "failed to add position to redis")
	}
}

func helperInsertFeaturedToken(t *testing.T, ctx context.Context, db *storage.DB, externalAddress string) {
	t.Helper()
	query := `INSERT INTO tokens_featured (external_address, created_at) VALUES ($1, NOW())`
	_, err := storage.Exec(ctx, db, query, externalAddress)
	require.NoError(t, err, "failed to insert featured token")
}
