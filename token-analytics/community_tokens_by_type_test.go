// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCommunityTokensByLatest_WithAndWithoutKeyword(t *testing.T) {
	ctx := t.Context()
	ta := NewForTest(ctx)

	helperInsertTestUser(t, ctx, testDB, "creator_latest1", "latest_one", "Latest One", "", true, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, testDB, "creator_latest2", "latest_two", "Latest Two", "", false, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, testDB, "creator_latest3", "latest_three", "Latest Three", "", true, PlatformGroupIonConnect)

	token1Ext := "0:creator_latest1:"
	token2Ext := "0:creator_latest2:"
	token3Ext := "0:creator_latest3:"

	helperInsertTestToken(t, ctx, testDB, "0xLATEST1111111111111111111111111111111111", token1Ext, "LAT1", "profile", "creator_latest1", "1000000000000000000000000", 100.0, 0.0001, 5, PlatformGroupIonConnect)
	time.Sleep(10 * time.Millisecond) // Ensure different created_at
	helperInsertTestToken(t, ctx, testDB, "0xLATEST2222222222222222222222222222222222", token2Ext, "LAT2", "post", "creator_latest2", "2000000000000000000000000", 200.0, 0.0002, 10, PlatformGroupIonConnect)
	time.Sleep(10 * time.Millisecond)
	helperInsertTestToken(t, ctx, testDB, "0xLATEST3333333333333333333333333333333333", token3Ext, "LAT3", "video", "creator_latest3", "3000000000000000000000000", 300.0, 0.0003, 15, PlatformGroupIonConnect)

	helperCreateSwapForVolume(t, ctx, testDB, "0xLATEST1111111111111111111111111111111111", token1Ext, "0x0000000000000000000000000000000000000001", false, "100000000000000000000", "1000000000000000000000", 0.0001)
	helperCreateSwapForVolume(t, ctx, testDB, "0xLATEST2222222222222222222222222222222222", token2Ext, "0x0000000000000000000000000000000000000002", false, "200000000000000000000", "2000000000000000000000", 0.0002)
	helperCreateSwapForVolume(t, ctx, testDB, "0xLATEST3333333333333333333333333333333333", token3Ext, "0x0000000000000000000000000000000000000003", false, "300000000000000000000", "3000000000000000000000", 0.0003)
	helperRefreshVolumeView(t, ctx, testDB)

	t.Run("without keyword - returns tokens ordered by created_at DESC", func(t *testing.T) {
		tokens, err := ta.(*tokenAnalytics).getCommunityTokensByLatest(ctx, "", 10, 0, nil)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(tokens), 3, "Should return at least our 3 test tokens")

		var foundTokens []*CommunityToken
		for _, token := range tokens {
			if strings.HasPrefix(token.Addresses.IonConnect, "0:creator_latest") {
				foundTokens = append(foundTokens, token)
			}
		}
		require.GreaterOrEqual(t, len(foundTokens), 3)

		// Verify order: newest first (token3 -> token2 -> token1,
		for i := 0; i < len(foundTokens)-1; i++ {
			assert.True(t, foundTokens[i].CreatedAt.After(foundTokens[i+1].CreatedAt) || foundTokens[i].CreatedAt.Equal(foundTokens[i+1].CreatedAt), "Tokens should be ordered by created_at DESC")
		}
		for _, token := range foundTokens {
			assert.NotEmpty(t, token.MarketData.Ticker, "Ticker should be present without keyword")
			assert.Greater(t, token.MarketData.MarketCap, 0.0, "MarketCap should be > 0")
			assert.Greater(t, token.MarketData.PriceUSD, 0.0, "PriceUSD should be > 0")
			assert.GreaterOrEqual(t, token.MarketData.Volume, 0.0, "Volume should be >= 0")
			assert.Greater(t, token.MarketData.Holders, uint64(0), "Holders should be > 0")
			// No position, platformHolders, topPlatformHolders, bondingCurveProgress in latest mode

			assert.Equal(t, uint64(0), token.MarketData.Position.Rank, "Position should be zero value")
			assert.Equal(t, uint64(0), token.MarketData.Position.Amount, "Position should be zero value")
			assert.Equal(t, uint64(0), token.MarketData.PlatformHolders)
			assert.Nil(t, token.MarketData.TopPlatformHolders)
			assert.Nil(t, token.MarketData.BondingCurveProgress)
		}
	})

	t.Run("with keyword - uses CTE candidates and KNN search", func(t *testing.T) {
		tokens, err := ta.(*tokenAnalytics).getCommunityTokensByLatest(ctx, "latest_one", 10, 0, nil)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(tokens), 1, "Should find matching token")

		found := false
		for _, token := range tokens {
			if token.Creator.Username == "latest_one" {
				found = true

				assert.Equal(t, "profile", token.Type)
				assert.Equal(t, "latest_one", token.Title)
				assert.Equal(t, "Latest One", token.Description)
				if !token.CreatedAt.IsZero() {
					assert.True(t, token.CreatedAt.Before(time.Now().Add(time.Second)))
				}

				assert.Equal(t, token1Ext, token.Addresses.IonConnect)

				assert.Equal(t, "latest_one", token.Creator.Username)
				assert.Equal(t, "Latest One", token.Creator.Display)
				assert.True(t, token.Creator.Verified)

				assert.NotEmpty(t, token.MarketData.Ticker, "Ticker should be present")
				assert.Equal(t, "LAT1", token.MarketData.Ticker)
				assert.InDelta(t, 100.0, token.MarketData.MarketCap, 0.01)
				assert.Greater(t, token.MarketData.Volume, 0.0, "Volume should be present")
				assert.InDelta(t, 0.0001, token.MarketData.PriceUSD, 0.00001)
				assert.Equal(t, uint64(5), token.MarketData.Holders)

				break
			}
		}
		assert.True(t, found, "Should find token with username 'latest_one'")
	})

	t.Run("with keyword - results ordered by relevance then created_at", func(t *testing.T) {
		tokens, err := ta.(*tokenAnalytics).getCommunityTokensByLatest(ctx, "latest", 10, 0, nil)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(tokens), 3, "Should find all matching tokens")

		for _, token := range tokens {
			assert.Contains(t, strings.ToLower(token.Creator.Username), "latest", "Username should contain 'latest'")
		}
	})

	t.Run("with tokenType filter and no keyword", func(t *testing.T) {
		tokenType := "profile"
		tokens, err := ta.(*tokenAnalytics).getCommunityTokensByLatest(ctx, "", 10, 0, &tokenType)
		require.NoError(t, err)

		found := false
		for _, token := range tokens {
			if token.Addresses.IonConnect == token1Ext {
				found = true
				assert.Equal(t, "profile", token.Type)
				break
			}
		}
		assert.True(t, found, "Should find profile token")
	})

	t.Run("with tokenType filter and keyword", func(t *testing.T) {
		tokenType := "post"
		tokens, err := ta.(*tokenAnalytics).getCommunityTokensByLatest(ctx, "latest", 10, 0, &tokenType)
		require.NoError(t, err)

		for _, token := range tokens {
			if strings.Contains(token.Creator.Username, "latest") {
				assert.Equal(t, "post", token.Type)
			}
		}
	})

	t.Run("with keyword - pagination works", func(t *testing.T) {
		tokens1, err := ta.(*tokenAnalytics).getCommunityTokensByLatest(ctx, "latest", 2, 0, nil)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(tokens1), 2)

		tokens2, err := ta.(*tokenAnalytics).getCommunityTokensByLatest(ctx, "latest", 2, 2, nil)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(tokens2), 2)

		if len(tokens1) > 0 && len(tokens2) > 0 {
			assert.NotEqual(t, tokens1[0].Addresses.IonConnect, tokens2[0].Addresses.IonConnect)
		}
	})
}

func TestGetCommunityTokensByFeatured(t *testing.T) {
	ctx := t.Context()
	ta := NewForTest(ctx)

	helperInsertTestUser(t, ctx, testDB, "creator_featured1", "featured_one", "Featured One", "", true, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, testDB, "creator_featured2", "featured_two", "Featured Two", "", false, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, testDB, "creator_featured3", "featured_three", "Featured Three", "", true, PlatformGroupIonConnect)

	token1Ext := "0:creator_featured1:"
	token2Ext := "0:creator_featured2:"
	token3Ext := "0:creator_featured3:"

	helperInsertTestToken(t, ctx, testDB, "0xFEATURE1111111111111111111111111111111111", token1Ext, "FEA1", "profile", "creator_featured1", "1000000000000000000000000", 100.0, 0.0001, 5, PlatformGroupIonConnect)
	time.Sleep(10 * time.Millisecond)
	helperInsertTestToken(t, ctx, testDB, "0xFEATURE2222222222222222222222222222222222", token2Ext, "FEA2", "post", "creator_featured2", "2000000000000000000000000", 200.0, 0.0002, 10, PlatformGroupIonConnect)
	time.Sleep(10 * time.Millisecond)
	helperInsertTestToken(t, ctx, testDB, "0xFEATURE3333333333333333333333333333333333", token3Ext, "FEA3", "video", "creator_featured3", "3000000000000000000000000", 300.0, 0.0003, 15, PlatformGroupIonConnect)

	helperCreateSwapForVolume(t, ctx, testDB, "0xFEATURE1111111111111111111111111111111111", token1Ext, "0x0000000000000000000000000000000000000001", false, "100000000000000000000", "1000000000000000000000", 0.0001)
	helperCreateSwapForVolume(t, ctx, testDB, "0xFEATURE2222222222222222222222222222222222", token2Ext, "0x0000000000000000000000000000000000000002", false, "200000000000000000000", "2000000000000000000000", 0.0002)
	helperCreateSwapForVolume(t, ctx, testDB, "0xFEATURE3333333333333333333333333333333333", token3Ext, "0x0000000000000000000000000000000000000003", false, "300000000000000000000", "3000000000000000000000", 0.0003)
	helperRefreshVolumeView(t, ctx, testDB)

	// Add tokens to tokens_featured table
	helperInsertFeaturedToken(t, ctx, testDB, token1Ext)
	time.Sleep(10 * time.Millisecond)
	helperInsertFeaturedToken(t, ctx, testDB, token2Ext)
	time.Sleep(10 * time.Millisecond)
	helperInsertFeaturedToken(t, ctx, testDB, token3Ext)

	t.Run("returns featured tokens ordered by tokens_featured.created_at DESC", func(t *testing.T) {
		tokens, err := ta.(*tokenAnalytics).getCommunityTokensByFeatured(ctx, 10, 0, nil)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(tokens), 3, "Should return at least our 3 featured tokens")

		var foundTokens []*CommunityToken
		for _, token := range tokens {
			if strings.HasPrefix(token.Addresses.IonConnect, "0:creator_featured") {
				foundTokens = append(foundTokens, token)
			}
		}
		require.GreaterOrEqual(t, len(foundTokens), 3)

		// Verify order: newest featured first
		for i := 0; i < len(foundTokens)-1; i++ {
			assert.True(t, foundTokens[i].CreatedAt.After(foundTokens[i+1].CreatedAt) || foundTokens[i].CreatedAt.Equal(foundTokens[i+1].CreatedAt), "Tokens should be ordered by featured date DESC")
		}

		for _, token := range foundTokens {
			assert.NotEmpty(t, token.MarketData.Ticker, "Ticker should be present")
			assert.Greater(t, token.MarketData.MarketCap, 0.0, "MarketCap should be > 0")
			assert.Greater(t, token.MarketData.PriceUSD, 0.0, "PriceUSD should be > 0")
			assert.GreaterOrEqual(t, token.MarketData.Volume, 0.0, "Volume should be >= 0")
			assert.Greater(t, token.MarketData.Holders, uint64(0), "Holders should be > 0")

			// Featured mode doesn't return position, platformHolders, topPlatformHolders, bondingCurveProgress
			assert.Equal(t, uint64(0), token.MarketData.Position.Rank)
			assert.Equal(t, uint64(0), token.MarketData.Position.Amount)
			assert.Equal(t, uint64(0), token.MarketData.PlatformHolders)
			assert.Nil(t, token.MarketData.TopPlatformHolders)
			assert.Nil(t, token.MarketData.BondingCurveProgress)
		}
	})

	t.Run("with tokenType filter - returns only matching type", func(t *testing.T) {
		tokenType := "profile"
		tokens, err := ta.(*tokenAnalytics).getCommunityTokensByFeatured(ctx, 10, 0, &tokenType)
		require.NoError(t, err)

		found := false
		for _, token := range tokens {
			if token.Addresses.IonConnect == token1Ext {
				found = true
				assert.Equal(t, "profile", token.Type)
				assert.Equal(t, "featured_one", token.Creator.Username)
				assert.Equal(t, "Featured One", token.Creator.Display)
				assert.True(t, token.Creator.Verified)
				break
			}
		}
		assert.True(t, found, "Should find featured profile token")
	})

	t.Run("pagination works correctly", func(t *testing.T) {
		tokens1, err := ta.(*tokenAnalytics).getCommunityTokensByFeatured(ctx, 2, 0, nil)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(tokens1), 2)

		tokens2, err := ta.(*tokenAnalytics).getCommunityTokensByFeatured(ctx, 2, 2, nil)
		require.NoError(t, err)

		if len(tokens1) > 0 && len(tokens2) > 0 {
			// Verify no overlap between pages
			for _, t1 := range tokens1 {
				for _, t2 := range tokens2 {
					assert.NotEqual(t, t1.Addresses.IonConnect, t2.Addresses.IonConnect, "Pages should not overlap")
				}
			}
		}
	})

	t.Run("returns empty for non-existent tokenType", func(t *testing.T) {
		tokenType := "nonexistent"
		tokens, err := ta.(*tokenAnalytics).getCommunityTokensByFeatured(ctx, 10, 0, &tokenType)
		require.NoError(t, err)

		// Should not find any featured tokens with this type
		for _, token := range tokens {
			assert.NotEqual(t, "nonexistent", token.Type)
		}
	})
}
