// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func TestGetCommunityTokensByLatest_WithAndWithoutKeyword(t *testing.T) {
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()

	ta := helperNewForTest(t, db)

	helperInsertTestUser(t, ctx, db, "creator_latest1", "latest_one", "Latest One", "", true, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, db, "creator_latest2", "latest_two", "Latest Two", "", false, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, db, "creator_latest3", "latest_three", "Latest Three", "", true, PlatformGroupIonConnect)

	token1Ext := "0:creator_latest1:"
	token2Ext := "30023:creator_latest2:post1"
	token3Ext := "30175:creator_latest3:video1"

	helperInsertTestToken(t, ctx, db, "0xLATEST1111111111111111111111111111111111", token1Ext, "LAT1", "profile", "creator_latest1", "1000000000000000000000000", 100.0, 0.0001, 5, PlatformGroupIonConnect)
	time.Sleep(10 * time.Millisecond) // Ensure different created_at

	creator2ProfileExt := "0:creator_latest2:"
	helperInsertTestToken(t, ctx, db, "0xLAT2PROFILE1111111111111111111111111111", creator2ProfileExt, "CLAT2", "profile", "creator_latest2", "500000000000000000000000", 50.0, 0.00005, 2, PlatformGroupIonConnect)

	helperInsertTestToken(t, ctx, db, "0xLATEST2222222222222222222222222222222222", token2Ext, "LAT2", "post", "creator_latest2", "2000000000000000000000000", 200.0, 0.0002, 10, PlatformGroupIonConnect)
	helperSetTokenBaseToken(t, ctx, db, token2Ext, "0xLAT2PROFILE1111111111111111111111111111")
	time.Sleep(10 * time.Millisecond)

	creator3ProfileExt := "0:creator_latest3:"
	helperInsertTestToken(t, ctx, db, "0xLAT3PROFILE1111111111111111111111111111", creator3ProfileExt, "CLAT3", "profile", "creator_latest3", "600000000000000000000000", 60.0, 0.00006, 3, PlatformGroupIonConnect)

	helperInsertTestToken(t, ctx, db, "0xLATEST3333333333333333333333333333333333", token3Ext, "LAT3", "video", "creator_latest3", "3000000000000000000000000", 300.0, 0.0003, 15, PlatformGroupIonConnect)
	helperSetTokenBaseToken(t, ctx, db, token3Ext, "0xLAT3PROFILE1111111111111111111111111111")

	helperCreateSwapForVolume(t, ctx, db, "0xLATEST1111111111111111111111111111111111", token1Ext, "0x0000000000000000000000000000000000000001", false, "100000000000000000000", "1000000000000000000000", 0.0001)
	helperCreateSwapForVolume(t, ctx, db, "0xLATEST2222222222222222222222222222222222", token2Ext, "0x0000000000000000000000000000000000000002", false, "200000000000000000000", "2000000000000000000000", 0.0002)
	helperCreateSwapForVolume(t, ctx, db, "0xLATEST3333333333333333333333333333333333", token3Ext, "0x0000000000000000000000000000000000000003", false, "300000000000000000000", "3000000000000000000000", 0.0003)
	helperRefreshVolumeView(t, ctx, db)

	t.Run("without keyword - returns tokens ordered by created_at DESC", func(t *testing.T) {
		tokens, err := ta.getCommunityTokensByLatest(ctx, "", 10, 0, nil)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(tokens), 3, "Should return at least our 3 test tokens")

		expectedAddresses := map[string]bool{
			token1Ext: true,
			token2Ext: true,
			token3Ext: true,
		}

		var foundTokens []*CommunityToken
		for _, token := range tokens {
			if expectedAddresses[token.Addresses.IonConnect] {
				foundTokens = append(foundTokens, token)
			}
		}
		require.Equal(t, 3, len(foundTokens), "Should find exactly 3 test tokens")

		// Verify order: newest first (token3 -> token2 -> token1,
		for i := 0; i < len(foundTokens)-1; i++ {
			require.True(t, foundTokens[i].CreatedAt.Time.After(*foundTokens[i+1].CreatedAt.Time) || foundTokens[i].CreatedAt.Time.Equal(*foundTokens[i+1].CreatedAt.Time), "Tokens should be ordered by created_at DESC")
		}
		expectedBlockchain := map[string]string{
			token1Ext: "0xLATEST1111111111111111111111111111111111",
			token2Ext: "0xLATEST2222222222222222222222222222222222",
			token3Ext: "0xLATEST3333333333333333333333333333333333",
		}

		for _, token := range foundTokens {
			require.NotNil(t, token.Addresses)
			require.True(t, expectedAddresses[token.Addresses.IonConnect], "IonConnect should be one of the test tokens")
			require.Empty(t, token.Addresses.Twitter)
			require.Equal(t, expectedBlockchain[token.Addresses.IonConnect], token.Addresses.Blockchain)

			require.NotEmpty(t, token.MarketData.Ticker, "Ticker should be present without keyword")
			require.Greater(t, token.MarketData.MarketCap, 0.0, "MarketCap should be > 0")
			require.Greater(t, token.MarketData.PriceUSD, 0.0, "PriceUSD should be > 0")
			require.GreaterOrEqual(t, token.MarketData.Volume, 0.0, "Volume should be >= 0")
			require.Greater(t, token.MarketData.Holders, uint64(0), "Holders should be > 0")
			require.Nil(t, token.MarketData.Position, "Position should be nil when user has no position")
			require.Equal(t, uint64(0), token.MarketData.PlatformHolders)
			require.Nil(t, token.MarketData.TopPlatformHolders)
			require.Nil(t, token.MarketData.BondingCurveProgress)

			// Verify creator.token: nil for profile tokens, populated for content tokens (post/video).
			if token.Type == "profile" {
				require.Nil(t, token.Creator.Token, "Profile token should not have creator.token")
			} else {
				require.NotNil(t, token.Creator.Token, "Content token (%s) should have creator.token", token.Type)
				require.NotEmpty(t, token.Creator.Token.Ticker, "Creator token ticker should not be empty")
				require.NotNil(t, token.Creator.Token.Addresses, "Creator token addresses should not be nil")
				require.NotEmpty(t, token.Creator.Token.Addresses.Blockchain, "Creator token blockchain address should not be empty")
			}
		}
	})

	t.Run("with keyword - uses CTE candidates and KNN search", func(t *testing.T) {
		tokens, err := ta.getCommunityTokensByLatest(ctx, "latest_one", 10, 0, nil)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(tokens), 1, "Should find matching token")

		found := false
		for _, token := range tokens {
			if strVal(token.Creator.Username) == "latest_one" {
				found = true

				require.Equal(t, "profile", token.Type)
				require.Equal(t, "latest_one", token.Title)
				require.Equal(t, "Latest One", token.Description)
				if !token.CreatedAt.IsZero() {
					require.True(t, token.CreatedAt.Before(time.Now().Add(time.Second)))
				}

				require.NotNil(t, token.Addresses)
				require.Equal(t, token1Ext, token.Addresses.IonConnect)
				require.Empty(t, token.Addresses.Twitter)
				require.Equal(t, "0xLATEST1111111111111111111111111111111111", token.Addresses.Blockchain)

				require.NotNil(t, token.Creator.Addresses)
				require.Equal(t, "creator_latest1", token.Creator.Addresses.IonConnect)
				require.Empty(t, token.Creator.Addresses.Twitter)
				require.Equal(t, "0x0000000000000000000000000creator_latest1", token.Creator.Addresses.Blockchain)

				require.Equal(t, "latest_one", strVal(token.Creator.Username))
				require.Equal(t, "Latest One", strVal(token.Creator.Display))
				require.True(t, token.Creator.Verified != nil && *token.Creator.Verified)

				require.NotEmpty(t, token.MarketData.Ticker, "Ticker should be present")
				require.Equal(t, "LAT1", token.MarketData.Ticker)
				require.InDelta(t, 100.0, token.MarketData.MarketCap, 0.01)
				require.Greater(t, token.MarketData.Volume, 0.0, "Volume should be present")
				require.InDelta(t, 0.0001, token.MarketData.PriceUSD, 0.00001)
				require.Equal(t, uint64(5), token.MarketData.Holders)

				require.Nil(t, token.Creator.Token, "Profile token should not have creator.token")

				break
			}
		}
		require.True(t, found, "Should find token with username 'latest_one'")
	})

	t.Run("with keyword - results ordered by relevance then created_at", func(t *testing.T) {
		tokens, err := ta.getCommunityTokensByLatest(ctx, "latest", 10, 0, nil)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(tokens), 3, "Should find all matching tokens")

		for _, token := range tokens {
			require.Contains(t, strings.ToLower(strVal(token.Creator.Username)), "latest", "Username should contain 'latest'")
		}
	})

	t.Run("with tokenType filter and no keyword", func(t *testing.T) {
		tokenType := "profile"
		tokens, err := ta.getCommunityTokensByLatest(ctx, "", 10, 0, &tokenType)
		require.NoError(t, err)

		found := false
		for _, token := range tokens {
			if token.Addresses.IonConnect == token1Ext {
				found = true
				require.Equal(t, "profile", token.Type)
				break
			}
		}
		require.True(t, found, "Should find profile token")
	})

	t.Run("with tokenType filter and keyword", func(t *testing.T) {
		tokenType := "post"
		tokens, err := ta.getCommunityTokensByLatest(ctx, "latest", 10, 0, &tokenType)
		require.NoError(t, err)

		for _, token := range tokens {
			if strings.Contains(strVal(token.Creator.Username), "latest") {
				require.Equal(t, "post", token.Type)
			}
		}
	})

	t.Run("with keyword - pagination works", func(t *testing.T) {
		tokens1, err := ta.getCommunityTokensByLatest(ctx, "latest", 2, 0, nil)
		require.NoError(t, err)
		require.LessOrEqual(t, len(tokens1), 2)

		tokens2, err := ta.getCommunityTokensByLatest(ctx, "latest", 2, 2, nil)
		require.NoError(t, err)
		require.LessOrEqual(t, len(tokens2), 2)

		if len(tokens1) > 0 && len(tokens2) > 0 {
			require.NotEqual(t, tokens1[0].Addresses.IonConnect, tokens2[0].Addresses.IonConnect)
		}
	})
}

func TestGetCommunityTokensByFeatured(t *testing.T) {
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()

	ta := helperNewForTest(t, db)

	helperInsertTestUser(t, ctx, db, "creator_featured1", "featured_one", "Featured One", "", true, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, db, "creator_featured2", "featured_two", "Featured Two", "", false, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, db, "creator_featured3", "featured_three", "Featured Three", "", true, PlatformGroupIonConnect)

	token1Ext := "0:creator_featured1:"
	token2Ext := "30023:creator_featured2:post1"
	token3Ext := "30175:creator_featured3:video1"

	helperInsertTestToken(t, ctx, db, "0xFEATURE1111111111111111111111111111111111", token1Ext, "FEA1", "profile", "creator_featured1", "1000000000000000000000000", 100.0, 0.0001, 5, PlatformGroupIonConnect)
	helperUpdateTokenBondingCurve(t, ctx, db,
		token1Ext,
		"80000000000000000000000",  // 80k tokens current
		"200000000000000000000000", // 200k tokens goal
		160.0,                      // $160 USD current
		400.0,                      // $400 USD goal
		"120000000000000000000",    // 120 tokens raised (wei)
		false,                      // not migrated
	)
	time.Sleep(10 * time.Millisecond)

	creator2FeatProfileExt := "0:creator_featured2:"
	helperInsertTestToken(t, ctx, db, "0xFEA2PROFILE111111111111111111111111111", creator2FeatProfileExt, "CFE2", "profile", "creator_featured2", "400000000000000000000000", 40.0, 0.00004, 2, PlatformGroupIonConnect)

	helperInsertTestToken(t, ctx, db, "0xFEATURE2222222222222222222222222222222222", token2Ext, "FEA2", "post", "creator_featured2", "2000000000000000000000000", 200.0, 0.0002, 10, PlatformGroupIonConnect)
	helperSetTokenBaseToken(t, ctx, db, token2Ext, "0xFEA2PROFILE111111111111111111111111111")
	time.Sleep(10 * time.Millisecond)

	creator3FeatProfileExt := "0:creator_featured3:"
	helperInsertTestToken(t, ctx, db, "0xFEA3PROFILE111111111111111111111111111", creator3FeatProfileExt, "CFE3", "profile", "creator_featured3", "500000000000000000000000", 50.0, 0.00005, 3, PlatformGroupIonConnect)

	helperInsertTestToken(t, ctx, db, "0xFEATURE3333333333333333333333333333333333", token3Ext, "FEA3", "video", "creator_featured3", "3000000000000000000000000", 300.0, 0.0003, 15, PlatformGroupIonConnect)
	helperSetTokenBaseToken(t, ctx, db, token3Ext, "0xFEA3PROFILE111111111111111111111111111")

	helperCreateSwapForVolume(t, ctx, db, "0xFEATURE1111111111111111111111111111111111", token1Ext, "0x0000000000000000000000000000000000000001", false, "100000000000000000000", "1000000000000000000000", 0.0001)
	helperCreateSwapForVolume(t, ctx, db, "0xFEATURE2222222222222222222222222222222222", token2Ext, "0x0000000000000000000000000000000000000002", false, "200000000000000000000", "2000000000000000000000", 0.0002)
	helperCreateSwapForVolume(t, ctx, db, "0xFEATURE3333333333333333333333333333333333", token3Ext, "0x0000000000000000000000000000000000000003", false, "300000000000000000000", "3000000000000000000000", 0.0003)
	helperRefreshVolumeView(t, ctx, db)

	helperInsertFeaturedToken(t, ctx, db, token1Ext)
	time.Sleep(10 * time.Millisecond)
	helperInsertFeaturedToken(t, ctx, db, token2Ext)
	time.Sleep(10 * time.Millisecond)
	helperInsertFeaturedToken(t, ctx, db, token3Ext)

	t.Run("returns featured tokens ordered by tokens_featured.created_at DESC", func(t *testing.T) {
		tokens, err := ta.getCommunityTokensByFeatured(ctx, 10, 0, nil)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(tokens), 3, "Should return at least our 3 featured tokens")

		expectedAddresses := map[string]bool{
			token1Ext: true,
			token2Ext: true,
			token3Ext: true,
		}

		var foundTokens []*CommunityToken
		for _, token := range tokens {
			if expectedAddresses[token.Addresses.IonConnect] {
				foundTokens = append(foundTokens, token)
			}
		}
		require.GreaterOrEqual(t, len(foundTokens), 3)

		// Verify order: newest featured first
		for i := 0; i < len(foundTokens)-1; i++ {
			require.True(t, foundTokens[i].CreatedAt.Time.After(*foundTokens[i+1].CreatedAt.Time) || foundTokens[i].CreatedAt.Time.Equal(*foundTokens[i+1].CreatedAt.Time), "Tokens should be ordered by featured date DESC")
		}

		for _, token := range foundTokens {
			require.NotEmpty(t, token.MarketData.Ticker, "Ticker should be present")
			require.Greater(t, token.MarketData.MarketCap, 0.0, "MarketCap should be > 0")
			require.Greater(t, token.MarketData.PriceUSD, 0.0, "PriceUSD should be > 0")
			require.GreaterOrEqual(t, token.MarketData.Volume, 0.0, "Volume should be >= 0")
			require.Greater(t, token.MarketData.Holders, uint64(0), "Holders should be > 0")

			require.Nil(t, token.MarketData.Position, "Position should be nil when user has no position")
			require.Equal(t, uint64(0), token.MarketData.PlatformHolders)
			require.Nil(t, token.MarketData.TopPlatformHolders)

			if token.MarketData.Ticker == "FEA1" {
				require.NotNil(t, token.MarketData.BondingCurveProgress)
				require.Equal(t, "80000000000000000000000", token.MarketData.BondingCurveProgress.CurrentAmount)
				require.Equal(t, "200000000000000000000000", token.MarketData.BondingCurveProgress.GoalAmount)
				require.InDelta(t, 160.0, token.MarketData.BondingCurveProgress.CurrentAmountUSD, 0.01)
				require.InDelta(t, 400.0, token.MarketData.BondingCurveProgress.GoalAmountUSD, 0.01)
				require.Nil(t, token.Creator.Token, "Profile token (FEA1) should not have creator.token")
			} else {
				require.Nil(t, token.MarketData.BondingCurveProgress)
				require.NotNil(t, token.Creator.Token, "Content token (%s / %s) should have creator.token", token.MarketData.Ticker, token.Type)
				require.NotEmpty(t, token.Creator.Token.Ticker)
				require.NotNil(t, token.Creator.Token.Addresses)
				require.NotEmpty(t, token.Creator.Token.Addresses.Blockchain)
			}
		}
	})

	t.Run("with tokenType filter - returns only matching type", func(t *testing.T) {
		tokenType := "profile"
		tokens, err := ta.getCommunityTokensByFeatured(ctx, 10, 0, &tokenType)
		require.NoError(t, err)

		found := false
		for _, token := range tokens {
			if token.Addresses.IonConnect == token1Ext {
				found = true
				require.Equal(t, "profile", token.Type)
				require.Equal(t, "featured_one", strVal(token.Creator.Username))
				require.Equal(t, "Featured One", strVal(token.Creator.Display))
				require.True(t, token.Creator.Verified != nil && *token.Creator.Verified)
				require.Nil(t, token.Creator.Token, "Profile token should not have creator.token")
				break
			}
		}
		require.True(t, found, "Should find featured profile token")
	})

	t.Run("pagination works correctly", func(t *testing.T) {
		tokens1, err := ta.getCommunityTokensByFeatured(ctx, 2, 0, nil)
		require.NoError(t, err)
		require.LessOrEqual(t, len(tokens1), 2)

		tokens2, err := ta.getCommunityTokensByFeatured(ctx, 2, 2, nil)
		require.NoError(t, err)

		if len(tokens1) > 0 && len(tokens2) > 0 {
			// Verify no overlap between pages
			for _, t1 := range tokens1 {
				for _, t2 := range tokens2 {
					require.NotEqual(t, t1.Addresses.IonConnect, t2.Addresses.IonConnect, "Pages should not overlap")
				}
			}
		}
	})

	t.Run("returns empty for non-existent tokenType", func(t *testing.T) {
		tokenType := "nonexistent"
		tokens, err := ta.getCommunityTokensByFeatured(ctx, 10, 0, &tokenType)
		require.NoError(t, err)

		for _, token := range tokens {
			require.NotEqual(t, "nonexistent", token.Type)
		}
	})

	t.Run("X.com tokens with IonConnect address should extract pubkey for creator", func(t *testing.T) {
		creatorExternalAddr := "987654321"
		helperInsertTestUser(t, ctx, db, creatorExternalAddr, "xcom_type_creator", "X.com Type Creator", "", true, PlatformGroupXCom)

		tokenExternalAddr := creatorExternalAddr
		expectedPubkey := "8abc4f296310ab5a2818d729b796c26f7ffa88e834f954084eded0236e26cd3e"
		ionConnectAddress := fmt.Sprintf("31751:%s:xyz789", expectedPubkey)

		contractAddr := "0xTYPEXCOMION11111111111111111111111111"
		helperInsertTestToken(t, ctx, db,
			contractAddr,
			tokenExternalAddr,
			"TXCION",
			"video",
			creatorExternalAddr,
			"3000000000000000000000",
			55.75,
			0.00012,
			12,
			PlatformGroupXCom,
		)
		_, err := storage.Exec(ctx, db,
			`UPDATE tokens SET ion_connect_address = $1 WHERE external_address = $2`,
			ionConnectAddress, tokenExternalAddr)
		require.NoError(t, err)

		helperInsertFeaturedToken(t, ctx, db, tokenExternalAddr)
		tokens, err := ta.getCommunityTokensByFeatured(ctx, 50, 0, nil)
		require.NoError(t, err)

		var foundToken *CommunityToken
		for i := range tokens {
			if tokens[i].Addresses.Twitter == tokenExternalAddr {
				foundToken = tokens[i]
				break
			}
		}

		require.NotNil(t, foundToken, "Should find X.com token with IonConnect")
		require.NotNil(t, foundToken.Addresses, "Token addresses should not be nil")
		require.Equal(t, ionConnectAddress, foundToken.Addresses.IonConnect,
			"Token IonConnect should contain full ion_connect_address in format 31751:pubkey:xxx")
		require.Equal(t, tokenExternalAddr, foundToken.Addresses.Twitter, "Token Twitter should be external_address")

		require.NotNil(t, foundToken.Creator.Addresses, "Creator addresses should not be nil")
		require.Equal(t, expectedPubkey, foundToken.Creator.Addresses.IonConnect,
			"Creator IonConnect should contain extracted pubkey from token external address")
		require.NotEmpty(t, foundToken.Creator.Addresses.Twitter, "Creator should have Twitter address")
	})
}

func TestGetCommunityTokensByLatest_CreatorNotRegistered(t *testing.T) {
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()

	ta := helperNewForTest(t, db)

	unregisteredCreatorPubkey := "unregistered_creator_pubkey_not_in_db"
	unregisteredCreatorAddr := "0xUNREGISTERED1234567890123456789012345678"
	tokenExternalAddr := "30023:unregistered_pubkey_abc123:019b-test-uuid"
	contractAddr := "0xTOKEN999999999999999999999999999999999"

	helperInsertTestUser(t, ctx, db, unregisteredCreatorPubkey, "", "", unregisteredCreatorAddr, false, PlatformGroupIonConnect)

	unregCreatorProfileExt := "0:unregistered_creator_pubkey_not_in_db:"
	unregCreatorProfileContract := "0xUNREGPROFILE1111111111111111111111111"
	helperInsertTestToken(t, ctx, db, unregCreatorProfileContract, unregCreatorProfileExt, "UNREG", "profile", unregisteredCreatorPubkey, "500000000000000000000000", 25.0, 0.00002, 1, PlatformGroupIonConnect)

	helperInsertTestToken(t, ctx, db,
		contractAddr,
		tokenExternalAddr,
		"TOKEN999",
		"article",
		unregisteredCreatorPubkey,
		"1000000000000000000000000",
		150.0,
		0.00015,
		3,
		PlatformGroupIonConnect,
	)
	helperSetTokenBaseToken(t, ctx, db, tokenExternalAddr, unregCreatorProfileContract)

	t.Run("token with unregistered creator should not fail", func(t *testing.T) {
		tokens, err := ta.getCommunityTokensByLatest(ctx, "", 50, 0, nil)
		require.NoError(t, err, "Should not fail when creator is not registered")

		var foundToken *CommunityToken
		for _, token := range tokens {
			if token.Addresses.IonConnect == tokenExternalAddr {
				foundToken = token
				break
			}
		}

		require.NotNil(t, foundToken, "Should find token even when creator is not registered")
		require.Equal(t, "article", foundToken.Type)
		require.Equal(t, tokenExternalAddr, foundToken.Addresses.IonConnect)

		require.Empty(t, strVal(foundToken.Creator.Username), "Creator username should be empty for unregistered creator")
		require.Empty(t, strVal(foundToken.Creator.Display), "Creator display should be empty for unregistered creator")
		require.False(t, foundToken.Creator.Verified != nil && *foundToken.Creator.Verified, "Creator verified should be false or nil")

		require.NotNil(t, foundToken.Creator.Addresses, "Creator addresses should not be nil")
		require.Equal(t, unregisteredCreatorPubkey, foundToken.Creator.Addresses.IonConnect,
			"Creator should have IonConnect address from external_address")

		require.InDelta(t, 150.0, foundToken.MarketData.MarketCap, 0.01)
		require.InDelta(t, 0.00015, foundToken.MarketData.PriceUSD, 0.000001)
		require.Equal(t, uint64(3), foundToken.MarketData.Holders)

		require.NotNil(t, foundToken.Creator.Token, "Article token should have creator.token")
		require.Equal(t, "UNREG", foundToken.Creator.Token.Ticker)
		require.NotNil(t, foundToken.Creator.Token.Addresses)
		require.Equal(t, unregCreatorProfileContract, foundToken.Creator.Token.Addresses.Blockchain)
	})

	t.Run("featured tokens with unregistered creator should not fail", func(t *testing.T) {
		helperInsertFeaturedToken(t, ctx, db, tokenExternalAddr)

		tokens, err := ta.getCommunityTokensByFeatured(ctx, 50, 0, nil)
		require.NoError(t, err, "Featured should not fail when creator is not registered")

		var foundToken *CommunityToken
		for _, token := range tokens {
			if token.Addresses.IonConnect == tokenExternalAddr {
				foundToken = token
				break
			}
		}

		require.NotNil(t, foundToken, "Should find featured token even when creator is not registered")
		require.NotNil(t, foundToken.Creator.Addresses, "Creator addresses should not be nil")
		require.Equal(t, unregisteredCreatorPubkey, foundToken.Creator.Addresses.IonConnect,
			"Creator should have IonConnect address from external_address")

		require.NotNil(t, foundToken.Creator.Token, "Article token should have creator.token")
		require.Equal(t, "UNREG", foundToken.Creator.Token.Ticker)
	})
}

func TestGetCommunityTokensByRewardsDistribution(t *testing.T) {
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()

	ta := helperNewForTest(t, db)

	helperInsertTestUser(t, ctx, db, "rd_creator1", "rd_alice", "RD Alice", "", true, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, db, "rd_creator2", "rd_bob", "RD Bob", "", false, PlatformGroupIonConnect)

	token1Ext := "0:rd_creator1:"
	token2Ext := "0:rd_creator2:"

	helperInsertTestToken(t, ctx, db, "0xRD111111111111111111111111111111111111", token1Ext, "RD1", "profile", "rd_creator1", "1000000000000000000000000", 500.0, 0.001, 10, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, db, "0xRD222222222222222222222222222222222222", token2Ext, "RD2", "profile", "rd_creator2", "2000000000000000000000000", 300.0, 0.002, 5, PlatformGroupIonConnect)

	t.Run("returns tokens from trending set ordered by volume", func(t *testing.T) {
		_ = testRedis.Del(ctx, globalTrendingSetKey).Err()

		helperSetupGlobalSet(t, ctx, globalTrendingSetKey, map[string]float64{
			token1Ext: 5000.0 * 1e18,
			token2Ext: 3000.0 * 1e18,
		})
		helperSetupGlobalSet(t, ctx, globalTopSetKey, map[string]float64{
			token1Ext: 500.0,
			token2Ext: 300.0,
		})

		referenceDate := time.Now()
		tokens, err := ta.GetCommunityTokensByRewardsDistribution(ctx, referenceDate, 10, 0)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(tokens), 2, "Should return at least 2 test tokens")

		var found1, found2 *CommunityToken
		for _, token := range tokens {
			switch token.Addresses.IonConnect {
			case token1Ext:
				found1 = token
			case token2Ext:
				found2 = token
			}
		}
		require.NotNil(t, found1, "Should find token1")
		require.NotNil(t, found2, "Should find token2")

		require.Equal(t, "RD1", found1.MarketData.Ticker)
		require.InDelta(t, 5000.0, found1.MarketData.Volume, 1.0)
		require.InDelta(t, 500.0, found1.MarketData.MarketCap, 1.0)

		require.Equal(t, "RD2", found2.MarketData.Ticker)
		require.InDelta(t, 3000.0, found2.MarketData.Volume, 1.0)
		require.InDelta(t, 300.0, found2.MarketData.MarketCap, 1.0)

		require.Nil(t, found1.Creator.Token, "Profile token should not have creator.token")
		require.Nil(t, found2.Creator.Token, "Profile token should not have creator.token")
	})

	t.Run("returns empty when no trending data", func(t *testing.T) {
		_ = testRedis.Del(ctx, globalTrendingSetKey).Err()

		referenceDate := time.Now()
		tokens, err := ta.GetCommunityTokensByRewardsDistribution(ctx, referenceDate, 10, 0)
		require.NoError(t, err)
		require.Empty(t, tokens)
	})

	t.Run("respects limit cap of 100", func(t *testing.T) {
		_ = testRedis.Del(ctx, globalTrendingSetKey).Err()

		members := make([]redis.Z, 0, 110)
		for i := 0; i < 110; i++ {
			members = append(members, redis.Z{
				Score:  float64(110 - i),
				Member: fmt.Sprintf("0:rd_limit_token_%d:", i),
			})
		}
		err := testRedis.ZAdd(ctx, globalTrendingSetKey, members...).Err()
		require.NoError(t, err)

		referenceDate := time.Now()
		tokens, err := ta.GetCommunityTokensByRewardsDistribution(ctx, referenceDate, 200, 0)
		require.NoError(t, err)
		require.LessOrEqual(t, len(tokens), 100, "Should return at most 100 tokens")
	})

	t.Run("pagination with offset works", func(t *testing.T) {
		_ = testRedis.Del(ctx, globalTrendingSetKey).Err()

		helperSetupGlobalSet(t, ctx, globalTrendingSetKey, map[string]float64{
			token1Ext: 5000.0 * 1e18,
			token2Ext: 3000.0 * 1e18,
		})
		helperSetupGlobalSet(t, ctx, globalTopSetKey, map[string]float64{
			token1Ext: 500.0,
			token2Ext: 300.0,
		})

		referenceDate := time.Now()
		tokens1, err := ta.GetCommunityTokensByRewardsDistribution(ctx, referenceDate, 1, 0)
		require.NoError(t, err)
		require.Len(t, tokens1, 1)

		tokens2, err := ta.GetCommunityTokensByRewardsDistribution(ctx, referenceDate, 1, 1)
		require.NoError(t, err)
		require.Len(t, tokens2, 1)

		if len(tokens1) > 0 && len(tokens2) > 0 {
			require.NotEqual(t, tokens1[0].MarketData.Ticker, tokens2[0].MarketData.Ticker, "Pages should not overlap")
		}
	})
}
