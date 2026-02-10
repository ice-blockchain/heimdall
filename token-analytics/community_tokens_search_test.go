// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSearchCommunityTokens(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()

	ta := helperNewForTest(t, db)

	t.Run("empty_keyword_returns_empty", func(t *testing.T) {
		tokens, err := ta.searchCommunityTokens(ctx, []string{}, "requestor123", "", 10, 0)
		require.NoError(t, err)
		require.Empty(t, tokens)
	})

	t.Run("search_by_username", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "search_creator1", "alice_search", "Alice Search", "", true, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "search_creator2", "bob_other", "Bob Other", "", false, PlatformGroupIonConnect)

		token1Ext := "0:search_creator1:"
		token2Ext := "0:search_creator2:"

		helperInsertTestToken(t, ctx, db, "0xSRCH1111111111111111111111111111111111", token1Ext, "SRCH1", "profile", "search_creator1", "1000000000000000000000000", 100.0, 0.0001, 5, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db, "0xSRCH2222222222222222222222222222222222", token2Ext, "SRCH2", "profile", "search_creator2", "2000000000000000000000000", 200.0, 0.0002, 10, PlatformGroupIonConnect)

		helperCreateSwapForVolume(t, ctx, db, "0xSRCH1111111111111111111111111111111111", token1Ext, "0x0000000000000000000000000000000000000001", false, "100000000000000000000", "1000000000000000000000", 0.0001)
		helperRefreshVolumeView(t, ctx, db)

		tokens, err := ta.searchCommunityTokens(ctx, []string{}, "requestor123", "alice", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		token := tokens[0]
		require.Equal(t, "alice_search", strVal(token.Creator.Username))
		require.Equal(t, "Alice Search", strVal(token.Creator.Display))
		require.True(t, token.Creator.Verified != nil && *token.Creator.Verified)
		require.Nil(t, token.MarketData.BondingCurveProgress, "BondingCurveProgress is not fetched in search")

		require.NotNil(t, token.Addresses)
		require.Equal(t, token1Ext, token.Addresses.IonConnect)
		require.Empty(t, token.Addresses.Twitter)
		require.Equal(t, "0xSRCH1111111111111111111111111111111111", token.Addresses.Blockchain)

		require.NotNil(t, token.Creator.Addresses)
		require.Equal(t, "search_creator1", token.Creator.Addresses.IonConnect)
		require.Empty(t, token.Creator.Addresses.Twitter)
		require.Empty(t, token.Creator.Addresses.Blockchain)
		require.Nil(t, token.MarketData.BondingCurveProgress, "BondingCurveProgress should be nil when not set")
	})

	t.Run("search_by_display_name", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "search_display_creator", "username123", "Unique Display Name", "", false, PlatformGroupIonConnect)
		tokenExt := "0:search_display_creator:"

		helperInsertTestToken(t, ctx, db, "0xDISP1111111111111111111111111111111111", tokenExt, "DISP", "profile", "search_display_creator", "3000000000000000000000000", 300.0, 0.0003, 15, PlatformGroupIonConnect)

		tokens, err := ta.searchCommunityTokens(ctx, []string{}, "requestor123", "unique display", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		token := tokens[0]
		require.Equal(t, "username123", strVal(token.Creator.Username))
		require.Equal(t, "Unique Display Name", strVal(token.Creator.Display))

		require.NotNil(t, token.Addresses)
		require.Equal(t, tokenExt, token.Addresses.IonConnect)
		require.Empty(t, token.Addresses.Twitter)
		require.Equal(t, "0xDISP1111111111111111111111111111111111", token.Addresses.Blockchain)
	})

	t.Run("search_by_ticker", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "search_ticker_creator", "ticker_user_unique", "Ticker User Unique", "", false, PlatformGroupIonConnect)
		tokenExt := "0:search_ticker_creator:"

		helperInsertTestToken(t, ctx, db, "0xTICKER111111111111111111111111111111", tokenExt, "UNIQTICKER", "profile", "search_ticker_creator", "4000000000000000000000000", 400.0, 0.0004, 20, PlatformGroupIonConnect)
		helperUpdateTokenBondingCurve(t, ctx, db,
			tokenExt,
			"100000000000000000000000", // 100k tokens current
			"250000000000000000000000", // 250k tokens goal
			200.0,                      // $200 USD current
			500.0,                      // $500 USD goal
			"200000000000000000000",    // 200 tokens raised (wei)
			false,                      // not migrated
		)

		tokens, err := ta.searchCommunityTokens(ctx, []string{}, "requestor123", "uniqticker", 10, 0)
		require.NoError(t, err)
		require.Equal(t, 1, len(tokens))

		var token *CommunityToken
		for _, t := range tokens {
			if t.MarketData.Ticker == "UNIQTICKER" {
				token = t
				break
			}
		}
		require.NotNil(t, token, "Should find token with ticker UNIQTICKER")
		require.Equal(t, "UNIQTICKER", token.MarketData.Ticker)
		require.Equal(t, "ticker_user_unique", strVal(token.Creator.Username))

		require.NotNil(t, token.Addresses)
		require.Equal(t, tokenExt, token.Addresses.IonConnect)
		require.Empty(t, token.Addresses.Twitter)
		require.Equal(t, "0xTICKER111111111111111111111111111111", token.Addresses.Blockchain)

		require.NotNil(t, token.MarketData.BondingCurveProgress)
		require.Equal(t, "100000000000000000000000", token.MarketData.BondingCurveProgress.CurrentAmount)
		require.Equal(t, "250000000000000000000000", token.MarketData.BondingCurveProgress.GoalAmount)
		require.InDelta(t, 200.0, token.MarketData.BondingCurveProgress.CurrentAmountUSD, 0.01)
		require.InDelta(t, 500.0, token.MarketData.BondingCurveProgress.GoalAmountUSD, 0.01)
	})

	t.Run("search_by_contract_address", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "search_contract_creator", "contract_user", "Contract User", "", false, PlatformGroupIonConnect)
		tokenExt := "0:search_contract_creator:"
		contractAddr := "0xABCDEF1234567890ABCDEF1234567890ABCD"

		helperInsertTestToken(t, ctx, db, contractAddr, tokenExt, "CNTR", "profile", "search_contract_creator", "8000000000000000000000000", 800.0, 0.0008, 40, PlatformGroupIonConnect)

		tokens1, err := ta.searchCommunityTokens(ctx, []string{}, "requestor123", contractAddr, 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens1, 1)
		require.Equal(t, contractAddr, tokens1[0].Addresses.Blockchain)
	})

	t.Run("search_with_pagination", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			creator := helperTestUniqueID(t, "search_page_creator", i)
			helperInsertTestUser(t, ctx, db, creator, helperTestUniqueID(t, "page_search", i), helperTestUniqueID(t, "Page Search", i), "", false, PlatformGroupIonConnect)

			tokenExt := "0:" + creator + ":"
			helperInsertTestToken(t, ctx, db,
				helperTestUniqueID(t, "0xPAGESRCH", i)+"111111111111111111111111",
				tokenExt,
				helperTestUniqueID(t, "PGS", i),
				"profile",
				creator,
				"1000000000000000000000000",
				float64(100+i*50),
				0.0001,
				1,
				PlatformGroupIonConnect,
			)
		}

		// Page 1
		tokens1, err := ta.searchCommunityTokens(ctx, []string{}, "requestor123", "page_search", 2, 0)
		require.NoError(t, err)
		require.LessOrEqual(t, len(tokens1), 2)

		// Page 2
		tokens2, err := ta.searchCommunityTokens(ctx, []string{}, "requestor123", "page_search", 2, 2)
		require.NoError(t, err)
		require.LessOrEqual(t, len(tokens2), 2)

		if len(tokens1) > 0 && len(tokens2) > 0 {
			for _, t1 := range tokens1 {
				for _, t2 := range tokens2 {
					require.NotEqual(t, t1.Addresses.IonConnect, t2.Addresses.IonConnect)
				}
			}
		}
	})

	t.Run("search_case_insensitive", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "search_case_creator", "CamelCase", "Camel Case User", "", false, PlatformGroupIonConnect)
		tokenExt := "0:search_case_creator:"

		helperInsertTestToken(t, ctx, db, "0xCASE1111111111111111111111111111111111", tokenExt, "CASE", "profile", "search_case_creator", "6000000000000000000000000", 600.0, 0.0006, 30, PlatformGroupIonConnect)

		tokens1, err := ta.searchCommunityTokens(ctx, []string{}, "requestor123", "camelcase", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens1, 1)

		tokens2, err := ta.searchCommunityTokens(ctx, []string{}, "requestor123", "CAMELCASE", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens2, 1)

		tokens3, err := ta.searchCommunityTokens(ctx, []string{}, "requestor123", "CaMeLcAsE", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens3, 1)

		require.Equal(t, tokens1[0].Addresses.IonConnect, tokens2[0].Addresses.IonConnect)
		require.Equal(t, tokens2[0].Addresses.IonConnect, tokens3[0].Addresses.IonConnect)
	})

	t.Run("search_no_results_for_nonexistent_keyword", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "search_nomatch_creator", "existing_user", "Existing User", "", false, PlatformGroupIonConnect)
		tokenExt := "0:search_nomatch_creator:"

		helperInsertTestToken(t, ctx, db, "0xNOMATCH111111111111111111111111111", tokenExt, "NOMA", "profile", "search_nomatch_creator", "7000000000000000000000000", 700.0, 0.0007, 35, PlatformGroupIonConnect)

		tokens, err := ta.searchCommunityTokens(ctx, []string{}, "requestor123", "nonexistent_keyword_xyz", 10, 0)
		require.NoError(t, err)
		require.Empty(t, tokens)
	})

	t.Run("search_returns_all_token_fields", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "search_full_creator", "full_user", "Full User", "", true, PlatformGroupIonConnect, "https://avatar-full.png")
		tokenExt := "0:search_full_creator:"
		contractAddr := "0xFULLSRCH111111111111111111111111111"

		helperInsertTestToken(t, ctx, db, contractAddr, tokenExt, "FULL", "profile", "search_full_creator", "10000000000000000000000000", 1000.0, 0.001, 50, PlatformGroupIonConnect)

		tokens, err := ta.searchCommunityTokens(ctx, []string{}, "requestor123", "full user", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		token := tokens[0]

		require.Equal(t, "profile", token.Type)
		require.Equal(t, "full_user", token.Title)
		require.Equal(t, "Full User", token.Description)
		require.Equal(t, "https://avatar-full.png", token.ImageURL)
		require.NotNil(t, token.CreatedAt)
		require.False(t, token.CreatedAt.IsZero())

		require.NotNil(t, token.Addresses)
		require.Equal(t, tokenExt, token.Addresses.IonConnect)
		require.Empty(t, token.Addresses.Twitter)
		require.Equal(t, contractAddr, token.Addresses.Blockchain)

		require.Equal(t, "full_user", strVal(token.Creator.Username))
		require.Equal(t, "Full User", strVal(token.Creator.Display))
		require.True(t, token.Creator.Verified != nil && *token.Creator.Verified)
		require.Equal(t, "https://avatar-full.png", strVal(token.Creator.Avatar))
		require.NotNil(t, token.Creator.Addresses)
		require.Equal(t, "search_full_creator", token.Creator.Addresses.IonConnect)
		require.Empty(t, token.Creator.Addresses.Twitter)
		require.Empty(t, token.Creator.Addresses.Blockchain)

		require.Equal(t, "FULL", token.MarketData.Ticker)
		require.InDelta(t, 1000.0, token.MarketData.MarketCap, 1.0)
		require.InDelta(t, 0.001, token.MarketData.PriceUSD, 0.0001)
		require.Equal(t, uint64(50), token.MarketData.Holders)
		require.Nil(t, token.MarketData.BondingCurveProgress, "BondingCurveProgress should be nil when not set")
	})
}
