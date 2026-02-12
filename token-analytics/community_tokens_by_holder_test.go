// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func TestGetCommunityTokensByHolder(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()

	ta := helperNewForTest(t, db)

	t.Run("empty_holder_returns_empty_result", func(t *testing.T) {
		tokens, totalHoldings, err := ta.GetCommunityTokensByHolder(ctx, "", "requestor_empty", 10, 0)
		require.NoError(t, err)
		require.Empty(t, tokens)
		require.Equal(t, uint64(0), totalHoldings)
	})

	t.Run("holder_without_positions_returns_empty", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "holder_no_pos", "holder_no_pos", "Holder No Pos", "", false, PlatformGroupIonConnect)
		holderExtAddr := "0:holder_no_pos:"

		tokens, totalHoldings, err := ta.GetCommunityTokensByHolder(ctx, holderExtAddr, "requestor123", 10, 0)
		require.NoError(t, err)
		require.Empty(t, tokens)
		require.Equal(t, uint64(0), totalHoldings)
	})

	t.Run("holder_with_single_position", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "creator_h1", "creator_h1", "Creator H1", "", true, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "holder_h1", "holder_h1", "Holder H1", "", false, PlatformGroupIonConnect)

		tokenExt := "0:creator_h1:"
		holderExtAddr := "0:holder_h1:"
		contractAddr := "0xH1TOKEN111111111111111111111111111111"

		helperInsertTestToken(t, ctx, db, contractAddr, tokenExt, "H1TK", "profile", "creator_h1", "1000000000000000000000000", 100.0, 0.0001, 5, PlatformGroupIonConnect)
		helperInsertUserTokenPosition(t, ctx, db, "holder_h1", contractAddr, tokenExt, holderExtAddr, "5000000000000000000000", 0.0001, 0.5)
		helperSetupRedisPositionData(t, ctx, testRedis, tokenExt, map[string]float64{
			holderExtAddr: 5000.0,
		})

		tokens, totalHoldings, err := ta.GetCommunityTokensByHolder(ctx, holderExtAddr, "holder_h1", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)
		require.Equal(t, uint64(1), totalHoldings)

		token := tokens[0]
		require.Equal(t, "profile", token.Type)

		require.NotNil(t, token.Addresses)
		require.Equal(t, tokenExt, token.Addresses.IonConnect)
		require.Empty(t, token.Addresses.Twitter)
		require.Equal(t, contractAddr, token.Addresses.Blockchain)

		require.Equal(t, "H1TK", token.MarketData.Ticker)
		require.Nil(t, token.MarketData.BondingCurveProgress, "BondingCurveProgress should be nil when not set")
		require.NotNil(t, token.MarketData.Position)
		require.Equal(t, "5000000000000000000000", token.MarketData.Position.Amount)
		require.Nil(t, token.Creator.Token, "Profile token should not have creator.token")
	})

	t.Run("holder_with_multiple_positions_sorted_by_amount_desc", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "creator_multi", "creator_multi", "Creator Multi", "", true, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "holder_multi", "holder_multi", "Holder Multi", "", false, PlatformGroupIonConnect)

		holderExtAddr := "0:holder_multi:"

		tokens := []struct {
			contractAddr string
			tokenExt     string
			ticker       string
			amount       string
			amountFloat  float64
		}{
			{"0xMULTI1111111111111111111111111111111", "0:creator_multi:token1", "MTK1", "10000000000000000000000", 10000.0}, // 10,000 tokens
			{"0xMULTI2222222222222222222222222222222", "0:creator_multi:token2", "MTK2", "50000000000000000000000", 50000.0}, // 50,000 tokens (highest)
			{"0xMULTI3333333333333333333333333333333", "0:creator_multi:token3", "MTK3", "5000000000000000000000", 5000.0},   // 5,000 tokens
			{"0xMULTI4444444444444444444444444444444", "0:creator_multi:token4", "MTK4", "20000000000000000000000", 20000.0}, // 20,000 tokens
			{"0xMULTI5555555555555555555555555555555", "0:creator_multi:token5", "MTK5", "1000000000000000000000", 1000.0},   // 1,000 tokens (lowest)
		}

		for _, tk := range tokens {
			helperInsertTestToken(t, ctx, db, tk.contractAddr, tk.tokenExt, tk.ticker, "profile", "creator_multi", "100000000000000000000000", 100.0, 0.001, 5, PlatformGroupIonConnect)
			helperInsertUserTokenPosition(t, ctx, db, "holder_multi", tk.contractAddr, tk.tokenExt, holderExtAddr, tk.amount, 0.001, 0.5)
			helperSetupRedisPositionData(t, ctx, testRedis, tk.tokenExt, map[string]float64{
				holderExtAddr: tk.amountFloat,
			})
		}

		result, totalHoldings, err := ta.GetCommunityTokensByHolder(ctx, holderExtAddr, "holder_multi", 10, 0)
		require.NoError(t, err)
		require.Len(t, result, 5)
		require.Equal(t, uint64(5), totalHoldings)

		// Verify sorting: MTK2 (50k) > MTK4 (20k) > MTK1 (10k) > MTK3 (5k) > MTK5 (1k)
		require.Equal(t, "MTK2", result[0].MarketData.Ticker)
		require.Equal(t, "MTK4", result[1].MarketData.Ticker)
		require.Equal(t, "MTK1", result[2].MarketData.Ticker)
		require.Equal(t, "MTK3", result[3].MarketData.Ticker)
		require.Equal(t, "MTK5", result[4].MarketData.Ticker)
	})

	t.Run("pagination_limit_and_offset", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "creator_page", "creator_page", "Creator Page", "", true, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "holder_page", "holder_page", "Holder Page", "", false, PlatformGroupIonConnect)

		holderExtAddr := "0:holder_page:"

		// Create 7 tokens
		for i := 1; i <= 7; i++ {
			contractAddr := fmt.Sprintf("0xPAGE%02d111111111111111111111111111111", i)
			tokenExt := fmt.Sprintf("0:creator_page:token%d", i)
			ticker := fmt.Sprintf("PAGE%d", i)
			amount := fmt.Sprintf("%d000000000000000000000", (8-i)*1000) // Descending amounts

			helperInsertTestToken(t, ctx, db, contractAddr, tokenExt, ticker, "profile", "creator_page", "100000000000000000000000", 100.0, 0.001, 5, PlatformGroupIonConnect)
			helperInsertUserTokenPosition(t, ctx, db, "holder_page", contractAddr, tokenExt, holderExtAddr, amount, 0.001, 0.5)
			helperSetupRedisPositionData(t, ctx, testRedis, tokenExt, map[string]float64{
				holderExtAddr: float64((8 - i) * 1000),
			})
		}

		// Page 1: limit=3, offset=0
		page1, totalHoldings1, err := ta.GetCommunityTokensByHolder(ctx, holderExtAddr, "holder_page", 3, 0)
		require.NoError(t, err)
		require.Len(t, page1, 3)
		require.Equal(t, uint64(7), totalHoldings1, "Total holdings should be 7")
		require.Equal(t, "PAGE1", page1[0].MarketData.Ticker)
		require.Equal(t, "PAGE2", page1[1].MarketData.Ticker)
		require.Equal(t, "PAGE3", page1[2].MarketData.Ticker)

		// Page 2: limit=3, offset=3
		page2, totalHoldings2, err := ta.GetCommunityTokensByHolder(ctx, holderExtAddr, "holder_page", 3, 3)
		require.NoError(t, err)
		require.Len(t, page2, 3)
		require.Equal(t, uint64(7), totalHoldings2, "Total holdings should still be 7")
		require.Equal(t, "PAGE4", page2[0].MarketData.Ticker)
		require.Equal(t, "PAGE5", page2[1].MarketData.Ticker)
		require.Equal(t, "PAGE6", page2[2].MarketData.Ticker)

		// Page 3: limit=3, offset=6 (only 1 remaining)
		page3, totalHoldings3, err := ta.GetCommunityTokensByHolder(ctx, holderExtAddr, "holder_page", 3, 6)
		require.NoError(t, err)
		require.Len(t, page3, 1)
		require.Equal(t, uint64(7), totalHoldings3)
		require.Equal(t, "PAGE7", page3[0].MarketData.Ticker)
	})

	t.Run("pages_do_not_overlap", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "creator_overlap", "creator_overlap", "Creator Overlap", "", true, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "holder_overlap", "holder_overlap", "Holder Overlap", "", false, PlatformGroupIonConnect)

		holderExtAddr := "0:holder_overlap:"

		for i := 1; i <= 5; i++ {
			contractAddr := fmt.Sprintf("0xOVER%02d111111111111111111111111111111", i)
			tokenExt := fmt.Sprintf("0:creator_overlap:token%d", i)
			ticker := fmt.Sprintf("OVR%d", i)
			amount := fmt.Sprintf("%d000000000000000000000", (6-i)*1000)

			helperInsertTestToken(t, ctx, db, contractAddr, tokenExt, ticker, "profile", "creator_overlap", "100000000000000000000000", 100.0, 0.001, 5, PlatformGroupIonConnect)
			helperInsertUserTokenPosition(t, ctx, db, "holder_overlap", contractAddr, tokenExt, holderExtAddr, amount, 0.001, 0.5)
			helperSetupRedisPositionData(t, ctx, testRedis, tokenExt, map[string]float64{
				holderExtAddr: float64((6 - i) * 1000),
			})
		}

		page1, _, err := ta.GetCommunityTokensByHolder(ctx, holderExtAddr, "holder_overlap", 2, 0)
		require.NoError(t, err)
		page2, _, err := ta.GetCommunityTokensByHolder(ctx, holderExtAddr, "holder_overlap", 2, 2)
		require.NoError(t, err)

		// Verify no overlap
		for _, t1 := range page1 {
			for _, t2 := range page2 {
				require.NotEqual(t, t1.MarketData.Ticker, t2.MarketData.Ticker, "Pages should not overlap")
			}
		}
	})

	t.Run("holder_position_includes_all_token_fields", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "creator_full", "creator_full_user", "Creator Full Display", "", true, PlatformGroupIonConnect, "https://avatar-full.png")
		helperInsertTestUser(t, ctx, db, "holder_full", "holder_full", "Holder Full", "", false, PlatformGroupIonConnect)

		tokenExt := "0:creator_full:"
		creatorPubkey := "creator_full"
		holderExtAddr := "0:holder_full:"
		contractAddr := "0xFULL1111111111111111111111111111111111"

		helperInsertTestToken(t, ctx, db, contractAddr, tokenExt, "FULL", "profile", "creator_full", "1000000000000000000000000", 150.5, 0.00015, 10, PlatformGroupIonConnect)
		helperUpdateTokenBondingCurve(t, ctx, db,
			tokenExt,
			"75000000000000000000000",  // 75k tokens current
			"150000000000000000000000", // 150k tokens goal
			150.0,                      // $150 USD current
			300.0,                      // $300 USD goal
			"100000000000000000000",    // 100 tokens raised (wei)
			false,                      // not migrated
		)
		helperInsertUserTokenPosition(t, ctx, db, "holder_full", contractAddr, tokenExt, holderExtAddr, "8000000000000000000000", 0.00015, 1.2)
		helperCreateSwapForVolume(t, ctx, db, contractAddr, tokenExt, "0x0000000000000000000000000000000000000001", false, "100000000000000000000", "1000000000000000000000", 0.00015)
		helperRefreshVolumeView(t, ctx, db)
		helperSetupRedisPositionData(t, ctx, testRedis, tokenExt, map[string]float64{
			holderExtAddr: 8000.0,
		})

		tokens, totalHoldings, err := ta.GetCommunityTokensByHolder(ctx, holderExtAddr, "holder_full", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)
		require.Equal(t, uint64(1), totalHoldings)

		token := tokens[0]
		require.Equal(t, "profile", token.Type)
		require.Equal(t, "creator_full_user", token.Title)
		require.Equal(t, "Creator Full Display", token.Description)
		require.Equal(t, "https://avatar-full.png", token.ImageURL)
		require.NotNil(t, token.CreatedAt)

		require.NotNil(t, token.Addresses)
		require.Equal(t, tokenExt, token.Addresses.IonConnect)
		require.Empty(t, token.Addresses.Twitter)
		require.Equal(t, contractAddr, token.Addresses.Blockchain)

		require.Equal(t, "creator_full_user", strVal(token.Creator.Username))
		require.Equal(t, "Creator Full Display", strVal(token.Creator.Display))
		require.True(t, token.Creator.Verified != nil && *token.Creator.Verified)
		require.Equal(t, "https://avatar-full.png", strVal(token.Creator.Avatar))

		require.NotNil(t, token.Creator.Addresses)
		require.Equal(t, creatorPubkey, token.Creator.Addresses.IonConnect)
		require.Empty(t, token.Creator.Addresses.Twitter)
		require.Empty(t, token.Creator.Addresses.Blockchain)
		require.Nil(t, token.Creator.Token, "Profile token should not have creator.token")

		require.Equal(t, "FULL", token.MarketData.Ticker)
		require.InDelta(t, 150.5, token.MarketData.MarketCap, 0.01)
		require.Greater(t, token.MarketData.Volume, 0.0)
		require.InDelta(t, 0.00015, token.MarketData.PriceUSD, 0.000001)
		require.GreaterOrEqual(t, token.MarketData.Holders, uint64(10), "Should have at least 10 holders")

		require.NotNil(t, token.MarketData.BondingCurveProgress)
		require.Equal(t, "75000000000000000000000", token.MarketData.BondingCurveProgress.CurrentAmount)
		require.Equal(t, "150000000000000000000000", token.MarketData.BondingCurveProgress.GoalAmount)
		require.InDelta(t, 150.0, token.MarketData.BondingCurveProgress.CurrentAmountUSD, 0.01)
		require.InDelta(t, 300.0, token.MarketData.BondingCurveProgress.GoalAmountUSD, 0.01)
	})

	t.Run("holder_position_includes_position_data", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "creator_pos_data", "creator_pos_data", "Creator Pos Data", "", true, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "holder_pos_data", "holder_pos_data", "Holder Pos Data", "", false, PlatformGroupIonConnect)

		tokenExt := "0:creator_pos_data:"
		holderExtAddr := "0:holder_pos_data:"
		contractAddr := "0xPOSDATA11111111111111111111111111111"

		helperInsertTestToken(t, ctx, db, contractAddr, tokenExt, "POSD", "profile", "creator_pos_data", "1000000000000000000000000", 100.0, 0.0001, 5, PlatformGroupIonConnect)
		helperInsertUserTokenPosition(t, ctx, db, "holder_pos_data", contractAddr, tokenExt, holderExtAddr, "3000000000000000000000", 0.0001, 0.3)
		helperSetupRedisPositionData(t, ctx, testRedis, tokenExt, map[string]float64{
			"0:top_holder:":   5000.0,
			holderExtAddr:     3000.0,
			"0:other_holder:": 2000.0,
		})

		tokens, totalHoldings, err := ta.GetCommunityTokensByHolder(ctx, holderExtAddr, "holder_pos_data", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)
		require.Equal(t, uint64(1), totalHoldings)

		token := tokens[0]
		require.NotNil(t, token.MarketData.Position, "Position should be present for holder")

		require.Equal(t, uint64(2), token.MarketData.Position.Rank, "Rank should be 2 (second highest)")
		require.Equal(t, "3000000000000000000000", token.MarketData.Position.Amount)
		require.InDelta(t, 0.3, token.MarketData.Position.AmountUSD, 0.01, "3000 * 0.0001 = $0.3")
	})

	t.Run("ionconnect_holder_with_ionconnect_tokens", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "ion_creator", "ion_creator", "ION Creator", "", true, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "ion_holder", "ion_holder", "ION Holder", "", false, PlatformGroupIonConnect)

		holderExtAddr := "0:ion_holder:"
		tokenExt := "0:ion_creator:"
		contractAddr := "0xIONION11111111111111111111111111111"

		helperInsertTestToken(t, ctx, db, contractAddr, tokenExt, "IONC", "profile", "ion_creator", "1000000000000000000000000", 100.0, 0.0001, 5, PlatformGroupIonConnect)
		helperInsertUserTokenPosition(t, ctx, db, "ion_holder", contractAddr, tokenExt, holderExtAddr, "2000000000000000000000", 0.0001, 0.2)
		helperSetupRedisPositionData(t, ctx, testRedis, tokenExt, map[string]float64{
			holderExtAddr: 2000.0,
		})

		tokens, totalHoldings, err := ta.GetCommunityTokensByHolder(ctx, holderExtAddr, "ion_holder", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)
		require.Equal(t, uint64(1), totalHoldings)

		token := tokens[0]

		require.NotNil(t, token.Addresses)
		require.Equal(t, tokenExt, token.Addresses.IonConnect)
		require.Empty(t, token.Addresses.Twitter)
		require.Equal(t, contractAddr, token.Addresses.Blockchain)

		require.Nil(t, token.Launcher, "ION tokens should not have launcher")
	})

	t.Run("xcom_holder_with_xcom_tokens", func(t *testing.T) {
		xcomCreator := "111222333"
		xcomHolder := "444555666"
		helperInsertTestUser(t, ctx, db, "xcom_creator_master", "xcom_creator", "XCom Creator", "0xXCOMCREATOR111111111111111111111111", true, PlatformGroupXCom)
		helperInsertTestUser(t, ctx, db, "xcom_holder_master", "xcom_holder", "XCom Holder", "0xXCOMHOLDER1111111111111111111111111", false, PlatformGroupXCom)

		_, err := storage.Exec(ctx, db, `UPDATE users SET external_address = $1 WHERE master_pubkey = $2`, xcomCreator, "xcom_creator_master")
		require.NoError(t, err)
		_, err = storage.Exec(ctx, db, `UPDATE users SET external_address = $1 WHERE master_pubkey = $2`, xcomHolder, "xcom_holder_master")
		require.NoError(t, err)

		contractAddr := "0xXCOMXCOM111111111111111111111111111"
		helperInsertTestToken(t, ctx, db, contractAddr, xcomCreator, "XCOM", "profile", "xcom_creator_master", "1000000000000000000000000", 100.0, 0.0001, 5, PlatformGroupXCom)
		helperInsertUserTokenPosition(t, ctx, db, "xcom_holder_master", contractAddr, xcomCreator, xcomHolder, "3000000000000000000000", 0.0001, 0.3)
		helperSetupRedisPositionData(t, ctx, testRedis, xcomCreator, map[string]float64{
			xcomHolder: 3000.0,
		})

		helperInsertTokenSwap(t, ctx, db, contractAddr, xcomCreator, "0xXCOMLAUNCHER11111111111111111111111", "0xtxhash123", false, "100000000000000000000", "1000000000000000000000", 0.0001)

		tokens, totalHoldings, err := ta.GetCommunityTokensByHolder(ctx, xcomHolder, "xcom_holder_master", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)
		require.Equal(t, uint64(1), totalHoldings)

		token := tokens[0]

		require.NotNil(t, token.Addresses)
		require.Empty(t, token.Addresses.IonConnect)
		require.Equal(t, xcomCreator, token.Addresses.Twitter)
		require.Equal(t, contractAddr, token.Addresses.Blockchain)

		require.NotNil(t, token.Launcher, "XCom tokens should have launcher when swaps exist")
	})

	t.Run("holder_with_mixed_platform_positions", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "mixed_ion_creator", "mixed_ion_creator", "Mixed ION Creator", "", true, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "mixed_xcom_creator", "mixed_xcom_creator", "Mixed XCom Creator", "0xMIXEDXCOM1111111111111111111111111", true, PlatformGroupXCom)
		helperInsertTestUser(t, ctx, db, "mixed_holder", "mixed_holder", "Mixed Holder", "", false, PlatformGroupIonConnect)

		xcomCreatorExt := "789012345"
		_, err := storage.Exec(ctx, db, `UPDATE users SET external_address = $1 WHERE master_pubkey = $2`, xcomCreatorExt, "mixed_xcom_creator")
		require.NoError(t, err)

		holderExtAddr := "0:mixed_holder:"

		ionTokenExt := "0:mixed_ion_creator:"
		ionContractAddr := "0xMIXEDION111111111111111111111111111"
		helperInsertTestToken(t, ctx, db, ionContractAddr, ionTokenExt, "MION", "profile", "mixed_ion_creator", "1000000000000000000000000", 100.0, 0.0001, 5, PlatformGroupIonConnect)
		helperInsertUserTokenPosition(t, ctx, db, "mixed_holder", ionContractAddr, ionTokenExt, holderExtAddr, "5000000000000000000000", 0.0001, 0.5)
		helperSetupRedisPositionData(t, ctx, testRedis, ionTokenExt, map[string]float64{
			holderExtAddr: 5000.0,
		})

		xcomContractAddr := "0xMIXEDXCOM11111111111111111111111111"
		helperInsertTestToken(t, ctx, db, xcomContractAddr, xcomCreatorExt, "MXCOM", "profile", "mixed_xcom_creator", "1000000000000000000000000", 200.0, 0.0002, 10, PlatformGroupXCom)
		helperInsertUserTokenPosition(t, ctx, db, "mixed_holder", xcomContractAddr, xcomCreatorExt, holderExtAddr, "2000000000000000000000", 0.0002, 0.4)
		helperSetupRedisPositionData(t, ctx, testRedis, xcomCreatorExt, map[string]float64{
			holderExtAddr: 2000.0,
		})

		tokens, totalHoldings, err := ta.GetCommunityTokensByHolder(ctx, holderExtAddr, "mixed_holder", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 2)
		require.Equal(t, uint64(2), totalHoldings)

		var ionToken, xcomToken *CommunityToken
		for _, token := range tokens {
			if token.Addresses.IonConnect != "" {
				ionToken = token
			} else {
				xcomToken = token
			}
		}

		require.NotNil(t, ionToken, "Should find ION token")
		require.NotNil(t, xcomToken, "Should find XCom token")

		require.Equal(t, "MION", ionToken.MarketData.Ticker)
		require.Equal(t, ionTokenExt, ionToken.Addresses.IonConnect)
		require.Empty(t, ionToken.Addresses.Twitter)

		require.Equal(t, "MXCOM", xcomToken.MarketData.Ticker)
		require.Equal(t, xcomCreatorExt, xcomToken.Addresses.Twitter)
		require.Empty(t, xcomToken.Addresses.IonConnect)
	})

	t.Run("filters_out_zero_amount_positions", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "creator_zero", "creator_zero", "Creator Zero", "", true, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "holder_zero", "holder_zero", "Holder Zero", "", false, PlatformGroupIonConnect)

		holderExtAddr := "0:holder_zero:"

		token1Ext := "0:creator_zero:token1"
		contract1Addr := "0xZERO1111111111111111111111111111111111"
		helperInsertTestToken(t, ctx, db, contract1Addr, token1Ext, "ZERO1", "profile", "creator_zero", "1000000000000000000000000", 100.0, 0.0001, 5, PlatformGroupIonConnect)
		helperInsertUserTokenPosition(t, ctx, db, "holder_zero", contract1Addr, token1Ext, holderExtAddr, "1000000000000000000000", 0.0001, 0.1)
		helperSetupRedisPositionData(t, ctx, testRedis, token1Ext, map[string]float64{
			holderExtAddr: 1000.0,
		})

		token2Ext := "0:creator_zero:token2"
		contract2Addr := "0xZERO2222222222222222222222222222222222"
		helperInsertTestToken(t, ctx, db, contract2Addr, token2Ext, "ZERO2", "profile", "creator_zero", "1000000000000000000000000", 100.0, 0.0001, 5, PlatformGroupIonConnect)
		helperInsertUserTokenPosition(t, ctx, db, "holder_zero", contract2Addr, token2Ext, holderExtAddr, "0", 0.0001, 0.0)

		tokens, totalHoldings, err := ta.GetCommunityTokensByHolder(ctx, holderExtAddr, "holder_zero", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1, "Should only return token with amount > 0")
		require.Equal(t, uint64(1), totalHoldings)
		require.Equal(t, "ZERO1", tokens[0].MarketData.Ticker)
	})

	t.Run("holder_with_content_token_position_has_creator_token", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "creator_hcontent", "creator_hcontent", "Creator HContent", "", true, PlatformGroupIonConnect, "https://avatar-hcontent.png")
		helperInsertTestUser(t, ctx, db, "holder_hcontent", "holder_hcontent", "Holder HContent", "", false, PlatformGroupIonConnect)

		creatorProfileExt := "0:creator_hcontent:"
		creatorProfileContract := "0xHCONTPROFILE111111111111111111111111"
		helperInsertTestToken(t, ctx, db, creatorProfileContract, creatorProfileExt, "HCPROF", "profile", "creator_hcontent", "800000000000000000000000", 80.0, 0.00008, 4, PlatformGroupIonConnect)

		holderExtAddr := "0:holder_hcontent:"
		contentTokenExt := "30175:hcontent_video_id:content"
		contentTokenContract := "0xHCONTVIDEO1111111111111111111111111"
		helperInsertTestToken(t, ctx, db, contentTokenContract, contentTokenExt, "HCVID", "video", "creator_hcontent", "2000000000000000000000000", 200.0, 0.0002, 8, PlatformGroupIonConnect)
		helperSetTokenBaseToken(t, ctx, db, contentTokenExt, creatorProfileContract)

		helperInsertUserTokenPosition(t, ctx, db, "holder_hcontent", contentTokenContract, contentTokenExt, holderExtAddr, "4000000000000000000000", 0.0002, 0.8)
		helperSetupRedisPositionData(t, ctx, testRedis, contentTokenExt, map[string]float64{
			holderExtAddr: 4000.0,
		})

		tokens, totalHoldings, err := ta.GetCommunityTokensByHolder(ctx, holderExtAddr, "holder_hcontent", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)
		require.Equal(t, uint64(1), totalHoldings)

		token := tokens[0]
		require.Equal(t, "video", token.Type)
		require.Equal(t, "HCVID", token.MarketData.Ticker)

		require.NotNil(t, token.Creator.Token, "Content token should have creator.token")
		require.Equal(t, "HCPROF", token.Creator.Token.Ticker)
		require.Equal(t, "creator_hcontent", token.Creator.Token.Title)
		require.Equal(t, "Creator HContent", token.Creator.Token.Description)
		require.Equal(t, "https://avatar-hcontent.png", token.Creator.Token.ImageURL)
		require.NotNil(t, token.Creator.Token.CreatedAt)
		require.NotNil(t, token.Creator.Token.Addresses)
		require.Equal(t, creatorProfileContract, token.Creator.Token.Addresses.Blockchain)
		require.Equal(t, creatorProfileExt, token.Creator.Token.Addresses.IonConnect)
	})

	t.Run("offset_beyond_total_returns_empty", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "creator_beyond", "creator_beyond", "Creator Beyond", "", true, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "holder_beyond", "holder_beyond", "Holder Beyond", "", false, PlatformGroupIonConnect)

		holderExtAddr := "0:holder_beyond:"
		tokenExt := "0:creator_beyond:"
		contractAddr := "0xBEYOND111111111111111111111111111111"

		helperInsertTestToken(t, ctx, db, contractAddr, tokenExt, "BYND", "profile", "creator_beyond", "1000000000000000000000000", 100.0, 0.0001, 5, PlatformGroupIonConnect)
		helperInsertUserTokenPosition(t, ctx, db, "holder_beyond", contractAddr, tokenExt, holderExtAddr, "1000000000000000000000", 0.0001, 0.1)
		helperSetupRedisPositionData(t, ctx, testRedis, tokenExt, map[string]float64{
			holderExtAddr: 1000.0,
		})

		tokens, totalHoldings, err := ta.GetCommunityTokensByHolder(ctx, holderExtAddr, "holder_beyond", 10, 100)
		require.NoError(t, err)
		require.Empty(t, tokens, "Should return empty when offset > total")
		require.Equal(t, uint64(1), totalHoldings, "Total holdings equals the user's total number of holdings, even when no rows are returned for the current page")
	})
}
