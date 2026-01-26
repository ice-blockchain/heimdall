// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"strings"
	"testing"
	stdtime "time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func TestGetCommunityTokensByExternalAddresses(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()

	ta := helperNewForTest(t, db)

	t.Run("empty addresses returns empty result", func(t *testing.T) {
		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{}, "requestor123", nil, "", 0, 0)
		require.NoError(t, err)
		require.Empty(t, tokens)
	})

	t.Run("non-existent addresses returns empty result", func(t *testing.T) {
		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{"0:nonexistent:"}, "requestor123", nil, "", 0, 0)
		require.NoError(t, err)
		require.Empty(t, tokens)
	})

	t.Run("fetch tokens with basic data", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "creator_basic", "alice_basic", "Alice Basic", "", true, PlatformGroupIonConnect, "https://avatar1.png")
		helperInsertTestUser(t, ctx, db, "requestor_basic", "charlie_basic", "Charlie Basic", "", false, PlatformGroupIonConnect)

		token1Ext := "0:creator_basic:"
		creatorBasic := "creator_basic"
		helperInsertTestToken(t, ctx, db,
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
		require.Equal(t, "profile", token.Type)
		require.Equal(t, "alice_basic", token.Title)
		require.Equal(t, "Alice Basic", token.Description)
		require.Equal(t, "https://avatar1.png", token.ImageURL)
		require.NotNil(t, token.CreatedAt, "CreatedAt should not be nil")
		require.True(t, token.CreatedAt.Time.Before(stdtime.Now().Add(stdtime.Second)))

		require.NotNil(t, token.Addresses, "Token addresses should not be nil")
		require.Equal(t, token1Ext, token.Addresses.IonConnect)
		require.Empty(t, token.Addresses.Twitter)
		require.Equal(t, "0xBASIC1111111111111111111111111111111111", token.Addresses.Blockchain)

		require.Equal(t, "alice_basic", strVal(token.Creator.Username))
		require.Equal(t, "Alice Basic", strVal(token.Creator.Display))
		require.Equal(t, "https://avatar1.png", strVal(token.Creator.Avatar))
		require.True(t, token.Creator.Verified != nil && *token.Creator.Verified)
		require.NotNil(t, token.Creator.Addresses, "Creator addresses should not be nil")
		require.Equal(t, creatorBasic, token.Creator.Addresses.IonConnect)
		require.Empty(t, token.Creator.Addresses.Twitter)

		require.Equal(t, "BASIC1", token.MarketData.Ticker)
		require.InDelta(t, 100.5, token.MarketData.MarketCap, 0.01)
		require.GreaterOrEqual(t, token.MarketData.Volume, 0.0)
		require.InDelta(t, 0.0001, token.MarketData.PriceUSD, 0.00001)
		require.Equal(t, uint64(5), token.MarketData.Holders)
		require.Equal(t, uint64(0), token.MarketData.PlatformHolders)
		require.Nil(t, token.MarketData.BondingCurveProgress)
		require.Empty(t, token.MarketData.TopPlatformHolders)

		require.Nil(t, token.MarketData.Position, "Position should be nil when user has no position")
	})

	t.Run("fetch tokens with bonding curve progress", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "creator_bonding", "alice_bonding", "Alice Bonding", "", true, PlatformGroupIonConnect)

		tokenExt := "0:creator_bonding:"
		contractAddr := "0xBOND1111111111111111111111111111111111"
		helperInsertTestToken(t, ctx, db,
			contractAddr,
			tokenExt,
			"BOND1",
			"profile",
			"creator_bonding",
			"100000000000000000000000", // 100k tokens total supply
			150.0,
			0.0002,
			5,
			PlatformGroupIonConnect,
		)

		helperUpdateTokenBondingCurve(t, ctx, db,
			tokenExt,
			"50000000000000000000000",  // 50k tokens in wei (CurrentAmount)
			"100000000000000000000000", // 100k tokens in wei (GoalAmount)
			100.0,                      // $100 USD current
			200.0,                      // $200 USD goal
			"50000000000000000000",     // 50 tokens raised in base currency (wei)
			false,
		)

		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{tokenExt}, "requestor_basic", nil, "", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		token := tokens[0]
		require.NotNil(t, token.MarketData.BondingCurveProgress, "BondingCurveProgress should not be nil")

		require.Equal(t, "50000000000000000000000", token.MarketData.BondingCurveProgress.CurrentAmount)
		require.Equal(t, "100000000000000000000000", token.MarketData.BondingCurveProgress.GoalAmount)
		require.InDelta(t, 100.0, token.MarketData.BondingCurveProgress.CurrentAmountUSD, 0.01)
		require.InDelta(t, 200.0, token.MarketData.BondingCurveProgress.GoalAmountUSD, 0.01)
		require.Equal(t, "50000000000000000000", token.MarketData.BondingCurveProgress.RaisedAmount)
		require.False(t, token.MarketData.BondingCurveProgress.Migrated)
	})

	t.Run("fetch tokens with user position", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "creator_pos", "alice_pos", "Alice Pos", "", true, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "requestor_pos", "charlie_pos", "Charlie Pos", "", false, PlatformGroupIonConnect)

		tokenExt := "0:creator_pos:"
		creatorPos := "creator_pos"
		helperInsertTestToken(t, ctx, db,
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
		helperInsertUserTokenPosition(t, ctx, db,
			"requestor_pos",
			"0xPOS11111111111111111111111111111111111",
			tokenExt,
			"0:requestor_pos:",
			"3500000000000000000000", // 3500 tokens in wei (3500 * 1e18,
			0.0001,
			0.315,
		)
		helperCreateSwapForVolume(t, ctx, db,
			"0xPOS11111111111111111111111111111111111",
			tokenExt,
			"0x0000000000000000000000000000000000000001",
			false,
			"100000000000000000000",  // 100 ION
			"1000000000000000000000", // 1000 tokens
			0.0001,
		)
		helperRefreshVolumeView(t, ctx, db)

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

		require.Equal(t, "profile", token.Type)
		require.Equal(t, "alice_pos", token.Title)
		require.Equal(t, "Alice Pos", token.Description)
		if !token.CreatedAt.IsZero() {
			require.True(t, token.CreatedAt.Time.Before(stdtime.Now().Add(stdtime.Second)))
		}

		require.Equal(t, tokenExt, token.Addresses.IonConnect)
		require.Empty(t, token.Addresses.Twitter)
		require.Equal(t, "0xPOS11111111111111111111111111111111111", token.Addresses.Blockchain)

		require.Equal(t, "alice_pos", strVal(token.Creator.Username))
		require.Equal(t, "Alice Pos", strVal(token.Creator.Display))
		require.True(t, token.Creator.Verified != nil && *token.Creator.Verified)
		require.Equal(t, creatorPos, token.Creator.Addresses.IonConnect)

		require.Equal(t, "POS1", token.MarketData.Ticker)
		require.InDelta(t, 100.0, token.MarketData.MarketCap, 0.01)
		require.GreaterOrEqual(t, token.MarketData.Volume, 0.0, "Volume should be >= 0")
		require.InDelta(t, 0.0001, token.MarketData.PriceUSD, 0.00001)
		require.GreaterOrEqual(t, token.MarketData.Holders, uint64(1), "Should have at least 1 holder")

		require.NotNil(t, token.MarketData.Position, "Position should be present for user with holdings")
		require.Equal(t, uint64(3), token.MarketData.Position.Rank, "Rank from Redis sorted set")
		require.Equal(t, "3500000000000000000000", token.MarketData.Position.Amount, "Amount = 3500 tokens in wei")
		require.InDelta(t, 0.35, token.MarketData.Position.AmountUSD, 0.01, "AmountUSD = 3500 * 0.0001 = $0.35")
		require.InDelta(t, 0.035, token.MarketData.Position.PnL, 0.001, "PnL = $0.35 - $0.315 = $0.035")
		require.InDelta(t, 11.11, token.MarketData.Position.PnLPercentage, 1.0, "PnL% = 0.035/0.315*100 = 11.11%")
	})

	t.Run("position PnL with partial sale - break even scenario", func(t *testing.T) {
		// User bought 300 tokens for $0.9, sold 150 for $0.45, holding 150 worth $0.45. Expected PnL = 0.
		helperInsertTestUser(t, ctx, db, "creator_pnl", "pnl_creator", "PnL Creator", "", false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "holder_pnl", "pnl_holder", "PnL Holder", "", false, PlatformGroupIonConnect)

		tokenExt := "0:creator_pnl:"
		contractAddr := "0xPNL11111111111111111111111111111111111"
		helperInsertTestToken(t, ctx, db,
			contractAddr,
			tokenExt,
			"PNL",
			"profile",
			"creator_pnl",
			"100000000000000000000000", // 100k tokens total supply
			30.0,
			0.003, // $0.003 per token
			1,
			PlatformGroupIonConnect,
		)

		// User bought 300 tokens (100 + 200) for total $0.9, sold 150 for $0.45, holding 150 worth $0.45
		helperInsertUserTokenPosition(t, ctx, db,
			"holder_pnl",
			contractAddr,
			tokenExt,
			"0:holder_pnl:",
			"150000000000000000000", // 150 tokens remaining in wei
			0.003,                   // avg_buy_price_usd = $0.003
			0.9,                     // total_invested_usd = $0.9 (constant)
			0.45,                    // total_realized_usd = $0.45 (revenue from sale)
		)

		helperSetupRedisPositionData(t, ctx, testRedis, tokenExt, map[string]float64{
			"0:holder_pnl:": 150.0,
		})

		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{tokenExt}, "holder_pnl", nil, "", 0, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		token := tokens[0]
		require.NotNil(t, token.MarketData.Position, "Position should be present")

		// Current value: 150 * $0.003 = $0.45
		require.InDelta(t, 0.45, token.MarketData.Position.AmountUSD, 0.01, "AmountUSD = 150 * $0.003 = $0.45")
		// PnL = (Current + Realized) - Invested = ($0.45 + $0.45) - $0.9 = $0
		require.InDelta(t, 0.0, token.MarketData.Position.PnL, 0.01, "PnL should be $0 (break even)")
		require.InDelta(t, 0.0, token.MarketData.Position.PnLPercentage, 0.01, "PnL% should be 0%")
	})

	t.Run("position PnL with sale at profit", func(t *testing.T) {
		// Bought 200 tokens for $100, sold 100 for $60, holding 100 worth $55
		// Total value = $60 + $55 = $115
		// PnL = $115 - $100 = $15 (15% profit)
		helperInsertTestUser(t, ctx, db, "creator_profit", "profit_creator", "Profit Creator", "", false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "holder_profit", "profit_holder", "Profit Holder", "", false, PlatformGroupIonConnect)

		tokenExt := "0:creator_profit:"
		contractAddr := "0xPROFIT111111111111111111111111111111"
		helperInsertTestToken(t, ctx, db,
			contractAddr,
			tokenExt,
			"PROF",
			"profile",
			"creator_profit",
			"50000000000000000000000",
			55.0,
			0.55, // $0.55 per token now
			1,
			PlatformGroupIonConnect,
		)

		helperInsertUserTokenPosition(t, ctx, db,
			"holder_profit",
			contractAddr,
			tokenExt,
			"0:holder_profit:",
			"100000000000000000000", // 100 tokens remaining
			0.5,                     // avg_buy_price_usd = $0.5
			100.0,                   // total_invested_usd = $100
			60.0,                    // total_realized_usd = $60 (revenue from sale)
		)

		helperSetupRedisPositionData(t, ctx, testRedis, tokenExt, map[string]float64{
			"0:holder_profit:": 100.0,
		})

		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{tokenExt}, "holder_profit", nil, "", 0, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		token := tokens[0]
		require.NotNil(t, token.MarketData.Position, "Position should be present")

		// Current value: 100 * $0.55 = $55
		require.InDelta(t, 55.0, token.MarketData.Position.AmountUSD, 0.01, "AmountUSD = 100 * $0.55 = $55")
		// PnL = ($55 + $60) - $100 = $15
		require.InDelta(t, 15.0, token.MarketData.Position.PnL, 0.01, "PnL should be $15")
		require.InDelta(t, 15.0, token.MarketData.Position.PnLPercentage, 1.0, "PnL% should be 15%")
	})

	t.Run("position PnL with sale at loss", func(t *testing.T) {
		// Bought 200 tokens for $100, sold 100 for $40, holding 100 worth $35
		// Total value = $40 + $35 = $75
		// PnL = $75 - $100 = -$25 (25% loss)
		helperInsertTestUser(t, ctx, db, "creator_loss", "loss_creator", "Loss Creator", "", false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "holder_loss", "loss_holder", "Loss Holder", "", false, PlatformGroupIonConnect)

		tokenExt := "0:creator_loss:"
		contractAddr := "0xLOSS1111111111111111111111111111111111"
		helperInsertTestToken(t, ctx, db,
			contractAddr,
			tokenExt,
			"LOSS",
			"profile",
			"creator_loss",
			"50000000000000000000000",
			35.0,
			0.35, // $0.35 per token now
			1,
			PlatformGroupIonConnect,
		)

		helperInsertUserTokenPosition(t, ctx, db,
			"holder_loss",
			contractAddr,
			tokenExt,
			"0:holder_loss:",
			"100000000000000000000", // 100 tokens remaining
			0.5,                     // avg_buy_price_usd = $0.5
			100.0,                   // total_invested_usd = $100
			40.0,                    // total_realized_usd = $40 (revenue from sale)
		)

		helperSetupRedisPositionData(t, ctx, testRedis, tokenExt, map[string]float64{
			"0:holder_loss:": 100.0,
		})

		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{tokenExt}, "holder_loss", nil, "", 0, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		token := tokens[0]
		require.NotNil(t, token.MarketData.Position, "Position should be present")

		// Current value: 100 * $0.35 = $35
		require.InDelta(t, 35.0, token.MarketData.Position.AmountUSD, 0.01, "AmountUSD = 100 * $0.35 = $35")
		// PnL = ($35 + $40) - $100 = -$25
		require.InDelta(t, -25.0, token.MarketData.Position.PnL, 0.01, "PnL should be -$25")
		require.InDelta(t, -25.0, token.MarketData.Position.PnLPercentage, 1.0, "PnL% should be -25%")
	})

	t.Run("X.com tokens with IonConnect address should extract pubkey for creator", func(t *testing.T) {
		creatorExternalAddr := "123456789"
		helperInsertTestUser(t, ctx, db, creatorExternalAddr, "xcom_creator_with_ion", "X.com Creator with IonConnect", "", true, PlatformGroupXCom)

		tokenExternalAddr := creatorExternalAddr
		expectedPubkey := "9dbf3f196310fb4a1818f619a686b15e6ffa78d723e843973fcdc9125f15bc2f"
		tokenIonConnectAddr := fmt.Sprintf("31751:%s:abc123", expectedPubkey)
		contractAddr := "0xXCOMION111111111111111111111111111111"
		helperInsertTestToken(t, ctx, db,
			contractAddr,
			tokenExternalAddr,
			"XCION",
			"post",
			creatorExternalAddr,
			"5000000000000000000000",
			75.25,
			0.00015,
			8,
			PlatformGroupXCom,
		)

		_, err := storage.Exec(ctx, db,
			`UPDATE tokens SET ion_connect_address = $1 WHERE external_address = $2`,
			tokenIonConnectAddr, tokenExternalAddr)
		require.NoError(t, err)

		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{tokenExternalAddr}, "requestor123", nil, "", 0, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		token := tokens[0]

		require.NotNil(t, token.Addresses, "Token addresses should not be nil")
		require.Equal(t, tokenIonConnectAddr, token.Addresses.IonConnect,
			"Token IonConnect should contain full ion_connect_address in format 31751:pubkey:xxx")
		require.Equal(t, tokenExternalAddr, token.Addresses.Twitter, "Token Twitter should be external_address")

		require.NotNil(t, token.Creator.Addresses, "Creator addresses should not be nil")
		require.Equal(t, expectedPubkey, token.Creator.Addresses.IonConnect,
			"Creator IonConnect should contain extracted pubkey from token external address")
		require.NotEmpty(t, token.Creator.Addresses.Twitter, "Creator should have Twitter address")
	})

	t.Run("Twitter token with launcher field populated", func(t *testing.T) {
		creatorExtAddr := "987654321"
		launcherExtAddr := "111222333"
		helperInsertTestUser(t, ctx, db, "creator_bsc_addr", "twitter_creator", "Twitter Creator", "0x0000000000000000000000000000000000CREATOR", true, PlatformGroupXCom)
		helperInsertTestUser(t, ctx, db, "launcher_bsc_addr", "twitter_launcher", "Twitter Launcher", "0x0000000000000000000000000000000000LAUNCH", false, PlatformGroupXCom)

		creatorBscAddress := "0xCREATOR1111111111111111111111111111"

		_, err := storage.Exec(ctx, db, `UPDATE users SET external_address = $1, content_author_id = $2 WHERE master_pubkey = $3`, creatorExtAddr, creatorBscAddress, "creator_bsc_addr")
		require.NoError(t, err)
		_, err = storage.Exec(ctx, db, `UPDATE users SET external_address = $1 WHERE master_pubkey = $2`, launcherExtAddr, "launcher_bsc_addr")
		require.NoError(t, err)

		contractAddr := "0xLAUNCH111111111111111111111111111111"
		helperInsertTestToken(t, ctx, db,
			contractAddr,
			creatorExtAddr,
			"TWTR",
			"profile",
			"creator_bsc_addr",
			"10000000000000000000000",
			100.0,
			0.001,
			5,
			PlatformGroupXCom,
		)
		_, err = storage.Exec(ctx, db, `UPDATE tokens SET content_author_id = $1 WHERE contract_address = $2`, creatorBscAddress, contractAddr)
		require.NoError(t, err)

		helperInsertTokenSwap(t, ctx, db, // First buy by the launcher
			contractAddr,
			creatorExtAddr,
			"0x0000000000000000000000000000000000LAUNCH",
			"0xfirstswap123",
			false,
			"100000000000000000000",  // 100 ION
			"1000000000000000000000", // 1000 tokens
			0.001,
		)

		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{creatorExtAddr}, "requestor_launcher", nil, "", 0, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		token := tokens[0]
		require.Equal(t, "twitter_creator", strVal(token.Creator.Username))
		require.Equal(t, "Twitter Creator", strVal(token.Creator.Display))
		require.True(t, token.Creator.Verified != nil && *token.Creator.Verified)
		require.NotEmpty(t, strVal(token.Creator.Avatar), "Creator avatar should be present")
		require.NotNil(t, token.Creator.Addresses, "Creator addresses should not be nil")
		require.Equal(t, creatorExtAddr, token.Creator.Addresses.Twitter)
		require.Equal(t, creatorBscAddress, token.Creator.Addresses.Blockchain, "Creator blockchain address should be from content_author_id")
		require.Empty(t, token.Creator.Addresses.IonConnect, "Creator IonConnect should be empty for xcom")

		require.NotNil(t, token.Launcher, "Launcher should be populated for Twitter token with first swap")
		require.Equal(t, "twitter_launcher", strVal(token.Launcher.Username))
		require.Equal(t, "Twitter Launcher", strVal(token.Launcher.Display))
		require.True(t, token.Launcher.Verified == nil || !*token.Launcher.Verified)
		require.NotEmpty(t, strVal(token.Launcher.Avatar), "Launcher avatar should be present")
		require.NotNil(t, token.Launcher.Addresses, "Launcher addresses should not be nil")
		require.Equal(t, launcherExtAddr, token.Launcher.Addresses.Twitter)
		require.Equal(t, "0x0000000000000000000000000000000000LAUNCH", token.Launcher.Addresses.Blockchain)
		require.Empty(t, token.Launcher.Addresses.IonConnect, "Launcher IonConnect should be empty")
	})

	t.Run("Twitter token without swaps - launcher is nil", func(t *testing.T) {
		creatorExtAddr := "555666777"
		helperInsertTestUser(t, ctx, db, "creator_no_swap", "twitter_no_swap", "Twitter No Swap", "0x0000000000000000000000000000000000NOSWAP", true, PlatformGroupXCom)
		_, err := storage.Exec(ctx, db, `UPDATE users SET external_address = $1 WHERE content_author_id = $2`, creatorExtAddr, "0x0000000000000000000000000000000000noswap")
		require.NoError(t, err)

		contractAddr := "0xNOSWAP111111111111111111111111111111"
		helperInsertTestToken(t, ctx, db,
			contractAddr,
			creatorExtAddr,
			"NOSW",
			"profile",
			"creator_no_swap",
			"5000000000000000000000",
			50.0,
			0.0005,
			2,
			PlatformGroupXCom,
		)

		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{creatorExtAddr}, "requestor_no_swap", nil, "", 0, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		token := tokens[0]
		require.Nil(t, token.Launcher, "Launcher should be nil for Twitter token without swaps")
	})

	t.Run("IonConnect token - launcher is nil", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "ionconnect_master", "ion_user", "IonConnect User", "", false, PlatformGroupIonConnect)

		tokenExt := "0:ionconnect_master:"
		contractAddr := "0xIONCONNECT1111111111111111111111111"
		helperInsertTestToken(t, ctx, db,
			contractAddr,
			tokenExt,
			"IONC",
			"profile",
			"ionconnect_master",
			"8000000000000000000000",
			80.0,
			0.0008,
			3,
			PlatformGroupIonConnect,
		)

		helperInsertTokenSwap(t, ctx, db,
			contractAddr,
			tokenExt,
			"0x0000000000000000000000000000000000IONUSR",
			"0xionswap456",
			false,
			"200000000000000000000",
			"2000000000000000000000",
			0.0008,
		)

		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{tokenExt}, "requestor_ion", nil, "", 0, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		token := tokens[0]
		require.Nil(t, token.Launcher, "Launcher should be nil for IonConnect tokens (only for xcom)")
	})

	t.Run("Twitter token - only first buy is considered for launcher", func(t *testing.T) {
		creatorExtAddr := "888999000"
		firstBuyerExtAddr := "111111111"
		secondBuyerExtAddr := "222222222"

		helperInsertTestUser(t, ctx, db, "first_buyer_master", "first_buyer", "First Buyer", "0x0000000000000000000000000000000000FIRST", false, PlatformGroupXCom)
		helperInsertTestUser(t, ctx, db, "second_buyer_master", "second_buyer", "Second Buyer", "0x0000000000000000000000000000000000SECND", false, PlatformGroupXCom)
		helperInsertTestUser(t, ctx, db, "order_creator_master", "order_creator", "Order Creator", "0x0000000000000000000000000000000000ORDER", true, PlatformGroupXCom)

		orderCreatorBscAddress := "0xORDERCREATOR1111111111111111111111"

		_, err := storage.Exec(ctx, db, `UPDATE users SET external_address = $1 WHERE master_pubkey = $2`, firstBuyerExtAddr, "first_buyer_master")
		require.NoError(t, err)
		_, err = storage.Exec(ctx, db, `UPDATE users SET external_address = $1 WHERE master_pubkey = $2`, secondBuyerExtAddr, "second_buyer_master")
		require.NoError(t, err)
		_, err = storage.Exec(ctx, db, `UPDATE users SET external_address = $1, content_author_id = $2 WHERE master_pubkey = $3`, creatorExtAddr, orderCreatorBscAddress, "order_creator_master")
		require.NoError(t, err)

		contractAddr := "0xORDER1111111111111111111111111111111"
		helperInsertTestToken(t, ctx, db,
			contractAddr,
			creatorExtAddr,
			"ORDR",
			"profile",
			"order_creator_master",
			"15000000000000000000000",
			150.0,
			0.0015,
			8,
			PlatformGroupXCom,
		)

		_, err = storage.Exec(ctx, db, `UPDATE tokens SET content_author_id = $1 WHERE contract_address = $2`, orderCreatorBscAddress, contractAddr)
		require.NoError(t, err)

		baseTime := stdtime.Now().Add(-1 * stdtime.Hour)

		// First swap: FIRST BUYER
		helperInsertTokenSwap(t, ctx, db,
			contractAddr,
			creatorExtAddr,
			"0x0000000000000000000000000000000000FIRST",
			"0xfirst001",
			false,
			"100000000000000000000",
			"1000000000000000000000",
			0.0015,
			baseTime,
		)

		// Second swap: SECOND BUYER (should NOT be launcher)
		helperInsertTokenSwap(t, ctx, db,
			contractAddr,
			creatorExtAddr,
			"0x0000000000000000000000000000000000SECND",
			"0xsecond002",
			false,
			"200000000000000000000",
			"2000000000000000000000",
			0.0015,
			baseTime.Add(10*stdtime.Minute),
		)

		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{creatorExtAddr}, "requestor_order", nil, "", 0, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		token := tokens[0]

		// Verify creator - ALL fields
		require.Equal(t, "order_creator", strVal(token.Creator.Username))
		require.Equal(t, "Order Creator", strVal(token.Creator.Display))
		require.True(t, token.Creator.Verified != nil && *token.Creator.Verified)
		require.NotEmpty(t, strVal(token.Creator.Avatar), "Creator avatar should be present")
		require.NotNil(t, token.Creator.Addresses, "Creator addresses should not be nil")
		require.Equal(t, creatorExtAddr, token.Creator.Addresses.Twitter)
		require.Equal(t, orderCreatorBscAddress, token.Creator.Addresses.Blockchain, "Creator blockchain address should be from content_author_id")
		require.Empty(t, token.Creator.Addresses.IonConnect, "Creator IonConnect should be empty for xcom")

		// Verify launcher - ALL fields (should be FIRST buyer, not second)
		require.NotNil(t, token.Launcher, "Launcher should be populated")
		require.Equal(t, "first_buyer", strVal(token.Launcher.Username), "Launcher should be the FIRST buyer, not the second")
		require.Equal(t, "First Buyer", strVal(token.Launcher.Display))
		require.True(t, token.Launcher.Verified == nil || !*token.Launcher.Verified)
		require.NotEmpty(t, strVal(token.Launcher.Avatar), "Launcher avatar should be present")
		require.NotNil(t, token.Launcher.Addresses, "Launcher addresses should not be nil")
		require.Equal(t, firstBuyerExtAddr, token.Launcher.Addresses.Twitter)
		require.Equal(t, "0x0000000000000000000000000000000000FIRST", token.Launcher.Addresses.Blockchain)
		require.Empty(t, token.Launcher.Addresses.IonConnect, "Launcher IonConnect should be empty")
	})
}

func TestGetCommunityTokensByExternalAddresses_WithKeyword(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()

	ta := helperNewForTest(t, db)

	t.Run("search by keyword returns simplified response", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "creator_search", "satoshi_search", "Satoshi Search", "", false, PlatformGroupIonConnect)

		tokenExt := "0:creator_search:"
		helperInsertTestToken(t, ctx, db,
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
		helperCreateSwapForVolume(t, ctx, db,
			"0xSEARCH11111111111111111111111111111",
			tokenExt,
			"0x0000000000000000000000000000000000000001",
			false,                    // buy
			"500000000000000000000",  // 500 ION input
			"5000000000000000000000", // 5000 tokens output
			0.0001,
		)
		helperRefreshVolumeView(t, ctx, db)

		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{tokenExt}, "requestor_search", nil, "SAT", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		token := tokens[0]

		require.Equal(t, "profile", token.Type)
		require.Equal(t, "satoshi_search", token.Title)
		require.Equal(t, "Satoshi Search", token.Description)

		require.Equal(t, "SAT", token.MarketData.Ticker)
		require.InDelta(t, 100.0, token.MarketData.MarketCap, 0.01)
		require.Greater(t, token.MarketData.Volume, 0.0, "Volume should be present from materialized view")
		require.InDelta(t, 0.0001, token.MarketData.PriceUSD, 0.00001)
		require.Equal(t, uint64(10), token.MarketData.Holders)

	})

	t.Run("search with limit and offset - 250+ tokens for KNN candidates", func(t *testing.T) {
		var allTokenExtAddrs []string
		for i := 0; i < 260; i++ {
			creator := fmt.Sprintf("creator_page_%d", i)
			helperInsertTestUser(t, ctx, db, creator, fmt.Sprintf("testknn_%d", i), fmt.Sprintf("Test KNN User %d", i), "", false, PlatformGroupIonConnect)

			tokenExt := fmt.Sprintf("0:%s:", creator)
			allTokenExtAddrs = append(allTokenExtAddrs, tokenExt)

			helperInsertTestToken(t, ctx, db,
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
			helperCreateSwapForVolume(t, ctx, db,
				fmt.Sprintf("0xKNN%03d111111111111111111111111111", i),
				tokenExt,
				"0x0000000000000000000000000000000000000001",
				false,
				fmt.Sprintf("%d00000000000000000000", 100+i), // Different volumes
				"1000000000000000000000",
				0.0001,
			)
		}
		helperRefreshVolumeView(t, ctx, db)

		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx,
			allTokenExtAddrs,
			"requestor_page",
			nil,
			"testknn",
			10,
			0,
		)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(tokens), 10, "Should return at least 10 results from 260+ tokens")

		for _, token := range tokens {
			require.Contains(t, strVal(token.Creator.Username), "testknn", "Creator username should contain search keyword")
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
		require.LessOrEqual(t, len(tokens1), 2)

		tokens2, err := ta.GetCommunityTokensByExternalAddresses(ctx,
			allTokenExtAddrs,
			"requestor_page",
			nil,
			"testknn",
			2,
			2,
		)
		require.NoError(t, err)
		require.LessOrEqual(t, len(tokens2), 2)

		// Verify no overlap between pages
		if len(tokens1) > 0 && len(tokens2) > 0 {
			for _, t1 := range tokens1 {
				for _, t2 := range tokens2 {
					require.NotEqual(t, t1.Creator.Username, t2.Creator.Username, "Pages should not overlap")
				}
			}
		}
	})
}

func TestGetCommunityTokensByExternalAddresses_WithAndWithoutKeyword(t *testing.T) {
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()

	ta := helperNewForTest(t, db)

	// Setup test data
	helperInsertTestUser(t, ctx, db, "creator_kw1", "alice_kw1", "Alice Keyword One", "", true, PlatformGroupIonConnect, "https://avatar1.png")
	helperInsertTestUser(t, ctx, db, "creator_kw2", "bob_kw2", "Bob Keyword Two", "", false, PlatformGroupIonConnect, "https://avatar2.png")
	helperInsertTestUser(t, ctx, db, "creator_kw3", "charlie_kw3", "Charlie Keyword Three", "", true, PlatformGroupIonConnect, "https://avatar3.png")
	helperInsertTestUser(t, ctx, db, "requestor_kw", "requestor_kw", "Requestor KW", "", false, PlatformGroupIonConnect)

	token1Ext := "0:creator_kw1:"
	token2Ext := "0:creator_kw2:"
	token3Ext := "0:creator_kw3:"

	helperInsertTestToken(t, ctx, db, "0xKW1111111111111111111111111111111111111", token1Ext, "TK1", "profile", "creator_kw1", "1000000000000000000000000", 100.0, 0.0001, 5, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, db, "0xKW2222222222222222222222222222222222222", token2Ext, "TK2", "profile", "creator_kw2", "2000000000000000000000000", 200.0, 0.0002, 10, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, db, "0xKW3333333333333333333333333333333333333", token3Ext, "TK3", "post", "creator_kw3", "3000000000000000000000000", 300.0, 0.0003, 15, PlatformGroupIonConnect)

	helperCreateSwapForVolume(t, ctx, db, "0xKW1111111111111111111111111111111111111", token1Ext, "0x0000000000000000000000000000000000000001", false, "100000000000000000000", "1000000000000000000000", 0.0001)
	helperCreateSwapForVolume(t, ctx, db, "0xKW2222222222222222222222222222222222222", token2Ext, "0x0000000000000000000000000000000000000002", false, "200000000000000000000", "2000000000000000000000", 0.0002)
	helperCreateSwapForVolume(t, ctx, db, "0xKW3333333333333333333333333333333333333", token3Ext, "0x0000000000000000000000000000000000000003", false, "300000000000000000000", "3000000000000000000000", 0.0003)
	helperRefreshVolumeView(t, ctx, db)

	t.Run("without keyword - returns full data with ticker", func(t *testing.T) {
		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{token1Ext, token2Ext, token3Ext}, "requestor_kw", nil, "", 0, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 3)

		tickerMap := map[string]string{
			token1Ext: "TK1",
			token2Ext: "TK2",
			token3Ext: "TK3",
		}

		for _, token := range tokens {
			expectedTicker := tickerMap[token.Addresses.IonConnect]
			require.Equal(t, expectedTicker, token.MarketData.Ticker, "Ticker should match for token %s", token.Addresses.IonConnect)
			require.Greater(t, token.MarketData.MarketCap, 0.0, "MarketCap should be present")
			require.Greater(t, token.MarketData.Volume, 0.0, "Volume should be present from materialized view")

			require.NotNil(t, token.Addresses)
			switch token.Addresses.IonConnect {
			case token1Ext:
				require.Equal(t, token1Ext, token.Addresses.IonConnect)
				require.Empty(t, token.Addresses.Twitter)
				require.Equal(t, "0xKW1111111111111111111111111111111111111", token.Addresses.Blockchain)
			case token2Ext:
				require.Equal(t, token2Ext, token.Addresses.IonConnect)
				require.Empty(t, token.Addresses.Twitter)
				require.Equal(t, "0xKW2222222222222222222222222222222222222", token.Addresses.Blockchain)
			case token3Ext:
				require.Equal(t, token3Ext, token.Addresses.IonConnect)
				require.Empty(t, token.Addresses.Twitter)
				require.Equal(t, "0xKW3333333333333333333333333333333333333", token.Addresses.Blockchain)
			}
		}
	})

	t.Run("with keyword - returns simplified data with ticker", func(t *testing.T) {
		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{token1Ext, token2Ext, token3Ext}, "requestor_kw", nil, "alice", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		token := tokens[0]
		require.Equal(t, "profile", token.Type)
		require.Equal(t, "alice_kw1", token.Title)
		require.Equal(t, "Alice Keyword One", token.Description)
		require.Equal(t, "https://avatar1.png", token.ImageURL)

		require.NotNil(t, token.Addresses)
		require.Equal(t, token1Ext, token.Addresses.IonConnect)
		require.Empty(t, token.Addresses.Twitter)
		require.Equal(t, "0xKW1111111111111111111111111111111111111", token.Addresses.Blockchain)

		require.Equal(t, "TK1", token.MarketData.Ticker)
		require.InDelta(t, 100.0, token.MarketData.MarketCap, 0.01)
		require.Greater(t, token.MarketData.Volume, 0.0, "Volume should be present")
		require.InDelta(t, 0.0001, token.MarketData.PriceUSD, 0.00001)
		require.Equal(t, uint64(5), token.MarketData.Holders)

		require.Nil(t, token.MarketData.Position, "Position should be nil when user has no position")
	})

	t.Run("with keyword - uses KNN search and similarity ranking", func(t *testing.T) {
		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{token1Ext, token2Ext, token3Ext}, "requestor_kw", nil, "keyword", 10, 0)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(tokens), 1, "Should find tokens with keyword in lookup")

		tickerMap := map[string]string{
			token1Ext: "TK1",
			token2Ext: "TK2",
			token3Ext: "TK3",
		}

		for _, token := range tokens {
			expectedTicker := tickerMap[token.Addresses.IonConnect]
			require.Equal(t, expectedTicker, token.MarketData.Ticker, "Ticker should match for token %s", token.Addresses.IonConnect)

			require.NotNil(t, token.Addresses)
			switch token.Addresses.IonConnect {
			case token1Ext:
				require.Equal(t, token1Ext, token.Addresses.IonConnect)
				require.Empty(t, token.Addresses.Twitter)
				require.Equal(t, "0xKW1111111111111111111111111111111111111", token.Addresses.Blockchain)
			case token2Ext:
				require.Equal(t, token2Ext, token.Addresses.IonConnect)
				require.Empty(t, token.Addresses.Twitter)
				require.Equal(t, "0xKW2222222222222222222222222222222222222", token.Addresses.Blockchain)
			case token3Ext:
				require.Equal(t, token3Ext, token.Addresses.IonConnect)
				require.Empty(t, token.Addresses.Twitter)
				require.Equal(t, "0xKW3333333333333333333333333333333333333", token.Addresses.Blockchain)
			}
		}
	})

	t.Run("with keyword - pagination works correctly", func(t *testing.T) {
		tokens1, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{token1Ext, token2Ext, token3Ext}, "requestor_kw", nil, "k", 2, 0)
		require.NoError(t, err)
		require.LessOrEqual(t, len(tokens1), 2)

		tokens2, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{token1Ext, token2Ext, token3Ext}, "requestor_kw", nil, "k", 2, 2)
		require.NoError(t, err)
		require.LessOrEqual(t, len(tokens2), 2)

		if len(tokens1) > 0 && len(tokens2) > 0 {
			require.NotEqual(t, tokens1[0].Addresses.IonConnect, tokens2[0].Addresses.IonConnect)
		}
	})
}

func TestGetCommunityTokensWithTopPlatformHolders_WithAndWithoutKeyword(t *testing.T) {
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()

	ta := helperNewForTest(t, db)

	helperInsertTestUser(t, ctx, db, "creator_tph1", "creator_tph1", "Creator TPH One", "", true, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, db, "creator_tph2", "creator_tph2", "Creator TPH Two", "", false, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, db, "holder_tph1", "holder_tph1", "Holder TPH One", "", false, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, db, "holder_tph2", "holder_tph2", "Holder TPH Two", "", true, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, db, "requestor_tph", "requestor_tph", "Requestor TPH", "", false, PlatformGroupIonConnect)

	token1Ext := "0:creator_tph1:"
	token2Ext := "0:creator_tph2:"

	helperInsertTestToken(t, ctx, db, "0xTPH1111111111111111111111111111111111111", token1Ext, "TPH1", "profile", "creator_tph1", "1000000000000000000000000", 100.0, 0.0001, 2, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, db, "0xTPH2222222222222222222222222222222222222", token2Ext, "TPH2", "profile", "creator_tph2", "2000000000000000000000000", 200.0, 0.0002, 2, PlatformGroupIonConnect)

	helperInsertUserTokenPosition(t, ctx, db, "holder_tph1", "0xTPH1111111111111111111111111111111111111", token1Ext, "0:holder_tph1:", "5000000000000000000000", 0.00009, 0.45)
	helperInsertUserTokenPosition(t, ctx, db, "holder_tph2", "0xTPH1111111111111111111111111111111111111", token1Ext, "0:holder_tph2:", "3000000000000000000000", 0.00009, 0.27)
	helperInsertUserTokenPosition(t, ctx, db, "requestor_tph", "0xTPH1111111111111111111111111111111111111", token1Ext, "0:requestor_tph:", "1000000000000000000000", 0.00009, 0.09)

	helperSetupRedisPositionData(t, ctx, testRedis, token1Ext, map[string]float64{
		"0:holder_tph1:":   5000.0,
		"0:holder_tph2:":   3000.0,
		"0:requestor_tph:": 1000.0,
	})

	includeTop := uint32(2)

	t.Run("without keyword - returns full data with ticker", func(t *testing.T) {
		tokens, err := ta.getCommunityTokensWithTopPlatformHolders(ctx, []string{token1Ext, token2Ext}, "requestor_tph", &includeTop, "", 0, 0)
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

		require.Equal(t, "profile", token1.Type)
		require.Equal(t, "TPH1", token1.MarketData.Ticker)

		require.Len(t, token1.MarketData.TopPlatformHolders, 2, "Should return top 2 platform holders")

		holder1 := token1.MarketData.TopPlatformHolders[0]
		require.Equal(t, "holder_tph1", strVal(holder1.Holder.Username))
		require.Equal(t, "Holder TPH One", strVal(holder1.Holder.Display))
		require.True(t, holder1.Holder.Verified == nil || !*holder1.Holder.Verified)
		require.NotEmpty(t, holder1.Holder.Avatar)
		require.Equal(t, "holder_tph1", holder1.Holder.Addresses.IonConnect)
		require.Equal(t, uint64(1), holder1.Rank)
		require.Equal(t, "5000000000000000000000", holder1.Amount)
		require.InDelta(t, 0.5, holder1.AmountUSD, 0.01, "5000 * 0.0001 = 0.5")
		require.InDelta(t, 0.5, holder1.SupplyShare, 0.01, "5000 / 1000000 * 100 = 0.5%")

		holder2 := token1.MarketData.TopPlatformHolders[1]
		require.Equal(t, "holder_tph2", strVal(holder2.Holder.Username))
		require.Equal(t, "Holder TPH Two", strVal(holder2.Holder.Display))
		require.True(t, holder2.Holder.Verified != nil && *holder2.Holder.Verified)
		require.NotEmpty(t, holder2.Holder.Avatar)
		require.Equal(t, "holder_tph2", holder2.Holder.Addresses.IonConnect)
		require.Equal(t, uint64(2), holder2.Rank)
		require.Equal(t, "3000000000000000000000", holder2.Amount)
		require.InDelta(t, 0.3, holder2.AmountUSD, 0.01, "3000 * 0.0001 = 0.3")
		require.InDelta(t, 0.3, holder2.SupplyShare, 0.01, "3000 / 1000000 * 100 = 0.3%")
	})

	t.Run("with keyword - uses CTE candidates and KNN search", func(t *testing.T) {
		tokens, err := ta.getCommunityTokensWithTopPlatformHolders(ctx, []string{token1Ext, token2Ext}, "requestor_tph", &includeTop, "creator_tph1", 10, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1, "Should find only matching token")

		token := tokens[0]
		require.Equal(t, "creator_tph1", strVal(token.Creator.Username), "Should find token by creator username")
		require.Len(t, token.MarketData.TopPlatformHolders, 2, "Should return top platform holders even with keyword")

		holder1 := token.MarketData.TopPlatformHolders[0]
		require.Equal(t, "holder_tph1", strVal(holder1.Holder.Username))
		require.Equal(t, "Holder TPH One", strVal(holder1.Holder.Display))
		require.True(t, holder1.Holder.Verified == nil || !*holder1.Holder.Verified)
		require.NotEmpty(t, holder1.Holder.Avatar)
		require.Equal(t, "holder_tph1", holder1.Holder.Addresses.IonConnect)
		require.Equal(t, uint64(1), holder1.Rank)
		require.Equal(t, "5000000000000000000000", holder1.Amount)
		require.InDelta(t, 0.5, holder1.AmountUSD, 0.01)
		require.InDelta(t, 0.5, holder1.SupplyShare, 0.01)

		holder2 := token.MarketData.TopPlatformHolders[1]
		require.Equal(t, "holder_tph2", strVal(holder2.Holder.Username))
		require.Equal(t, "Holder TPH Two", strVal(holder2.Holder.Display))
		require.True(t, holder2.Holder.Verified != nil && *holder2.Holder.Verified)
		require.NotEmpty(t, holder2.Holder.Avatar)
		require.Equal(t, "holder_tph2", holder2.Holder.Addresses.IonConnect)
		require.Equal(t, uint64(2), holder2.Rank)
		require.Equal(t, "3000000000000000000000", holder2.Amount)
		require.InDelta(t, 0.3, holder2.AmountUSD, 0.01)
		require.InDelta(t, 0.3, holder2.SupplyShare, 0.01)
	})

	t.Run("with keyword - pagination works", func(t *testing.T) {
		tokens1, err := ta.getCommunityTokensWithTopPlatformHolders(ctx, []string{token1Ext, token2Ext}, "requestor_tph", &includeTop, "tph", 1, 0)
		require.NoError(t, err)
		require.LessOrEqual(t, len(tokens1), 1)

		tokens2, err := ta.getCommunityTokensWithTopPlatformHolders(ctx, []string{token1Ext, token2Ext}, "requestor_tph", &includeTop, "tph", 1, 1)
		require.NoError(t, err)
		require.LessOrEqual(t, len(tokens2), 1)
	})
}

func TestGetCommunityTokensByExternalAddresses_WithTopPlatformHolders(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()

	ta := helperNewForTest(t, db)

	t.Run("returns top platform holders", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "creator_top", "alice_top", "Alice Top", "", true, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "holder1_top", "holder1", "Holder One", "", false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "holder2_top", "holder2", "Holder Two", "", false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "requestor_top", "requestor", "Requestor", "", false, PlatformGroupIonConnect)

		tokenExt := "0:creator_top:"
		helperInsertTestToken(t, ctx, db,
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

		helperInsertUserTokenPosition(t, ctx, db, "holder1_top", "0xTOP111111111111111111111111111111111", tokenExt, "0:holder1_top:", "5000000000000000000000", 0.00009, 0.45)
		helperInsertUserTokenPosition(t, ctx, db, "holder2_top", "0xTOP111111111111111111111111111111111", tokenExt, "0:holder2_top:", "3000000000000000000000", 0.00009, 0.27)
		helperInsertUserTokenPosition(t, ctx, db, "requestor_top", "0xTOP111111111111111111111111111111111", tokenExt, "0:requestor_top:", "1000000000000000000000", 0.00009, 0.09)

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

		require.Equal(t, "profile", token.Type)
		require.Equal(t, "TOP1", token.MarketData.Ticker)
		require.Nil(t, token.MarketData.BondingCurveProgress, "BondingCurveProgress should be nil when not set")

		require.Len(t, token.MarketData.TopPlatformHolders, 2, "Expected 2 top platform holders")

		holder1 := token.MarketData.TopPlatformHolders[0]
		require.Equal(t, "holder1", strVal(holder1.Holder.Username))
		require.Equal(t, "Holder One", strVal(holder1.Holder.Display))
		require.True(t, holder1.Holder.Verified == nil || !*holder1.Holder.Verified)
		require.NotEmpty(t, holder1.Holder.Avatar)
		require.Equal(t, "holder1_top", holder1.Holder.Addresses.IonConnect)
		require.Equal(t, uint64(1), holder1.Rank)
		require.Equal(t, "5000000000000000000000", holder1.Amount)
		require.InDelta(t, 0.5, holder1.AmountUSD, 0.01, "5000 * 0.0001 = 0.5")
		require.InDelta(t, 0.05, holder1.SupplyShare, 0.01, "5000 / 10000000 * 100 = 0.05%")

		holder2 := token.MarketData.TopPlatformHolders[1]
		require.Equal(t, "holder2", strVal(holder2.Holder.Username))
		require.Equal(t, "Holder Two", strVal(holder2.Holder.Display))
		require.True(t, holder2.Holder.Verified == nil || !*holder2.Holder.Verified)
		require.NotEmpty(t, holder2.Holder.Avatar)
		require.Equal(t, "holder2_top", holder2.Holder.Addresses.IonConnect)
		require.Equal(t, uint64(2), holder2.Rank)
		require.Equal(t, "3000000000000000000000", holder2.Amount)
		require.InDelta(t, 0.3, holder2.AmountUSD, 0.01, "3000 * 0.0001 = 0.3")
		require.InDelta(t, 0.03, holder2.SupplyShare, 0.01, "3000 / 10000000 * 100 = 0.03%")
	})
}

func TestGetCommunityTokensByPlatform(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()

	ta := helperNewForTest(t, db)

	t.Run("xcom_platform_with_bnb_bsc_address", func(t *testing.T) {
		xcomMasterPubkey := "1234567890"
		xcomUsername := "elonmusk"
		xcomDisplay := "Elon Musk"
		bscAddress := "0x1234567890abcdef1234567890abcdef12345678"

		helperInsertTestUser(t, ctx, db, xcomMasterPubkey, xcomUsername, xcomDisplay, bscAddress, true, PlatformGroupXCom)

		contractAddr := "0xXCOM1111111111111111111111111111111111"
		tokenExt := xcomMasterPubkey

		helperInsertTestToken(t, ctx, db,
			contractAddr,
			tokenExt,
			"XCOM",
			TokenTypeProfile,
			xcomMasterPubkey,
			"1000000000000000000000",
			50.0,
			0.001,
			10,
			PlatformGroupXCom,
		)

		_, err := storage.Exec(ctx, db, `
			UPDATE tokens SET content_author_id = $1 WHERE contract_address = $2
		`, bscAddress, contractAddr)
		require.NoError(t, err)

		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{tokenExt}, "requestor_xcom", nil, "", 0, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		token := tokens[0]

		require.Equal(t, "profile", token.Type)
		require.Equal(t, xcomUsername, token.Title)
		require.Equal(t, xcomDisplay, token.Description)
		require.Equal(t, tokenExt, token.Addresses.Twitter)
		require.Empty(t, token.Addresses.IonConnect)
		require.Equal(t, contractAddr, token.Addresses.Blockchain)

		require.Equal(t, xcomUsername, strVal(token.Creator.Username))
		require.Equal(t, xcomDisplay, strVal(token.Creator.Display))
		require.True(t, token.Creator.Verified != nil && *token.Creator.Verified)
		require.Equal(t, tokenExt, token.Creator.Addresses.Twitter)
		require.Empty(t, token.Creator.Addresses.IonConnect)

		require.Equal(t, bscAddress, token.Creator.Addresses.Blockchain, "X.com creator should have blockchain address from content_author_id")
	})

	t.Run("ionconnect_platform_without_bnb_bsc_address", func(t *testing.T) {
		ionMasterPubkey := "ion_creator_123"
		ionUsername := "alice_ion"
		ionDisplay := "Alice IonConnect"

		helperInsertTestUser(t, ctx, db, ionMasterPubkey, ionUsername, ionDisplay, "", true, PlatformGroupIonConnect)

		contractAddr := "0xION1111111111111111111111111111111111"
		tokenExt := helperBuildProfileExternalAddress(ionMasterPubkey)

		helperInsertTestToken(t, ctx, db,
			contractAddr,
			tokenExt,
			"IONC",
			TokenTypeProfile,
			ionMasterPubkey,
			"2000000000000000000000",
			100.0,
			0.002,
			20,
			PlatformGroupIonConnect,
		)

		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{tokenExt}, "requestor_ion", nil, "", 0, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 1)

		token := tokens[0]

		require.Equal(t, "profile", token.Type)
		require.Equal(t, ionUsername, token.Title)
		require.Equal(t, ionDisplay, token.Description)
		require.Equal(t, tokenExt, token.Addresses.IonConnect)
		require.Empty(t, token.Addresses.Twitter)
		require.Equal(t, contractAddr, token.Addresses.Blockchain)

		require.Equal(t, ionUsername, strVal(token.Creator.Username))
		require.Equal(t, ionDisplay, strVal(token.Creator.Display))
		require.True(t, token.Creator.Verified != nil && *token.Creator.Verified)
		require.Equal(t, ionMasterPubkey, token.Creator.Addresses.IonConnect)
		require.Empty(t, token.Creator.Addresses.Twitter)

		require.Empty(t, token.Creator.Addresses.Blockchain, "IonConnect creator should NOT have blockchain address")
	})

	t.Run("mixed_platforms_in_same_query", func(t *testing.T) {
		xcomMasterPubkey := "9876543210"
		xcomTokenExt := xcomMasterPubkey
		xcomBscAddr := "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"

		helperInsertTestUser(t, ctx, db, xcomMasterPubkey, "jack", "Jack Dorsey", "", true, PlatformGroupXCom)
		helperInsertTestToken(t, ctx, db,
			"0xJACK1111111111111111111111111111111111",
			xcomTokenExt,
			"JACK",
			TokenTypeProfile,
			xcomMasterPubkey,
			"5000000000000000000000",
			200.0,
			0.005,
			50,
			PlatformGroupXCom,
		)
		_, err := storage.Exec(ctx, db, `
			UPDATE tokens SET content_author_id = $1 WHERE external_address = $2
		`, xcomBscAddr, xcomTokenExt)
		require.NoError(t, err)

		ionMasterPubkey := "ion_mixed_456"
		ionTokenExt := helperBuildProfileExternalAddress(ionMasterPubkey)

		helperInsertTestUser(t, ctx, db, ionMasterPubkey, "bob_ion", "Bob IonConnect", "", false, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db,
			"0xBOB1111111111111111111111111111111111",
			ionTokenExt,
			"BOB",
			TokenTypeProfile,
			ionMasterPubkey,
			"3000000000000000000000",
			150.0,
			0.003,
			30,
			PlatformGroupIonConnect,
		)

		tokens, err := ta.GetCommunityTokensByExternalAddresses(ctx, []string{xcomTokenExt, ionTokenExt}, "requestor_mixed", nil, "", 0, 0)
		require.NoError(t, err)
		require.Len(t, tokens, 2)

		var xcomToken *CommunityToken
		var ionToken *CommunityToken
		for _, token := range tokens {
			if token.Addresses.Twitter != "" {
				xcomToken = token
			} else {
				ionToken = token
			}
		}

		require.NotNil(t, xcomToken, "X.com token should be found")
		require.NotNil(t, ionToken, "IonConnect token should be found")

		require.Equal(t, xcomBscAddr, xcomToken.Creator.Addresses.Blockchain)
		require.NotEmpty(t, xcomToken.Addresses.Twitter)
		require.Empty(t, xcomToken.Addresses.IonConnect)

		require.Empty(t, ionToken.Creator.Addresses.Blockchain)
		require.Empty(t, ionToken.Addresses.Twitter)
		require.NotEmpty(t, ionToken.Addresses.IonConnect)
	})
}

func helperBuildProfileExternalAddress(masterPubkey string) string {
	return fmt.Sprintf("0:%s:", masterPubkey)
}

func helperInsertTestUser(t *testing.T, ctx context.Context, db *storage.DB, masterPubkey, username, displayName, contentAuthorID string, verified bool, platformGroup string, avatar ...string) {
	t.Helper()
	var externalAddr string
	if platformGroup == "xcom" {
		externalAddr = masterPubkey
	} else {
		externalAddr = helperBuildProfileExternalAddress(masterPubkey)
	}
	if contentAuthorID == "" {
		hexPubkey := fmt.Sprintf("%040s", masterPubkey)
		hexPubkey = strings.ReplaceAll(hexPubkey, " ", "0")
		if len(hexPubkey) > 40 {
			hexPubkey = hexPubkey[:40]
		}
		contentAuthorID = "0x" + hexPubkey
	}
	contentAuthorID = strings.ToLower(contentAuthorID)

	avatarURL := "avatar.png"
	if len(avatar) > 0 && avatar[0] != "" {
		avatarURL = avatar[0]
	}

	query := `
		INSERT INTO users (created_at, updated_at, id, master_pubkey, content_author_id, external_address, username, display_name, avatar, lookup, verified, platform_group)
		VALUES (NOW(), NOW(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (content_author_id) DO UPDATE SET
			master_pubkey = EXCLUDED.master_pubkey,
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
		contentAuthorID,
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
		Username        string `db:"username"`
		DisplayName     string `db:"display_name"`
		ContentAuthorID string `db:"content_author_id"`
		Avatar          string `db:"avatar"`
	}
	users, err := storage.Select[userInfo](ctx, db, "SELECT username, COALESCE(display_name, '') as display_name, content_author_id, COALESCE(avatar, '') as avatar FROM users WHERE master_pubkey = $1", creatorPubkey)
	var username, displayName, creatorContentAuthorID, avatarURL string
	if err == nil && len(users) > 0 {
		username = users[0].Username
		displayName = users[0].DisplayName
		creatorContentAuthorID = users[0].ContentAuthorID
		avatarURL = users[0].Avatar
	}
	lookup := strings.ToLower(strings.TrimSpace(username + " " + displayName + " " + ticker))

	query := `
		INSERT INTO tokens (
			created_at, updated_at, contract_address, external_address, platform,
			ticker, total_supply, content_author_id, type, 
			market_cap_usd, price_usd, holders_count, lookup,
			title, description, image_url, price_model
		)
		VALUES (NOW(), NOW(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, '0x000000000000000000000000000000000000dead')
		ON CONFLICT (contract_address) DO UPDATE SET
			external_address = EXCLUDED.external_address,
			platform = EXCLUDED.platform,
			ticker = EXCLUDED.ticker,
			total_supply = EXCLUDED.total_supply,
			type = EXCLUDED.type,
			market_cap_usd = EXCLUDED.market_cap_usd,
			price_usd = EXCLUDED.price_usd,
			holders_count = EXCLUDED.holders_count,
			lookup = EXCLUDED.lookup,
			title = EXCLUDED.title,
			description = EXCLUDED.description,
			image_url = EXCLUDED.image_url
	`
	_, err = storage.Exec(ctx, db, query,
		contractAddress,
		externalAddress,
		platform,
		ticker,
		totalSupply,
		creatorContentAuthorID,
		tokenType,
		marketCapUSD,
		priceUSD,
		holdersCount,
		lookup,
		username,
		displayName,
		avatarURL,
	)
	require.NoError(t, err, "failed to insert test token")
}

func helperUpdateTokenBondingCurve(t *testing.T, ctx context.Context, db *storage.DB,
	externalAddress, currentAmount, goalAmount string, currentAmountUSD, goalAmountUSD float64, raisedAmount string, migrated bool) {
	t.Helper()

	_, err := storage.Exec(ctx, db, `
		UPDATE tokens 
		SET bonding_curve_current_amount = $1,
		    bonding_curve_goal_amount = $2,
		    bonding_curve_current_amount_usd = $3,
		    bonding_curve_goal_amount_usd = $4,
		    bonding_curve_raised_amount = $5,
		    bonding_curve_migrated = $6
		WHERE external_address = $7`,
		currentAmount,
		goalAmount,
		currentAmountUSD,
		goalAmountUSD,
		raisedAmount,
		migrated,
		externalAddress,
	)
	require.NoError(t, err, "failed to update token bonding curve")
}

func helperInsertUserTokenPosition(t *testing.T, ctx context.Context, db *storage.DB,
	masterPubkey, contractAddress, externalAddress, userExternalAddress string, amount string, avgBuyPriceUSD, totalInvestedUSD float64, totalRealizedUSD ...float64) {
	t.Helper()

	type userAddr struct {
		ContentAuthorID string `db:"content_author_id"`
	}
	users, err := storage.Select[userAddr](ctx, db, "SELECT content_author_id FROM users WHERE master_pubkey = $1", masterPubkey)
	var contentAuthorID string
	if err == nil && len(users) > 0 {
		contentAuthorID = users[0].ContentAuthorID
	} else {
		hexPubkey := fmt.Sprintf("%040s", masterPubkey)
		hexPubkey = strings.ReplaceAll(hexPubkey, " ", "0")
		if len(hexPubkey) > 40 {
			hexPubkey = hexPubkey[:40]
		}
		contentAuthorID = "0x" + hexPubkey
	}

	realized := 0.0
	if len(totalRealizedUSD) > 0 {
		realized = totalRealizedUSD[0]
	}

	query := `
		INSERT INTO user_token_positions (
			updated_at, user_blockchain_address, contract_address, external_address, user_external_address,
			amount, avg_buy_price_usd, total_invested_usd, total_realized_usd
		)
		VALUES (NOW(), $1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (user_blockchain_address, contract_address) DO UPDATE SET
			amount = EXCLUDED.amount,
			external_address = EXCLUDED.external_address,
			user_external_address = EXCLUDED.user_external_address,
		    avg_buy_price_usd = EXCLUDED.avg_buy_price_usd,
		    total_invested_usd = EXCLUDED.total_invested_usd,
		    total_realized_usd = EXCLUDED.total_realized_usd,
		    updated_at = NOW()
	`
	_, err = storage.Exec(ctx, db, query,
		contentAuthorID,
		contractAddress,
		externalAddress,
		userExternalAddress,
		amount,
		avgBuyPriceUSD,
		totalInvestedUSD,
		realized,
	)
	require.NoError(t, err, "failed to insert user token position")
}

func helperInsertTokenSwap(t *testing.T, ctx context.Context, db *storage.DB,
	contractAddress, externalAddress, userAddress string,
	txHash string,
	direction bool, inputAmount, outputAmount string, priceUSD float64, createdAt ...stdtime.Time) {
	t.Helper()

	var swapTime stdtime.Time
	if len(createdAt) > 0 {
		swapTime = createdAt[0]
	} else {
		swapTime = stdtime.Now()
	}

	query := `
		INSERT INTO token_swaps (
			created_at, transaction_hash, contract_address, external_address,
			user_blockchain_address, direction, input_amount, output_amount, price_usd, fee
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 0)
		ON CONFLICT (transaction_hash, contract_address, user_blockchain_address) DO NOTHING
	`
	_, err := storage.Exec(ctx, db, query,
		swapTime,
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

func helperCreateSwapForVolume(t *testing.T, ctx context.Context, db *storage.DB,
	contractAddress, externalAddress, userAddress string, direction bool, inputAmount, outputAmount string, priceUSD float64) {
	t.Helper()

	txHash := fmt.Sprintf("0x%s%d", contractAddress[2:10], stdtime.Now().UnixNano())
	query := `
		INSERT INTO token_swaps (
			created_at, transaction_hash, contract_address, external_address,
			user_blockchain_address, direction, input_amount, output_amount, fee, price_usd
		)
		VALUES (NOW(), $1, $2, $3, $4, $5, $6, $7, 0, $8)
		ON CONFLICT (transaction_hash, contract_address, user_blockchain_address) DO NOTHING
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

func helperSetupRedisPositionData(t *testing.T, ctx context.Context, client redis.Cmdable,
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
