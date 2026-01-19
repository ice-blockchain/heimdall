// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetHolderPositions(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()

	ta := helperNewForTest(t, db)

	t.Run("returns positions for specified holders", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "creator_holder", "creator", "Creator", "", false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "holder_a", "holdera", "Holder A", "", false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "holder_b", "holderb", "Holder B", "", false, PlatformGroupIonConnect)

		tokenExt := "0:creator_holder:"
		helperInsertTestToken(t, ctx, db,
			"0xHOLDER1111111111111111111111111111111",
			tokenExt,
			"HOLD",
			"profile",
			"creator_holder",
			"10000000000000000000000000",
			1000.0,
			0.0001,
			2,
			PlatformGroupIonConnect,
		)

		helperInsertUserTokenPosition(t, ctx, db,
			"holder_a",
			"0xHOLDER1111111111111111111111111111111",
			tokenExt,
			"0:holder_a:",
			"5000000000000000000000", // 5000 tokens
			0.00009,
			0.45,
		)
		helperInsertUserTokenPosition(t, ctx, db,
			"holder_b",
			"0xHOLDER1111111111111111111111111111111",
			tokenExt,
			"0:holder_b:",
			"3000000000000000000000", // 3000 tokens
			0.00008,
			0.24,
		)

		helperSetupRedisPositionData(t, ctx, testRedis, tokenExt, map[string]float64{
			"0:holder_a:": 5000.0,
			"0:holder_b:": 3000.0,
		})

		positions, err := ta.GetHolderPositions(ctx, tokenExt, []string{"0:holder_a:", "0:holder_b:"})
		require.NoError(t, err)
		require.Len(t, positions, 2)

		// Verify ALL fields for first position with exact values
		require.Equal(t, "holdera", strVal(positions[0].Holder.Username))
		require.Equal(t, "Holder A", strVal(positions[0].Holder.Display))
		require.True(t, positions[0].Holder.Verified == nil || !*positions[0].Holder.Verified)
		require.NotEmpty(t, positions[0].Holder.Avatar)
		require.Equal(t, "holder_a", positions[0].Holder.Addresses.IonConnect)

		require.Equal(t, uint64(1), positions[0].Rank)
		require.Equal(t, "5000000000000000000000", positions[0].Amount) // 5000 * 1e18
		// AmountUSD: 5000 * $0.0001 = $0.5
		require.InDelta(t, 0.5, positions[0].AmountUSD, 0.01)
		// PnL: $0.5 - $0.45 = $0.05
		require.InDelta(t, 0.05, positions[0].PnL, 0.01)
		// PnL%: 0.05 / 0.45 * 100 = 11.11%
		require.InDelta(t, 11.11, positions[0].PnLPercentage, 1.0)

		// Verify second position with exact values
		require.Equal(t, "holderb", strVal(positions[1].Holder.Username))
		require.Equal(t, "Holder B", strVal(positions[1].Holder.Display))
		require.True(t, positions[1].Holder.Verified == nil || !*positions[1].Holder.Verified)
		require.Equal(t, "holder_b", positions[1].Holder.Addresses.IonConnect)
		require.Equal(t, uint64(2), positions[1].Rank)
		require.Equal(t, "3000000000000000000000", positions[1].Amount) // 3000 * 1e18
		// AmountUSD: 3000 * $0.0001 = $0.3
		require.InDelta(t, 0.3, positions[1].AmountUSD, 0.01)
		// PnL: $0.3 - $0.24 = $0.06
		require.InDelta(t, 0.06, positions[1].PnL, 0.01)
		// PnL%: 0.06 / 0.24 * 100 = 25%
		require.InDelta(t, 25.0, positions[1].PnLPercentage, 1.0)
	})

	t.Run("returns empty for non-existent holders", func(t *testing.T) {
		positions, err := ta.GetHolderPositions(ctx, "a0:nonexistent:", []string{"a0:fake:"})
		require.NoError(t, err)
		require.Empty(t, positions)
	})

	t.Run("PnL calculation with partial sales - break even", func(t *testing.T) {
		// User bought 300 tokens for $0.9, sold 150 for $0.45, holding 150 worth $0.45
		// PnL = ($0.45 + $0.45) - $0.9 = $0
		helperInsertTestUser(t, ctx, db, "creator_pnl_holder", "pnl_creator", "PnL Creator", "", false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "holder_pnl_test", "pnl_tester", "PnL Tester", "", false, PlatformGroupIonConnect)

		tokenExt := "0:creator_pnl_holder:"
		contractAddr := "0xPNLHOLDER11111111111111111111111111"
		helperInsertTestToken(t, ctx, db,
			contractAddr,
			tokenExt,
			"PNLH",
			"profile",
			"creator_pnl_holder",
			"100000000000000000000000",
			45.0,
			0.003, // Current price $0.003
			1,
			PlatformGroupIonConnect,
		)

		helperInsertUserTokenPosition(t, ctx, db,
			"holder_pnl_test",
			contractAddr,
			tokenExt,
			"0:holder_pnl_test:",
			"150000000000000000000", // 150 tokens
			0.003,                   // avg_buy_price_usd
			0.9,                     // total_invested_usd
			0.45,                    // total_realized_usd (revenue from sale)
		)

		helperSetupRedisPositionData(t, ctx, testRedis, tokenExt, map[string]float64{
			"0:holder_pnl_test:": 150.0,
		})

		positions, err := ta.GetHolderPositions(ctx, tokenExt, []string{"0:holder_pnl_test:"})
		require.NoError(t, err)
		require.Len(t, positions, 1)

		// Current value: 150 * $0.003 = $0.45
		require.InDelta(t, 0.45, positions[0].AmountUSD, 0.01)
		// PnL = ($0.45 + $0.45) - $0.9 = $0
		require.InDelta(t, 0.0, positions[0].PnL, 0.01, "PnL should be $0 (break even)")
		require.InDelta(t, 0.0, positions[0].PnLPercentage, 0.01, "PnL% should be 0%")
	})

	t.Run("PnL calculation with sale at profit", func(t *testing.T) {
		// Bought 200 for $100, sold 100 for $60, holding 100 worth $55
		// PnL = ($55 + $60) - $100 = $15 (15%)
		helperInsertTestUser(t, ctx, db, "creator_profit_holder", "profit_creator", "Profit Creator", "", false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "holder_profit_test", "profit_tester", "Profit Tester", "", false, PlatformGroupIonConnect)

		tokenExt := "0:creator_profit_holder:"
		contractAddr := "0xPROFITHOLDER111111111111111111111"
		helperInsertTestToken(t, ctx, db,
			contractAddr,
			tokenExt,
			"PROFH",
			"profile",
			"creator_profit_holder",
			"50000000000000000000000",
			55.0,
			0.55, // Current price $0.55
			1,
			PlatformGroupIonConnect,
		)

		helperInsertUserTokenPosition(t, ctx, db,
			"holder_profit_test",
			contractAddr,
			tokenExt,
			"0:holder_profit_test:",
			"100000000000000000000", // 100 tokens
			0.5,                     // avg_buy_price_usd
			100.0,                   // total_invested_usd
			60.0,                    // total_realized_usd
		)

		helperSetupRedisPositionData(t, ctx, testRedis, tokenExt, map[string]float64{
			"0:holder_profit_test:": 100.0,
		})

		positions, err := ta.GetHolderPositions(ctx, tokenExt, []string{"0:holder_profit_test:"})
		require.NoError(t, err)
		require.Len(t, positions, 1)

		// Current value: 100 * $0.55 = $55
		require.InDelta(t, 55.0, positions[0].AmountUSD, 0.01)
		// PnL = ($55 + $60) - $100 = $15
		require.InDelta(t, 15.0, positions[0].PnL, 0.01, "PnL should be $15")
		require.InDelta(t, 15.0, positions[0].PnLPercentage, 1.0, "PnL% should be 15%")
	})

	t.Run("PnL calculation with sale at loss", func(t *testing.T) {
		// Bought 200 for $100, sold 100 for $40, holding 100 worth $35
		// PnL = ($35 + $40) - $100 = -$25 (-25%)
		helperInsertTestUser(t, ctx, db, "creator_loss_holder", "loss_creator", "Loss Creator", "", false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "holder_loss_test", "loss_tester", "Loss Tester", "", false, PlatformGroupIonConnect)

		tokenExt := "0:creator_loss_holder:"
		contractAddr := "0xLOSSHOLDER1111111111111111111111111"
		helperInsertTestToken(t, ctx, db,
			contractAddr,
			tokenExt,
			"LOSSH",
			"profile",
			"creator_loss_holder",
			"50000000000000000000000",
			35.0,
			0.35, // Current price $0.35
			1,
			PlatformGroupIonConnect,
		)

		helperInsertUserTokenPosition(t, ctx, db,
			"holder_loss_test",
			contractAddr,
			tokenExt,
			"0:holder_loss_test:",
			"100000000000000000000", // 100 tokens
			0.5,                     // avg_buy_price_usd
			100.0,                   // total_invested_usd
			40.0,                    // total_realized_usd
		)

		helperSetupRedisPositionData(t, ctx, testRedis, tokenExt, map[string]float64{
			"0:holder_loss_test:": 100.0,
		})

		positions, err := ta.GetHolderPositions(ctx, tokenExt, []string{"0:holder_loss_test:"})
		require.NoError(t, err)
		require.Len(t, positions, 1)

		// Current value: 100 * $0.35 = $35
		require.InDelta(t, 35.0, positions[0].AmountUSD, 0.01)
		// PnL = ($35 + $40) - $100 = -$25
		require.InDelta(t, -25.0, positions[0].PnL, 0.01, "PnL should be -$25")
		require.InDelta(t, -25.0, positions[0].PnLPercentage, 1.0, "PnL% should be -25%")
	})
}
