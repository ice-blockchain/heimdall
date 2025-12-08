// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetHolderPositions(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	ta := NewForTest(ctx)

	t.Run("returns positions for specified holders", func(t *testing.T) {
		helperInsertTestUser(t, ctx, testDB, "creator_holder", "creator", "Creator", "", false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, testDB, "holder_a", "holdera", "Holder A", "", false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, testDB, "holder_b", "holderb", "Holder B", "", false, PlatformGroupIonConnect)

		tokenExt := "0:creator_holder:"
		helperInsertTestToken(t, ctx, testDB,
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

		helperInsertUserTokenPosition(t, ctx, testDB,
			"holder_a",
			"0xHOLDER1111111111111111111111111111111",
			tokenExt,
			"0:holder_a:",
			"5000000000000000000000", // 5000 tokens
			0.00009,
			0.45,
		)
		helperInsertUserTokenPosition(t, ctx, testDB,
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
		assert.Equal(t, "holdera", positions[0].Holder.Username)
		assert.Equal(t, "Holder A", positions[0].Holder.Display)
		assert.False(t, positions[0].Holder.Verified)
		assert.NotEmpty(t, positions[0].Holder.Avatar)
		assert.Equal(t, "0:holder_a:", positions[0].Holder.Addresses.IonConnect)

		assert.Equal(t, uint64(1), positions[0].Rank)
		// Amount: Already converted from wei by weiToUint64
		assert.InDelta(t, 5000.0, float64(positions[0].Amount), 10.0)
		// AmountUSD: 5000 * $0.0001 = $0.5
		assert.InDelta(t, 0.5, positions[0].AmountUSD, 0.01)
		// PnL: $0.5 - $0.45 = $0.05
		assert.InDelta(t, 0.05, positions[0].PnL, 0.01)
		// PnL%: 0.05 / 0.45 * 100 = 11.11%
		assert.InDelta(t, 11.11, positions[0].PnLPercentage, 1.0)

		// Verify second position with exact values
		assert.Equal(t, "holderb", positions[1].Holder.Username)
		assert.Equal(t, "Holder B", positions[1].Holder.Display)
		assert.False(t, positions[1].Holder.Verified)
		assert.Equal(t, "0:holder_b:", positions[1].Holder.Addresses.IonConnect)
		assert.Equal(t, uint64(2), positions[1].Rank)
		// Amount: Already converted from wei by weiToUint64
		assert.InDelta(t, 3000.0, float64(positions[1].Amount), 10.0)
		// AmountUSD: 3000 * $0.0001 = $0.3
		assert.InDelta(t, 0.3, positions[1].AmountUSD, 0.01)
		// PnL: $0.3 - $0.24 = $0.06
		assert.InDelta(t, 0.06, positions[1].PnL, 0.01)
		// PnL%: 0.06 / 0.24 * 100 = 25%
		assert.InDelta(t, 25.0, positions[1].PnLPercentage, 1.0)
	})

	t.Run("returns empty for non-existent holders", func(t *testing.T) {
		positions, err := ta.GetHolderPositions(ctx, "a0:nonexistent:", []string{"a0:fake:"})
		require.NoError(t, err)
		assert.Empty(t, positions)
	})
}
