// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCalculatePnL(t *testing.T) {
	t.Parallel()

	t.Run("profit scenario", func(t *testing.T) {
		// Invested $100, current value $150, no sales
		pnl, pnlPercentage := calculatePnL(150.0, 100.0, 0.0)
		assert.InDelta(t, 50.0, pnl, 0.01, "PnL should be $50")
		assert.InDelta(t, 50.0, pnlPercentage, 0.01, "PnL% should be 50%")
	})

	t.Run("loss scenario", func(t *testing.T) {
		// Invested $100, current value $80, no sales
		pnl, pnlPercentage := calculatePnL(80.0, 100.0, 0.0)
		assert.InDelta(t, -20.0, pnl, 0.01, "PnL should be -$20")
		assert.InDelta(t, -20.0, pnlPercentage, 0.01, "PnL% should be -20%")
	})

	t.Run("break even with partial sale - your example", func(t *testing.T) {
		// Bought 100 ION worth ($0.3)
		// Bought 200 ION worth ($0.6)
		// Total invested: $0.9
		// Sold 50% (450 tokens) for 150 ION ($0.45) - realized $0.45
		// Holding 50% (450 tokens) worth $0.45 - unrealized $0.45
		// Total: $0.45 + $0.45 = $0.9
		// PnL = $0.9 - $0.9 = $0

		invested := 0.9
		currentHoldingValue := 0.45
		realized := 0.45

		pnl, pnlPercentage := calculatePnL(currentHoldingValue, invested, realized)
		assert.InDelta(t, 0.0, pnl, 0.01, "PnL should be $0 (break even)")
		assert.InDelta(t, 0.0, pnlPercentage, 0.01, "PnL% should be 0%")
	})

	t.Run("profit with partial sale", func(t *testing.T) {
		// Invested $100
		// Sold 50% for $60 (realized $10 profit on sold portion)
		// Holding 50% worth $55 (unrealized $5 profit on holding)
		// Total: $60 + $55 = $115
		// PnL = $115 - $100 = $15

		invested := 100.0
		currentHoldingValue := 55.0
		realized := 60.0

		pnl, pnlPercentage := calculatePnL(currentHoldingValue, invested, realized)
		assert.InDelta(t, 15.0, pnl, 0.01, "PnL should be $15")
		assert.InDelta(t, 15.0, pnlPercentage, 0.01, "PnL% should be 15%")
	})

	t.Run("loss with partial sale", func(t *testing.T) {
		// Invested $100
		// Sold 50% for $40 (realized $10 loss on sold portion)
		// Holding 50% worth $35 (unrealized $15 loss on holding)
		// Total: $40 + $35 = $75
		// PnL = $75 - $100 = -$25

		invested := 100.0
		currentHoldingValue := 35.0
		realized := 40.0

		pnl, pnlPercentage := calculatePnL(currentHoldingValue, invested, realized)
		assert.InDelta(t, -25.0, pnl, 0.01, "PnL should be -$25")
		assert.InDelta(t, -25.0, pnlPercentage, 0.01, "PnL% should be -25%")
	})

	t.Run("sold everything at profit", func(t *testing.T) {
		// Invested $100, sold everything for $120
		// Current holding: $0, realized: $120
		// PnL = $120 - $100 = $20

		invested := 100.0
		currentHoldingValue := 0.0
		realized := 120.0

		pnl, pnlPercentage := calculatePnL(currentHoldingValue, invested, realized)
		assert.InDelta(t, 20.0, pnl, 0.01, "PnL should be $20")
		assert.InDelta(t, 20.0, pnlPercentage, 0.01, "PnL% should be 20%")
	})

	t.Run("sold everything at loss", func(t *testing.T) {
		// Invested $100, sold everything for $70
		// Current holding: $0, realized: $70
		// PnL = $70 - $100 = -$30

		invested := 100.0
		currentHoldingValue := 0.0
		realized := 70.0

		pnl, pnlPercentage := calculatePnL(currentHoldingValue, invested, realized)
		assert.InDelta(t, -30.0, pnl, 0.01, "PnL should be -$30")
		assert.InDelta(t, -30.0, pnlPercentage, 0.01, "PnL% should be -30%")
	})

	t.Run("handles zero investment", func(t *testing.T) {
		// Edge case: somehow got tokens without investment (airdrop?)
		pnl, pnlPercentage := calculatePnL(100.0, 0.0, 0.0)
		assert.Equal(t, 100.0, pnl, "PnL should equal current value")
		assert.Equal(t, 0.0, pnlPercentage, "PnL% should be 0 when invested is 0")
	})

	t.Run("doubled investment", func(t *testing.T) {
		// Invested $100, now worth $200 (all unrealized)
		pnl, pnlPercentage := calculatePnL(200.0, 100.0, 0.0)
		assert.InDelta(t, 100.0, pnl, 0.01, "PnL should be $100")
		assert.InDelta(t, 100.0, pnlPercentage, 0.01, "PnL% should be 100%")
	})
}
