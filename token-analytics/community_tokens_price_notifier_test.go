// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func TestPriceNotifier(t *testing.T) {
	t.Run("handles price update via handlePriceUpdate", func(t *testing.T) {
		ctx := t.Context()

		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db).(*tokenAnalytics)

		tokenExternalAddr := "0:price_notifier_test:"
		contractAddr := "0x1111222233334444555566667777888899990000"
		pairID := "0xaaaa000000000000000000000000000000000000000000000000000000000001"
		baseToken := "0x2c73996babf1a06c2c057177353293f7ca0907c8"

		helperInsertTestToken(t, ctx, db,
			contractAddr, tokenExternalAddr, "NOTIFY", "profile", "test_master",
			"1000000000000000000000000", 0.001, 1000, 10, PlatformGroupIonConnect)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, tokenExternalAddr, pairID, baseToken)
		helperInsertBaseTokenPrice(t, ctx, db, baseToken, "ION", 0.01)

		helperUpdateTokenBondingCurve(t, ctx, db, tokenExternalAddr,
			"100000000000000000000", "200000000000000000000",
			1.0, 2.0, "10000000000000000000", false)
		helperUpdateTokenLiquidity(t, ctx, db, tokenExternalAddr, 0.5)

		err := ta.processedDataDB.ZAdd(ctx, globalTopSetKey, redis.Z{
			Score:  1000.0,
			Member: tokenExternalAddr,
		}).Err()
		require.NoError(t, err)

		newPriceUSD := 0.002
		newCurrentAmount := "150000000000000000000" // 150 tokens
		newCurrentAmountUSD := 1.5

		helperUpdateTokenBondingCurveAndPrice(t, ctx, db, tokenExternalAddr, newCurrentAmount, newCurrentAmountUSD, newPriceUSD)

		payload := fmt.Sprintf(`{
			"external_address": "%s",
			"contract_address": "%s",
			"price_usd": %f,
			"total_supply": "1000000000000000000000000",
			"liquidity_usd": 0.5,
			"bonding_curve_migrated": false,
			"bonding_curve_current_amount": "%s",
			"bonding_curve_goal_amount": "200000000000000000000",
			"bonding_curve_raised_amount": "10000000000000000000",
			"bonding_curve_current_amount_usd": %f,
			"bonding_curve_goal_amount_usd": 2.0,
			"updated_at": 1234567890.0
		}`, tokenExternalAddr, contractAddr, newPriceUSD, newCurrentAmount, newCurrentAmountUSD)

		err = ta.handlePriceUpdate(ctx, payload)
		require.NoError(t, err)

		score, err := ta.processedDataDB.ZScore(ctx, globalTopSetKey, tokenExternalAddr).Result()
		require.NoError(t, err)
		expectedMarketCap := newPriceUSD * 1000000.0
		require.InDelta(t, expectedMarketCap, score, 0.1, "Redis market cap should be updated")

		bcScore, err := ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressSetKey, tokenExternalAddr).Result()
		require.NoError(t, err)
		require.InDelta(t, 150.0, bcScore, 0.1, "Redis bonding curve progress should be updated")
	})

	t.Run("handles token migration", func(t *testing.T) {
		ctx := t.Context()

		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db).(*tokenAnalytics)

		tokenExternalAddr := "0:migration_test:"
		contractAddr := "0x2222333344445555666677778888999900001111"
		pairID := "0xbbbb000000000000000000000000000000000000000000000000000000000002"
		baseToken := "0x2c73996babf1a06c2c057177353293f7ca0907c8"

		helperInsertTestToken(t, ctx, db,
			contractAddr, tokenExternalAddr, "MIGRATE", "profile", "test_master",
			"1000000000000000000000000", 0.003, 3000, 15, PlatformGroupIonConnect)
		helperUpdateTokenPairAndBaseToken(t, ctx, db, tokenExternalAddr, pairID, baseToken)
		helperInsertBaseTokenPrice(t, ctx, db, baseToken, "ION", 0.01)

		helperUpdateTokenBondingCurve(t, ctx, db, tokenExternalAddr,
			"200000000000000000000", "200000000000000000000",
			0, 0, "0", false)
		helperUpdateTokenLiquidity(t, ctx, db, tokenExternalAddr, 1.0)

		err := ta.processedDataDB.ZAdd(ctx, globalTopSetKey, redis.Z{
			Score:  3000.0,
			Member: tokenExternalAddr,
		}).Err()
		require.NoError(t, err)

		err = ta.processedDataDB.ZAdd(ctx, globalBondingCurveProgressSetKey, redis.Z{
			Score:  200.0,
			Member: tokenExternalAddr,
		}).Err()
		require.NoError(t, err)

		helperMigrateToken(t, ctx, db, tokenExternalAddr, 100.0, 0.005)

		payload := fmt.Sprintf(`{
			"external_address": "%s",
			"contract_address": "%s",
			"price_usd": 0.005,
			"total_supply": "1000000000000000000000000",
			"liquidity_usd": 100.0,
			"bonding_curve_migrated": true,
			"bonding_curve_current_amount": "200000000000000000000",
			"bonding_curve_goal_amount": "200000000000000000000",
			"bonding_curve_raised_amount": "0",
			"bonding_curve_current_amount_usd": 0,
			"bonding_curve_goal_amount_usd": 0,
			"updated_at": 1234567890.0
		}`, tokenExternalAddr, contractAddr)

		err = ta.handlePriceUpdate(ctx, payload)
		require.NoError(t, err)

		_, err = ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressSetKey, tokenExternalAddr).Result()
		require.Equal(t, redis.Nil, err, "Token should be removed from bonding curve set after migration")

		score, err := ta.processedDataDB.ZScore(ctx, globalTopSetKey, tokenExternalAddr).Result()
		require.NoError(t, err)
		expectedMarketCap := 0.005 * 1000000.0
		require.InDelta(t, expectedMarketCap, score, 10.0, "Token should still be in global top set with updated market cap")
	})

	t.Run("adds new tokens to redis automatically", func(t *testing.T) {
		ctx := t.Context()

		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db).(*tokenAnalytics)

		tokenExternalAddr := "0:new_token_auto_add:"
		contractAddr := "0x3333444455556666777788889999000011112222"

		helperInsertTestToken(t, ctx, db,
			contractAddr, tokenExternalAddr, "NEWADD", "profile", "test_master",
			"1000000000000000000000000", 0.001, 100, 5, PlatformGroupIonConnect)

		helperUpdateTokenBondingCurveAndPrice(t, ctx, db, tokenExternalAddr, "50000000000000000000", 0, 0.001)

		newPrice := 0.002
		helperUpdateTokenPrice(t, ctx, db, tokenExternalAddr, newPrice)

		payload := fmt.Sprintf(`{
			"external_address": "%s",
			"contract_address": "%s",
			"price_usd": %f,
			"total_supply": "1000000000000000000000000",
			"liquidity_usd": 0,
			"bonding_curve_migrated": false,
			"bonding_curve_current_amount": "50000000000000000000",
			"bonding_curve_goal_amount": "0",
			"bonding_curve_raised_amount": "0",
			"bonding_curve_current_amount_usd": 0,
			"bonding_curve_goal_amount_usd": 0,
			"updated_at": 1234567890.0
		}`, tokenExternalAddr, contractAddr, newPrice)

		err := ta.handlePriceUpdate(ctx, payload)
		require.NoError(t, err)

		score, err := ta.processedDataDB.ZScore(ctx, globalTopSetKey, tokenExternalAddr).Result()
		require.NoError(t, err)
		expectedMarketCap := newPrice * 1000000.0
		require.InDelta(t, expectedMarketCap, score, 10.0, "Token should be automatically added to Redis with correct market cap")
	})

	t.Run("parses notification payload correctly", func(t *testing.T) {
		ctx := t.Context()
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db).(*tokenAnalytics)

		tokenExternalAddr := "0:unit_test:"

		err := ta.processedDataDB.ZAdd(ctx, globalTopSetKey, redis.Z{
			Score:  1000.0,
			Member: tokenExternalAddr,
		}).Err()
		require.NoError(t, err)

		payload := `{
			"external_address": "0:unit_test:",
			"contract_address": "0x1234567890123456789012345678901234567890",
			"price_usd": 0.005,
			"total_supply": "1000000000000000000000000",
			"liquidity_usd": 2.5,
			"bonding_curve_migrated": false,
			"bonding_curve_current_amount": "100000000000000000000",
			"bonding_curve_goal_amount": "200000000000000000000",
			"bonding_curve_raised_amount": "10000000000000000000",
			"bonding_curve_current_amount_usd": 1.5,
			"bonding_curve_goal_amount_usd": 3.0,
			"updated_at": 1234567890.0
		}`

		err = ta.handlePriceUpdate(ctx, payload)
		require.NoError(t, err)

		score, err := ta.processedDataDB.ZScore(ctx, globalTopSetKey, tokenExternalAddr).Result()
		require.NoError(t, err)
		expectedMarketCap := 0.005 * 1000000.0
		require.InDelta(t, expectedMarketCap, score, 0.1)
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		ctx := t.Context()
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db).(*tokenAnalytics)

		payload := `{"invalid json`

		err := ta.handlePriceUpdate(ctx, payload)
		require.Error(t, err)
	})

	t.Run("returns error for invalid total_supply", func(t *testing.T) {
		ctx := t.Context()
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db).(*tokenAnalytics)

		payload := `{
			"external_address": "0:test:",
			"price_usd": 0.005,
			"total_supply": "invalid_number"
		}`

		err := ta.handlePriceUpdate(ctx, payload)
		require.Error(t, err)
	})
}

func helperUpdateTokenPrice(t testing.TB, ctx context.Context, db *storage.DB, externalAddress string, priceUSD float64) {
	t.Helper()

	_, err := storage.Exec(ctx, db, `
		UPDATE tokens
		SET price_usd = $1,
		    updated_at = NOW()
		WHERE external_address = $2
	`, priceUSD, externalAddress)
	require.NoError(t, err, "failed to update token price")
}

func helperUpdateTokenLiquidity(t testing.TB, ctx context.Context, db *storage.DB, externalAddress string, liquidityUSD float64) {
	t.Helper()

	_, err := storage.Exec(ctx, db, `
		UPDATE tokens
		SET liquidity_usd = $1
		WHERE external_address = $2
	`, liquidityUSD, externalAddress)
	require.NoError(t, err, "failed to update token liquidity")
}

func helperMigrateToken(t testing.TB, ctx context.Context, db *storage.DB, externalAddress string, liquidityUSD, priceUSD float64) {
	t.Helper()

	_, err := storage.Exec(ctx, db, `
		UPDATE tokens
		SET bonding_curve_migrated = true,
		    liquidity_usd = $1,
		    price_usd = $2,
		    updated_at = NOW()
		WHERE external_address = $3
	`, liquidityUSD, priceUSD, externalAddress)
	require.NoError(t, err, "failed to migrate token")
}

func helperUpdateTokenBondingCurveAndPrice(t testing.TB, ctx context.Context, db *storage.DB,
	externalAddress, currentAmount string, currentAmountUSD, priceUSD float64) {
	t.Helper()

	_, err := storage.Exec(ctx, db, `
		UPDATE tokens
		SET bonding_curve_current_amount = $1,
		    bonding_curve_current_amount_usd = $2,
		    price_usd = $3,
		    updated_at = NOW()
		WHERE external_address = $4
	`, currentAmount, currentAmountUSD, priceUSD, externalAddress)
	require.NoError(t, err, "failed to update token bonding curve and price")
}
