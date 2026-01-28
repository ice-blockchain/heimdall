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

func TestBondingCurveNotifier(t *testing.T) {
	t.Run("handles bonding curve update via handleBondingCurveUpdate", func(t *testing.T) {
		ctx := t.Context()

		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db)

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
			"type": "profile",
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
			"updated_at": 1234567890
		}`, tokenExternalAddr, contractAddr, newPriceUSD, newCurrentAmount, newCurrentAmountUSD)

		err = ta.handleBondingCurveUpdate(ctx, payload)
		require.NoError(t, err)

		bcScore, err := ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressSetKey, tokenExternalAddr).Result()
		require.NoError(t, err)
		require.InDelta(t, 150000000000000000000.0, bcScore, 1e15, "Redis bonding curve progress should store wei amount")

		bcProfileScore, err := ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressProfileSetKey, tokenExternalAddr).Result()
		require.NoError(t, err)
		require.InDelta(t, 150000000000000000000.0, bcProfileScore, 1e15, "Redis profile bonding curve progress should store wei amount")
	})

	t.Run("handles token migration", func(t *testing.T) {
		ctx := t.Context()

		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db)

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
			"updated_at": 1234567890
		}`, tokenExternalAddr, contractAddr)

		err = ta.handleBondingCurveUpdate(ctx, payload)
		require.NoError(t, err)

		_, err = ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressSetKey, tokenExternalAddr).Result()
		require.Equal(t, redis.Nil, err, "Token should be removed from bonding curve set after migration")
	})

	t.Run("adds new tokens to redis automatically", func(t *testing.T) {
		ctx := t.Context()

		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db)

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
			"updated_at": 1234567890
		}`, tokenExternalAddr, contractAddr, newPrice)

		err := ta.handleBondingCurveUpdate(ctx, payload)
		require.NoError(t, err)
	})

	t.Run("parses notification payload correctly", func(t *testing.T) {
		ctx := t.Context()
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db)

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
			"updated_at": 1234567890
		}`

		err = ta.handleBondingCurveUpdate(ctx, payload)
		require.NoError(t, err)
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		ctx := t.Context()
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db)

		payload := `{"invalid json`

		err := ta.handleBondingCurveUpdate(ctx, payload)
		require.Error(t, err)
	})

	t.Run("returns error for invalid bonding curve amount", func(t *testing.T) {
		ctx := t.Context()
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db)

		payload := `{
			"external_address": "0:test:",
			"type": "profile",
			"bonding_curve_migrated": false,
			"bonding_curve_current_amount": "invalid_number",
			"bonding_curve_goal_amount": "200000000000000000000",
			"bonding_curve_raised_amount": "10000000000000000000",
			"bonding_curve_current_amount_usd": 1.5,
			"bonding_curve_goal_amount_usd": 3.0,
			"liquidity_usd": 0.5,
			"updated_at": 1234567890
		}`

		err := ta.handleBondingCurveUpdate(ctx, payload)
		require.NoError(t, err, "Should not error on invalid bonding curve amount parse - it just skips the update")
	})

	t.Run("updates bonding curve for post type and anyPost set", func(t *testing.T) {
		ctx := t.Context()
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db)

		tokenExternalAddr := "0:post_bc_test:"
		contractAddr := "0x4444555566667777888899990000111122223333"

		helperInsertTestToken(t, ctx, db,
			contractAddr, tokenExternalAddr, "POSTBC", "post", "test_master",
			"1000000000000000000000000", 0.001, 100, 5, PlatformGroupIonConnect)

		payload := fmt.Sprintf(`{
			"external_address": "%s",
			"type": "post",
			"bonding_curve_migrated": false,
			"bonding_curve_current_amount": "75000000000000000000",
			"bonding_curve_goal_amount": "200000000000000000000",
			"bonding_curve_raised_amount": "10000000000000000000",
			"bonding_curve_current_amount_usd": 1.0,
			"bonding_curve_goal_amount_usd": 2.0,
			"liquidity_usd": 0.5,
			"updated_at": 1234567890
		}`, tokenExternalAddr)

		err := ta.handleBondingCurveUpdate(ctx, payload)
		require.NoError(t, err)

		bcScore, err := ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressSetKey, tokenExternalAddr).Result()
		require.NoError(t, err)
		require.InDelta(t, 75000000000000000000.0, bcScore, 1e15, "Global bonding curve progress should store wei amount")

		bcPostScore, err := ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressPostSetKey, tokenExternalAddr).Result()
		require.NoError(t, err)
		require.InDelta(t, 75000000000000000000.0, bcPostScore, 1e15, "Post bonding curve progress should store wei amount")

		bcAnyPostScore, err := ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressAnyPostSetKey, tokenExternalAddr).Result()
		require.NoError(t, err)
		require.InDelta(t, 75000000000000000000.0, bcAnyPostScore, 1e15, "AnyPost bonding curve progress should store wei amount")
	})

	t.Run("updates bonding curve for video type and anyPost set", func(t *testing.T) {
		ctx := t.Context()
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db)

		tokenExternalAddr := "0:video_bc_test:"
		contractAddr := "0x5555666677778888999900001111222233334444"

		helperInsertTestToken(t, ctx, db,
			contractAddr, tokenExternalAddr, "VIDEOBC", "video", "test_master",
			"1000000000000000000000000", 0.001, 100, 5, PlatformGroupIonConnect)

		payload := fmt.Sprintf(`{
			"external_address": "%s",
			"type": "video",
			"bonding_curve_migrated": false,
			"bonding_curve_current_amount": "85000000000000000000",
			"bonding_curve_goal_amount": "200000000000000000000",
			"bonding_curve_raised_amount": "10000000000000000000",
			"bonding_curve_current_amount_usd": 1.0,
			"bonding_curve_goal_amount_usd": 2.0,
			"liquidity_usd": 0.5,
			"updated_at": 1234567890
		}`, tokenExternalAddr)

		err := ta.handleBondingCurveUpdate(ctx, payload)
		require.NoError(t, err)

		bcVideoScore, err := ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressVideoSetKey, tokenExternalAddr).Result()
		require.NoError(t, err)
		require.InDelta(t, 85000000000000000000.0, bcVideoScore, 1e15, "Video bonding curve progress should store wei amount")

		bcAnyPostScore, err := ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressAnyPostSetKey, tokenExternalAddr).Result()
		require.NoError(t, err)
		require.InDelta(t, 85000000000000000000.0, bcAnyPostScore, 1e15, "AnyPost bonding curve progress should store wei amount for video")
	})

	t.Run("updates bonding curve for article type and anyPost set", func(t *testing.T) {
		ctx := t.Context()
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db)

		tokenExternalAddr := "0:article_bc_test:"
		contractAddr := "0x6666777788889999000011112222333344445555"

		helperInsertTestToken(t, ctx, db,
			contractAddr, tokenExternalAddr, "ARTICLEBC", "article", "test_master",
			"1000000000000000000000000", 0.001, 100, 5, PlatformGroupIonConnect)

		payload := fmt.Sprintf(`{
			"external_address": "%s",
			"type": "article",
			"bonding_curve_migrated": false,
			"bonding_curve_current_amount": "95000000000000000000",
			"bonding_curve_goal_amount": "200000000000000000000",
			"bonding_curve_raised_amount": "10000000000000000000",
			"bonding_curve_current_amount_usd": 1.0,
			"bonding_curve_goal_amount_usd": 2.0,
			"liquidity_usd": 0.5,
			"updated_at": 1234567890
		}`, tokenExternalAddr)

		err := ta.handleBondingCurveUpdate(ctx, payload)
		require.NoError(t, err)

		bcArticleScore, err := ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressArticleSetKey, tokenExternalAddr).Result()
		require.NoError(t, err)
		require.InDelta(t, 95000000000000000000.0, bcArticleScore, 1e15, "Article bonding curve progress should store wei amount")

		bcAnyPostScore, err := ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressAnyPostSetKey, tokenExternalAddr).Result()
		require.NoError(t, err)
		require.InDelta(t, 95000000000000000000.0, bcAnyPostScore, 1e15, "AnyPost bonding curve progress should store wei amount for article")
	})

	t.Run("profile type does NOT update anyPost set", func(t *testing.T) {
		ctx := t.Context()
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db)

		tokenExternalAddr := "0:profile_not_anypost:"
		contractAddr := "0x7777888899990000111122223333444455556666"

		helperInsertTestToken(t, ctx, db,
			contractAddr, tokenExternalAddr, "PROFNOAP", "profile", "test_master",
			"1000000000000000000000000", 0.001, 100, 5, PlatformGroupIonConnect)

		payload := fmt.Sprintf(`{
			"external_address": "%s",
			"type": "profile",
			"bonding_curve_migrated": false,
			"bonding_curve_current_amount": "65000000000000000000",
			"bonding_curve_goal_amount": "200000000000000000000",
			"bonding_curve_raised_amount": "10000000000000000000",
			"bonding_curve_current_amount_usd": 1.0,
			"bonding_curve_goal_amount_usd": 2.0,
			"liquidity_usd": 0.5,
			"updated_at": 1234567890
		}`, tokenExternalAddr)

		err := ta.handleBondingCurveUpdate(ctx, payload)
		require.NoError(t, err)

		bcProfileScore, err := ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressProfileSetKey, tokenExternalAddr).Result()
		require.NoError(t, err)
		require.InDelta(t, 65000000000000000000.0, bcProfileScore, 1e15, "Profile bonding curve progress should store wei amount")

		_, err = ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressAnyPostSetKey, tokenExternalAddr).Result()
		require.Equal(t, redis.Nil, err, "Profile tokens should NOT be in anyPost bonding curve set")
	})

	t.Run("removes token from anyPost set on migration if post/video/article", func(t *testing.T) {
		ctx := t.Context()
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db)

		tokenExternalAddr := "0:post_migration_test:"
		contractAddr := "0x8888999900001111222233334444555566667777"

		helperInsertTestToken(t, ctx, db,
			contractAddr, tokenExternalAddr, "POSTMIG", "post", "test_master",
			"1000000000000000000000000", 0.001, 100, 5, PlatformGroupIonConnect)

		err := ta.processedDataDB.ZAdd(ctx, globalBondingCurveProgressSetKey, redis.Z{
			Score:  100000000000000000000.0,
			Member: tokenExternalAddr,
		}).Err()
		require.NoError(t, err)

		err = ta.processedDataDB.ZAdd(ctx, globalBondingCurveProgressPostSetKey, redis.Z{
			Score:  100000000000000000000.0,
			Member: tokenExternalAddr,
		}).Err()
		require.NoError(t, err)

		err = ta.processedDataDB.ZAdd(ctx, globalBondingCurveProgressAnyPostSetKey, redis.Z{
			Score:  100000000000000000000.0,
			Member: tokenExternalAddr,
		}).Err()
		require.NoError(t, err)

		payload := fmt.Sprintf(`{
			"external_address": "%s",
			"type": "post",
			"bonding_curve_migrated": true,
			"bonding_curve_current_amount": "200000000000000000000",
			"bonding_curve_goal_amount": "200000000000000000000",
			"bonding_curve_raised_amount": "0",
			"bonding_curve_current_amount_usd": 0,
			"bonding_curve_goal_amount_usd": 0,
			"liquidity_usd": 100.0,
			"updated_at": 1234567890
		}`, tokenExternalAddr)

		err = ta.handleBondingCurveUpdate(ctx, payload)
		require.NoError(t, err)

		_, err = ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressSetKey, tokenExternalAddr).Result()
		require.Equal(t, redis.Nil, err, "Token should be removed from global bonding curve set")

		_, err = ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressPostSetKey, tokenExternalAddr).Result()
		require.Equal(t, redis.Nil, err, "Token should be removed from post bonding curve set")

		_, err = ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressAnyPostSetKey, tokenExternalAddr).Result()
		require.Equal(t, redis.Nil, err, "Token should be removed from anyPost bonding curve set on migration")
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
