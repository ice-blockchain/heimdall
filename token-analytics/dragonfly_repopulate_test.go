// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestRepopulateBondingCurve(t *testing.T) {
	t.Parallel()
	t.Run("repopulates outdated bonding curve data in Redis", func(t *testing.T) {
		ctx := t.Context()

		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())

		tokenExternalAddr := "0:repopulate_test_1:"
		contractAddr := "0x1111111111111111111111111111111111111111"

		helperInsertTestToken(t, ctx, db,
			contractAddr, tokenExternalAddr, "REPOP1", "profile", "test_creator",
			"1000000000000000000000000", 0.001, 1000, 10, PlatformGroupIonConnect)

		helperUpdateTokenBondingCurve(t, ctx, db, tokenExternalAddr,
			"50000000000000000000", "100000000000000000000", 50.0, 100.0, "0", false)

		oldScore := 30e18 // 30 * 10^18 (outdated)
		err := ta.processedDataDB.ZAdd(ctx, globalBondingCurveProgressSetKey,
			redis.Z{Score: oldScore, Member: tokenExternalAddr}).Err()
		require.NoError(t, err)

		yesterday := time.Now().Add(-24 * time.Hour)
		err = ta.processedDataDB.Set(ctx, "token_analytics:last_bonding_sync", yesterday.Format(time.RFC3339), 0).Err()
		require.NoError(t, err)

		count, err := ta.repopulateBondingCurve(ctx)
		require.NoError(t, err)
		require.Equal(t, 1, count, "should repopulate 1 token")

		actualScore, err := ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressSetKey, tokenExternalAddr).Result()
		require.NoError(t, err)

		expectedScore := 50e18 // 50 * 10^18 Wei
		require.InDelta(t, expectedScore, actualScore, 1.0, "Redis should be updated to correct Wei amount")

		lastSync, err := ta.processedDataDB.Get(ctx, redisKeyLastBondingSync).Result()
		require.NoError(t, err)
		require.NotEmpty(t, lastSync, "last_bonding_sync should be set")
	})
}

func TestRepopulateBondingCurve_SkipsUpToDate(t *testing.T) {
	t.Parallel()
	t.Run("skips tokens that are already up to date in Redis", func(t *testing.T) {
		ctx := t.Context()

		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())

		tokenExternalAddr := "0:repopulate_test_2:"
		contractAddr := "0x2222222222222222222222222222222222222222"

		helperInsertTestToken(t, ctx, db, contractAddr, tokenExternalAddr, "REPOP2", "profile", "test_creator", "1000000000000000000000000", 0.001, 1000, 10, PlatformGroupIonConnect)
		helperUpdateTokenBondingCurve(t, ctx, db, tokenExternalAddr, "75000000000000000000", "100000000000000000000", 75.0, 100.0, "0", false)

		correctScore := 75e18 // 75 * 10^18
		err := ta.processedDataDB.ZAdd(ctx, globalBondingCurveProgressSetKey,
			redis.Z{Score: correctScore, Member: tokenExternalAddr}).Err()
		require.NoError(t, err)

		futureTime := time.Now().Add(1 * time.Hour)
		err = ta.processedDataDB.Set(ctx, "token_analytics:last_bonding_sync", futureTime.Format(time.RFC3339), 0).Err()
		require.NoError(t, err)

		count, err := ta.repopulateBondingCurve(ctx)
		require.NoError(t, err)
		require.Equal(t, 0, count, "should not repopulate any tokens (all up to date)")

		actualScore, err := ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressSetKey, tokenExternalAddr).Result()
		require.NoError(t, err)
		require.InDelta(t, correctScore, actualScore, 1.0)
	})
}

func TestRepopulateBondingCurveHandlesMigration(t *testing.T) {
	t.Parallel()
	t.Run("removes migrated tokens from Redis", func(t *testing.T) {
		ctx := t.Context()

		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())

		tokenExternalAddr := "0:repopulate_test_3:"
		contractAddr := "0x3333333333333333333333333333333333333333"

		helperInsertTestToken(t, ctx, db, contractAddr, tokenExternalAddr, "REPOP3", "profile", "test_creator", "1000000000000000000000000", 0.001, 1000, 10, PlatformGroupIonConnect)

		err := ta.processedDataDB.ZAdd(ctx, globalBondingCurveProgressSetKey, redis.Z{Score: 50.0, Member: tokenExternalAddr}).Err()
		require.NoError(t, err)

		err = ta.processedDataDB.ZAdd(ctx, globalBondingCurveProgressProfileSetKey, redis.Z{Score: 50.0, Member: tokenExternalAddr}).Err()
		require.NoError(t, err)

		helperUpdateTokenBondingCurve(t, ctx, db, tokenExternalAddr, "50000000000000000000", "100000000000000000000", 50.0, 100.0, "0", true)

		yesterday := time.Now().Add(-24 * time.Hour)
		err = ta.processedDataDB.Set(ctx, redisKeyLastBondingSync, yesterday.Format(time.RFC3339), 0).Err()
		require.NoError(t, err)

		count, err := ta.repopulateBondingCurve(ctx)
		require.NoError(t, err)
		require.Equal(t, 1, count, "should process 1 migrated token")

		_, err = ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressSetKey, tokenExternalAddr).Result()
		require.ErrorIs(t, err, redis.Nil, "token should be removed from global set")

		_, err = ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressProfileSetKey, tokenExternalAddr).Result()
		require.ErrorIs(t, err, redis.Nil, "token should be removed from profile set")
	})
}

func TestRepopulateUserBalances_Basic(t *testing.T) {
	t.Parallel()
	t.Run("repopulates outdated user balance data in Redis", func(t *testing.T) {
		ctx := t.Context()

		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())

		tokenExternalAddr := "0:balance_repop_test:"
		contractAddr := "0x4444444444444444444444444444444444444444"

		helperInsertTestToken(t, ctx, db, contractAddr, tokenExternalAddr, "BALTEST", "profile", "test_creator", "1000000000000000000000000", 0.001, 1000, 10, PlatformGroupIonConnect)

		correctAmount := "500000000000000000000" // 500 tokens
		masterPubkey := "test_user_balance_pubkey"
		userExternalAddr := "test_user_external"

		helperInsertUserTokenPosition(t, ctx, db, masterPubkey, contractAddr, tokenExternalAddr,
			userExternalAddr, correctAmount, 0, 0)

		userPositionKey := keyUserPositionOfToken(tokenExternalAddr)
		oldAmount := 300.0 // Outdated

		err := ta.processedDataDB.ZAdd(ctx, userPositionKey, redis.Z{Score: oldAmount, Member: userExternalAddr}).Err()
		require.NoError(t, err)

		yesterday := time.Now().Add(-24 * time.Hour)
		err = ta.processedDataDB.Set(ctx, redisKeyLastBalanceSync, yesterday.Format(time.RFC3339), 0).Err()
		require.NoError(t, err)

		count, err := ta.repopulateUserBalances(ctx)
		require.NoError(t, err)
		require.Equal(t, 1, count, "should repopulate 1 position")

		actualAmount, err := ta.processedDataDB.ZScore(ctx, userPositionKey, userExternalAddr).Result()
		require.NoError(t, err)
		require.InDelta(t, 500.0, actualAmount, 0.01, "Redis should be updated to correct amount")
	})
}

func TestRepopulateUserBalances_RemovesZero(t *testing.T) {
	t.Run("removes zero balance positions from Redis", func(t *testing.T) {
		ctx := t.Context()

		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())

		tokenExternalAddr := "0:zero_balance_test:"
		contractAddr := "0x6666666666666666666666666666666666666666"

		helperInsertTestToken(t, ctx, db,
			contractAddr, tokenExternalAddr, "ZEROTEST", "profile", "test_creator",
			"1000000000000000000000000", 0.001, 1000, 10, PlatformGroupIonConnect)

		masterPubkey := "test_user_zero_balance_pubkey"
		userExternalAddr := "test_user_external_zero"

		helperInsertUserTokenPosition(t, ctx, db, masterPubkey, contractAddr, tokenExternalAddr,
			userExternalAddr, "0", 0, 0)

		userPositionKey := keyUserPositionOfToken(tokenExternalAddr)

		err := ta.processedDataDB.ZAdd(ctx, userPositionKey, redis.Z{Score: 100.0, Member: userExternalAddr}).Err()
		require.NoError(t, err)

		yesterday := time.Now().Add(-24 * time.Hour)
		err = ta.processedDataDB.Set(ctx, redisKeyLastBalanceSync, yesterday.Format(time.RFC3339), 0).Err()
		require.NoError(t, err)

		count, err := ta.repopulateUserBalances(ctx)
		require.NoError(t, err)
		require.Equal(t, 1, count, "should process 1 position")

		_, err = ta.processedDataDB.ZScore(ctx, userPositionKey, userExternalAddr).Result()
		require.ErrorIs(t, err, redis.Nil, "zero balance should be removed from Redis")
	})
}

func TestRepopulateRedisFromPostgres_Full(t *testing.T) {
	t.Parallel()
	t.Run("repopulates both bonding curve and user balances", func(t *testing.T) {
		ctx := t.Context()

		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())

		tokenExternalAddr := "0:full_repop_test:"
		contractAddr := "0x8888888888888888888888888888888888888888"

		helperInsertTestToken(t, ctx, db,
			contractAddr, tokenExternalAddr, "FULLTEST", "profile", "test_creator",
			"1000000000000000000000000", 0.001, 1000, 10, PlatformGroupIonConnect)

		helperUpdateTokenBondingCurve(t, ctx, db, tokenExternalAddr, "60000000000000000000", "100000000000000000000", 60.0, 100.0, "0", false)

		masterPubkey := "test_user_full_pubkey"
		userExternalAddr := "test_user_full"

		helperInsertUserTokenPosition(t, ctx, db, masterPubkey, contractAddr, tokenExternalAddr, userExternalAddr, "250000000000000000000", 0, 0)

		err := ta.processedDataDB.FlushDB(ctx).Err()
		require.NoError(t, err)

		yesterday := time.Now().Add(-24 * time.Hour)
		err = ta.processedDataDB.Set(ctx, redisKeyLastBondingSync, yesterday.Format(time.RFC3339), 0).Err()
		require.NoError(t, err)
		err = ta.processedDataDB.Set(ctx, redisKeyLastBalanceSync, yesterday.Format(time.RFC3339), 0).Err()
		require.NoError(t, err)

		err = ta.RepopulateRedisFromPostgres(ctx)
		require.NoError(t, err)

		score, err := ta.processedDataDB.ZScore(ctx, globalBondingCurveProgressSetKey, tokenExternalAddr).Result()
		require.NoError(t, err)
		require.InDelta(t, 60e18, score, 1.0, "bonding curve score should be 60 * 10^18")

		userPositionKey := keyUserPositionOfToken(tokenExternalAddr)

		amount, err := ta.processedDataDB.ZScore(ctx, userPositionKey, userExternalAddr).Result()
		require.NoError(t, err)
		require.InDelta(t, 250.0, amount, 0.01)
	})
}
