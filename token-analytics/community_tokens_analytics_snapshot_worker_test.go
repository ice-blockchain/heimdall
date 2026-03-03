// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	questdb "github.com/ice-blockchain/heimdall/token-analytics/internal/questdb"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func TestAnalyticsSnapshotWorker_Interval24h(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()
	ta := helperNewForTest(t, db)

	targetHour := setupAnalyticsTestData(t, db, ta, "snap24h")
	stats := helperComputeAndVerifySnapshot(t, ctx, ta, targetHour, "24h", 1, 1)

	require.Equal(t, uint64(1), stats.Launched, "24h: only token_24h created within window")
	require.Equal(t, uint64(1), stats.Migrated, "24h: only token_24h migrated within window")
	require.Greater(t, stats.TotalVolume, float64(0), "24h: should have volume from token_24h swap")
}

func TestAnalyticsSnapshotWorker_Interval7d(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()
	ta := helperNewForTest(t, db)

	targetHour := setupAnalyticsTestData(t, db, ta, "snap7d")
	stats := helperComputeAndVerifySnapshot(t, ctx, ta, targetHour, "7d", 2, 2)

	require.Equal(t, uint64(2), stats.Launched, "7d: token_24h + token_7d created within window")
	require.Equal(t, uint64(2), stats.Migrated, "7d: token_24h + token_7d migrated within window")
	require.Greater(t, stats.TotalVolume, float64(0), "7d: should have volume from both swaps")
}

func TestAnalyticsSnapshotWorker_Interval30d(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()
	ta := helperNewForTest(t, db)

	targetHour := setupAnalyticsTestData(t, db, ta, "snap30d")
	stats := helperComputeAndVerifySnapshot(t, ctx, ta, targetHour, "30d", 3, 3)

	require.Equal(t, uint64(3), stats.Launched, "30d: 3 tokens created within window")
	require.Equal(t, uint64(3), stats.Migrated, "30d: 3 tokens migrated within window")
	require.Greater(t, stats.TotalVolume, float64(0), "30d: should have volume from 3 swaps")
}

func TestAnalyticsSnapshotWorker_Interval1y(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()
	ta := helperNewForTest(t, db)

	targetHour := setupAnalyticsTestData(t, db, ta, "snap1y")
	stats := helperComputeAndVerifySnapshot(t, ctx, ta, targetHour, "1y", 4, 4)

	require.Equal(t, uint64(4), stats.Launched, "1y: all 4 tokens created within window")
	require.Equal(t, uint64(4), stats.Migrated, "1y: all 4 tokens migrated within window")
	require.Greater(t, stats.TotalVolume, float64(0), "1y: should have volume from all 4 swaps")
}

func TestAnalyticsSnapshotWorker_MigratedCount(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()
	ta := helperNewForTest(t, db)

	targetHour := time.Date(2098, 1, 1, 10, 0, 0, 0, time.UTC)

	helperInsertTestUser(t, ctx, db, "mig_c1", "mig_one", "Mig One", "", true, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, db, "mig_c2", "mig_two", "Mig Two", "", false, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, db, "mig_c3", "mig_three", "Mig Three", "", true, PlatformGroupIonConnect)

	helperInsertTestToken(t, ctx, db, "0xMIG1111111111111111111111111111111111111", "0:mig_c1:", "MIG1", "profile", "mig_c1", "1000000000000000000000000", 100.0, 0.0001, 5, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, db, "0xMIG2222222222222222222222222222222222222", "0:mig_c2:", "MIG2", "profile", "mig_c2", "2000000000000000000000000", 200.0, 0.0002, 10, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, db, "0xMIG3333333333333333333333333333333333333", "0:mig_c3:", "MIG3", "profile", "mig_c3", "3000000000000000000000000", 300.0, 0.0003, 15, PlatformGroupIonConnect)

	migratedAt1 := targetHour.Add(-2 * time.Hour)
	_, err := storage.Exec(ctx, db,
		`UPDATE tokens SET bonding_curve_migrated = true, migrated_at = $1 WHERE external_address = $2`,
		migratedAt1, "0:mig_c1:")
	require.NoError(t, err)

	migratedAt2 := targetHour.Add(-5 * time.Hour)
	_, err = storage.Exec(ctx, db,
		`UPDATE tokens SET bonding_curve_migrated = true, migrated_at = $1 WHERE external_address = $2`,
		migratedAt2, "0:mig_c2:")
	require.NoError(t, err)

	// Token3: not migrated — no migrated_at set.
	err = ta.computeAndStoreAnalyticsSnapshot(ctx, targetHour, "7d")
	require.NoError(t, err)

	var stats *GlobalTokenStats
	require.Eventually(t, func() bool {
		stats, err = ta.GetGlobalTokenStatistics(ctx, "7d")
		return err == nil && stats.Migrated == 2
	}, 2*time.Second, 50*time.Millisecond, "should count exactly 2 migrated tokens in 7d window after QuestDB flush")

	require.Equal(t, uint64(2), stats.Migrated, "should count exactly 2 migrated tokens in 7d window")
}

func TestAnalyticsSnapshotWorker_VolumeAccuracy(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()
	ta := helperNewForTest(t, db)

	targetHour := time.Date(2099, 6, 15, 10, 0, 0, 0, time.UTC)

	helperInsertTestUser(t, ctx, db, "vol_c1", "vol_one", "Vol One", "", true, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, db, "0xVOL1111111111111111111111111111111111111", "0:vol_c1:", "VOL1", "profile", "vol_c1", "1000000000000000000000000", 100.0, 0.0001, 5, PlatformGroupIonConnect)

	swapTime := targetHour.Add(-1 * time.Hour)
	// Buy trade: amount=1e21, price=2.5 -> volume = 1e21/1e18*2.5 = 2500 USD
	helperWriteTradeToQuestDB(t, ctx, ta, "0:vol_c1:", "1000000000000000000000", "2.5", TradeTypeBuy, swapTime)
	// Sell trade: amount=5e20, price=3.0 -> volume = 5e20/1e18*3.0 = 1500 USD
	helperWriteTradeToQuestDB(t, ctx, ta, "0:vol_c1:", "500000000000000000000", "3.0", TradeTypeSell, swapTime.Add(time.Minute))

	helperWaitForQuestDBVolume(t, ctx, ta, swapTime.Truncate(time.Hour), 1)

	// Expected volume = 2500 + 1500 = 4000 USD
	expectedVolume := 1000.0*2.5 + 500.0*3.0

	err := ta.computeAndStoreAnalyticsSnapshot(ctx, targetHour, "1y")
	require.NoError(t, err)

	var stats *GlobalTokenStats
	require.Eventually(t, func() bool {
		stats, err = ta.GetGlobalTokenStatistics(ctx, "1y")
		if err != nil || stats == nil {
			return false
		}

		return stats.TotalVolume > 0 && stats.TotalVolume >= expectedVolume*0.999 && stats.TotalVolume <= expectedVolume*1.001
	}, 2*time.Second, 50*time.Millisecond, "volume should match buy+sell calculation after QuestDB flush")

	require.InDelta(t, expectedVolume, stats.TotalVolume, expectedVolume*0.001, "volume should match buy+sell calculation")
}

func TestAnalyticsSnapshotWorker_IdempotentProcessing(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()
	ta := helperNewForTest(t, db)

	targetHour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	require.NoError(t, ta.computeAndStoreAnalyticsSnapshot(ctx, targetHour, "24h"))

	processed, err := ta.isSnapshotProcessed(ctx, targetHour, "24h")
	require.NoError(t, err)
	require.True(t, processed)
	require.NoError(t, ta.tryComputeCurrentAnalyticsSnapshot(ctx))
}

func TestGetGlobalTokenStatistics_NoData(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()
	ta := helperNewForTest(t, db)

	stats, err := ta.GetGlobalTokenStatistics(ctx, "99d")
	require.NoError(t, err)
	require.NotNil(t, stats)
	require.Equal(t, uint64(0), stats.Launched)
	require.Equal(t, uint64(0), stats.Migrated)
	require.Equal(t, float64(0), stats.TotalVolume)
}

func TestGetGlobalTokenStatistics_ReturnsLatestSnapshot(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()
	ta := helperNewForTest(t, db)

	helperInsertTestUser(t, ctx, db, "latest_snap_c1", "ls_one", "LS One", "", true, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, db, "0xLS111111111111111111111111111111111111111", "0:latest_snap_c1:", "LS1", "profile", "latest_snap_c1", "1000000000000000000000000", 100.0, 0.0001, 5, PlatformGroupIonConnect)

	baseHour := time.Date(2010, 3, 20, 10, 0, 0, 0, time.UTC)
	olderHour := baseHour
	newerHour := baseHour.Add(2 * time.Hour)

	testInterval := "30d"

	_, err := storage.Exec(ctx, db, `UPDATE tokens SET created_at = $1 WHERE external_address = $2`,
		baseHour.Add(time.Hour), "0:latest_snap_c1:")
	require.NoError(t, err)

	err = ta.computeAndStoreAnalyticsSnapshot(ctx, olderHour, testInterval)
	require.NoError(t, err)

	helperInsertTestUser(t, ctx, db, "latest_snap_c2", "ls_two", "LS Two", "", false, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, db, "0xLS222222222222222222222222222222222222222", "0:latest_snap_c2:", "LS2", "profile", "latest_snap_c2", "2000000000000000000000000", 200.0, 0.0002, 10, PlatformGroupIonConnect)
	_, err = storage.Exec(ctx, db, `UPDATE tokens SET created_at = $1 WHERE external_address = $2`,
		baseHour.Add(2*time.Hour), "0:latest_snap_c2:")
	require.NoError(t, err)

	err = ta.computeAndStoreAnalyticsSnapshot(ctx, newerHour, testInterval)
	require.NoError(t, err)

	var result *GlobalTokenStats
	require.Eventually(t, func() bool {
		rows, qErr := questdb.Select[GlobalTokenStats](ctx, ta.questDB,
			`SELECT launched, migrated, total_volume
			 FROM token_analytics_snapshots
			 WHERE interval_type = $1 AND timestamp = $2`, testInterval, newerHour)
		if qErr != nil || len(rows) == 0 {
			return false
		}
		result = rows[0]

		return result.Launched >= 2
	}, 10*time.Second, 200*time.Millisecond, "newer snapshot should have launched >= 2")

	require.GreaterOrEqual(t, result.Launched, uint64(2), "newer snapshot should reflect data from both tokens")
}

func setupAnalyticsTestData(t *testing.T, db *storage.DB, ta *tokenAnalytics, prefix string) time.Time {
	t.Helper()
	ctx := t.Context()

	targetHour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)

	c1, c2, c3, c4 := prefix+"_c1", prefix+"_c2", prefix+"_c3", prefix+"_c4"
	ext1, ext2, ext3, ext4 := "0:"+c1+":", "0:"+c2+":", "0:"+c3+":", "0:"+c4+":"

	helperInsertTestUser(t, ctx, db, c1, prefix+"_one", prefix+" One", "", true, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, db, c2, prefix+"_two", prefix+" Two", "", false, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, db, c3, prefix+"_three", prefix+" Three", "", true, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, db, c4, prefix+"_four", prefix+" Four", "", false, PlatformGroupIonConnect)

	helperInsertTestToken(t, ctx, db, "0x"+prefix+"1111111111111111111111111111111111", ext1, prefix+"1", "profile", c1, "1000000000000000000000000", 100.0, 0.0001, 5, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, db, "0x"+prefix+"2222222222222222222222222222222222", ext2, prefix+"2", "profile", c2, "2000000000000000000000000", 200.0, 0.0002, 10, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, db, "0x"+prefix+"3333333333333333333333333333333333", ext3, prefix+"3", "profile", c3, "3000000000000000000000000", 300.0, 0.0003, 15, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, db, "0x"+prefix+"4444444444444444444444444444444444", ext4, prefix+"4", "profile", c4, "4000000000000000000000000", 400.0, 0.0004, 20, PlatformGroupIonConnect)

	createdAt24h := targetHour.Add(-2 * time.Hour)
	migratedAt24h := targetHour.Add(-3 * time.Hour)
	_, err := storage.Exec(ctx, db, `UPDATE tokens SET created_at = $1, bonding_curve_migrated = true, migrated_at = $2 WHERE external_address = $3`,
		createdAt24h, migratedAt24h, ext1)
	require.NoError(t, err)

	createdAt7d := targetHour.Add(-3 * 24 * time.Hour)
	migratedAt7d := targetHour.Add(-4 * 24 * time.Hour)
	_, err = storage.Exec(ctx, db, `UPDATE tokens SET created_at = $1, bonding_curve_migrated = true, migrated_at = $2 WHERE external_address = $3`,
		createdAt7d, migratedAt7d, ext2)
	require.NoError(t, err)

	createdAt30d := targetHour.Add(-15 * 24 * time.Hour)
	migratedAt30d := targetHour.Add(-16 * 24 * time.Hour)
	_, err = storage.Exec(ctx, db, `UPDATE tokens SET created_at = $1, bonding_curve_migrated = true, migrated_at = $2 WHERE external_address = $3`,
		createdAt30d, migratedAt30d, ext3)
	require.NoError(t, err)

	createdAt1y := targetHour.Add(-60 * 24 * time.Hour)
	migratedAt1y := targetHour.Add(-61 * 24 * time.Hour)
	_, err = storage.Exec(ctx, db, `UPDATE tokens SET created_at = $1, bonding_curve_migrated = true, migrated_at = $2 WHERE external_address = $3`,
		createdAt1y, migratedAt1y, ext4)
	require.NoError(t, err)

	helperWriteTradeToQuestDB(t, ctx, ta, ext1, "1000000000000000000000", "1.0", TradeTypeBuy, createdAt24h)
	helperWriteTradeToQuestDB(t, ctx, ta, ext2, "2000000000000000000000", "1.5", TradeTypeBuy, createdAt7d)
	helperWriteTradeToQuestDB(t, ctx, ta, ext3, "3000000000000000000000", "2.0", TradeTypeBuy, createdAt30d)
	helperWriteTradeToQuestDB(t, ctx, ta, ext4, "4000000000000000000000", "2.5", TradeTypeBuy, createdAt1y)

	snapAddresses := []string{ext1, ext2, ext3, ext4}
	require.Eventually(t, func() bool {
		rows, err := questdb.Select[struct {
			Cnt int64 `db:"cnt"`
		}](ctx, ta.questDB,
			`SELECT count() AS cnt FROM trades WHERE external_address IN ($1, $2, $3, $4)`,
			snapAddresses[0], snapAddresses[1], snapAddresses[2], snapAddresses[3])

		return err == nil && len(rows) > 0 && rows[0].Cnt >= 4
	}, 30*time.Second, 200*time.Millisecond, "all 4 "+prefix+" trades should be in QuestDB trades table")

	matCheck, _ := questdb.Select[struct {
		Cnt int64 `db:"cnt"`
	}](ctx, ta.questDB,
		`SELECT count() AS cnt FROM token_volume_1h WHERE external_address IN ($1, $2, $3, $4) AND volume_1h > 0`,
		snapAddresses[0], snapAddresses[1], snapAddresses[2], snapAddresses[3])
	if len(matCheck) == 0 || matCheck[0].Cnt < 4 {
		err = questdb.Exec(ctx, ta.questDB, "REFRESH MATERIALIZED VIEW token_volume_1h FULL")
		require.NoError(t, err)
	}

	require.Eventually(t, func() bool {
		rows, err := questdb.Select[struct {
			Cnt int64 `db:"cnt"`
		}](ctx, ta.questDB,
			`SELECT count() AS cnt FROM token_volume_1h WHERE external_address IN ($1, $2, $3, $4) AND volume_1h > 0`,
			snapAddresses[0], snapAddresses[1], snapAddresses[2], snapAddresses[3])

		return err == nil && len(rows) > 0 && rows[0].Cnt >= 4
	}, 30*time.Second, 300*time.Millisecond, "token_volume_1h should have 4 rows for "+prefix+" tokens")

	return targetHour
}

func helperGetSnapshotByTimestamp(ctx context.Context, ta *tokenAnalytics, targetHour time.Time, interval string) (*GlobalTokenStats, error) {
	rows, err := questdb.Select[GlobalTokenStats](ctx, ta.questDB,
		`SELECT launched, migrated, total_volume
		 FROM token_analytics_snapshots
		 WHERE interval_type = $1 AND timestamp = $2`, interval, targetHour)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return &GlobalTokenStats{}, nil
	}

	return rows[0], nil
}

func helperComputeAndVerifySnapshot(t *testing.T, ctx context.Context, ta *tokenAnalytics,
	targetHour time.Time, interval string, expectedLaunched, expectedMigrated uint64,
) *GlobalTokenStats {
	t.Helper()

	dur := intervalToDuration(interval)
	windowEnd := targetHour.Add(time.Hour)
	windowStart := windowEnd.Add(-dur)

	require.Eventually(t, func() bool {
		rows, err := questdb.Select[struct {
			Vol float64 `db:"vol"`
		}](ctx, ta.questDB, `SELECT COALESCE(sum(volume_1h), 0) AS vol FROM token_volume_1h WHERE timestamp >= $1 AND timestamp < $2`,
			windowStart, windowEnd)

		return err == nil && len(rows) > 0 && rows[0].Vol > 0
	}, 30*time.Second, 300*time.Millisecond, "%s: mat view should have volume > 0 in window [%v, %v)", interval, windowStart, windowEnd)

	err := ta.computeAndStoreAnalyticsSnapshot(ctx, targetHour, interval)
	require.NoError(t, err)

	processed, err := ta.isSnapshotProcessed(ctx, targetHour, interval)
	require.NoError(t, err)
	require.True(t, processed)

	var stats *GlobalTokenStats
	require.Eventually(t, func() bool {
		stats, err = helperGetSnapshotByTimestamp(ctx, ta, targetHour, interval)

		return err == nil && stats.Launched == expectedLaunched && stats.Migrated == expectedMigrated && stats.TotalVolume > 0
	}, 30*time.Second, 200*time.Millisecond, "%s: snapshot should have launched=%d, migrated=%d, vol>0", interval, expectedLaunched, expectedMigrated)

	return stats
}
