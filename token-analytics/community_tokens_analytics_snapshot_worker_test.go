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
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()
	ta := helperNewForTest(t, db)

	targetHour := setupAnalyticsTestData(t, db, ta)
	stats := helperComputeAndVerifySnapshot(t, ctx, ta, targetHour, "24h", 1, 1)

	require.Equal(t, uint64(1), stats.Launched, "24h: only token_24h created within window")
	require.Equal(t, uint64(1), stats.Migrated, "24h: only token_24h migrated within window")
	require.Greater(t, stats.TotalVolume, float64(0), "24h: should have volume from token_24h swap")
}

func TestAnalyticsSnapshotWorker_Interval7d(t *testing.T) {
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()
	ta := helperNewForTest(t, db)

	targetHour := setupAnalyticsTestData(t, db, ta)
	stats := helperComputeAndVerifySnapshot(t, ctx, ta, targetHour, "7d", 2, 2)

	require.Equal(t, uint64(2), stats.Launched, "7d: token_24h + token_7d created within window")
	require.Equal(t, uint64(2), stats.Migrated, "7d: token_24h + token_7d migrated within window")
	require.Greater(t, stats.TotalVolume, float64(0), "7d: should have volume from both swaps")
}

func TestAnalyticsSnapshotWorker_Interval30d(t *testing.T) {
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()
	ta := helperNewForTest(t, db)

	targetHour := setupAnalyticsTestData(t, db, ta)
	stats := helperComputeAndVerifySnapshot(t, ctx, ta, targetHour, "30d", 3, 3)

	require.Equal(t, uint64(3), stats.Launched, "30d: 3 tokens created within window")
	require.Equal(t, uint64(3), stats.Migrated, "30d: 3 tokens migrated within window")
	require.Greater(t, stats.TotalVolume, float64(0), "30d: should have volume from 3 swaps")
}

func TestAnalyticsSnapshotWorker_Interval1y(t *testing.T) {
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()
	ta := helperNewForTest(t, db)

	targetHour := setupAnalyticsTestData(t, db, ta)
	stats := helperComputeAndVerifySnapshot(t, ctx, ta, targetHour, "1y", 4, 4)

	require.Equal(t, uint64(4), stats.Launched, "1y: all 4 tokens created within window")
	require.Equal(t, uint64(4), stats.Migrated, "1y: all 4 tokens migrated within window")
	require.Greater(t, stats.TotalVolume, float64(0), "1y: should have volume from all 4 swaps")
}

func TestAnalyticsSnapshotWorker_MigratedCount(t *testing.T) {
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()
	ta := helperNewForTest(t, db)

	now := time.Now().UTC()
	targetHour := now.Truncate(time.Hour).Add(-time.Hour)

	// Insert 3 tokens: 2 migrated within 24h, 1 not migrated.
	helperInsertTestUser(t, ctx, db, "mig_c1", "mig_one", "Mig One", "", true, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, db, "mig_c2", "mig_two", "Mig Two", "", false, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, db, "mig_c3", "mig_three", "Mig Three", "", true, PlatformGroupIonConnect)

	helperInsertTestToken(t, ctx, db, "0xMIG1111111111111111111111111111111111111", "0:mig_c1:", "MIG1", "profile", "mig_c1", "1000000000000000000000000", 100.0, 0.0001, 5, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, db, "0xMIG2222222222222222222222222222222222222", "0:mig_c2:", "MIG2", "profile", "mig_c2", "2000000000000000000000000", 200.0, 0.0002, 10, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, db, "0xMIG3333333333333333333333333333333333333", "0:mig_c3:", "MIG3", "profile", "mig_c3", "3000000000000000000000000", 300.0, 0.0003, 15, PlatformGroupIonConnect)

	// Token1: migrated 2h ago
	migratedAt1 := now.Add(-2 * time.Hour)
	_, err := storage.Exec(ctx, db,
		`UPDATE tokens SET bonding_curve_migrated = true, migrated_at = $1 WHERE external_address = $2`,
		migratedAt1, "0:mig_c1:")
	require.NoError(t, err)

	// Token2: migrated 5h ago
	migratedAt2 := now.Add(-5 * time.Hour)
	_, err = storage.Exec(ctx, db,
		`UPDATE tokens SET bonding_curve_migrated = true, migrated_at = $1 WHERE external_address = $2`,
		migratedAt2, "0:mig_c2:")
	require.NoError(t, err)

	// Token3: not migrated — no migrated_at set.
	err = ta.computeAndStoreAnalyticsSnapshot(ctx, targetHour, "24h")
	require.NoError(t, err)

	var stats *GlobalTokenStats
	require.Eventually(t, func() bool {
		stats, err = ta.GetGlobalTokenStatistics(ctx, "24h")
		return err == nil && stats.Migrated == 2
	}, 2*time.Second, 50*time.Millisecond, "should count exactly 2 migrated tokens in 24h window after QuestDB flush")

	require.Equal(t, uint64(2), stats.Migrated, "should count exactly 2 migrated tokens in 24h window")
}

func TestAnalyticsSnapshotWorker_VolumeAccuracy(t *testing.T) {
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

	err := ta.computeAndStoreAnalyticsSnapshot(ctx, targetHour, "24h")
	require.NoError(t, err)

	var stats *GlobalTokenStats
	require.Eventually(t, func() bool {
		stats, err = ta.GetGlobalTokenStatistics(ctx, "24h")
		if err != nil || stats == nil {
			return false
		}

		return stats.TotalVolume > 0 && stats.TotalVolume >= expectedVolume*0.999 && stats.TotalVolume <= expectedVolume*1.001
	}, 2*time.Second, 50*time.Millisecond, "volume should match buy+sell calculation after QuestDB flush")

	require.InDelta(t, expectedVolume, stats.TotalVolume, expectedVolume*0.001, "volume should match buy+sell calculation")
}

func TestAnalyticsSnapshotWorker_IdempotentProcessing(t *testing.T) {
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

func setupAnalyticsTestData(t *testing.T, db *storage.DB, ta *tokenAnalytics) time.Time {
	t.Helper()
	ctx := t.Context()

	targetHour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)

	helperInsertTestUser(t, ctx, db, "snap_c1", "snap_one", "Snap One", "", true, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, db, "snap_c2", "snap_two", "Snap Two", "", false, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, db, "snap_c3", "snap_three", "Snap Three", "", true, PlatformGroupIonConnect)
	helperInsertTestUser(t, ctx, db, "snap_c4", "snap_four", "Snap Four", "", false, PlatformGroupIonConnect)

	helperInsertTestToken(t, ctx, db, "0xSNAP1111111111111111111111111111111111", "0:snap_c1:", "SN1", "profile", "snap_c1", "1000000000000000000000000", 100.0, 0.0001, 5, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, db, "0xSNAP2222222222222222222222222222222222", "0:snap_c2:", "SN2", "profile", "snap_c2", "2000000000000000000000000", 200.0, 0.0002, 10, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, db, "0xSNAP3333333333333333333333333333333333", "0:snap_c3:", "SN3", "profile", "snap_c3", "3000000000000000000000000", 300.0, 0.0003, 15, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, db, "0xSNAP4444444444444444444444444444444444", "0:snap_c4:", "SN4", "profile", "snap_c4", "4000000000000000000000000", 400.0, 0.0004, 20, PlatformGroupIonConnect)

	// token_24h: created and migrated within 24h.
	createdAt24h := targetHour.Add(-2 * time.Hour)
	migratedAt24h := targetHour.Add(-3 * time.Hour)
	_, err := storage.Exec(ctx, db, `UPDATE tokens SET created_at = $1, bonding_curve_migrated = true, migrated_at = $2 WHERE external_address = $3`,
		createdAt24h, migratedAt24h, "0:snap_c1:")
	require.NoError(t, err)

	// token_7d: created 3 days ago, migrated 4 days ago.
	createdAt7d := targetHour.Add(-3 * 24 * time.Hour)
	migratedAt7d := targetHour.Add(-4 * 24 * time.Hour)
	_, err = storage.Exec(ctx, db, `UPDATE tokens SET created_at = $1, bonding_curve_migrated = true, migrated_at = $2 WHERE external_address = $3`,
		createdAt7d, migratedAt7d, "0:snap_c2:")
	require.NoError(t, err)

	// token_30d: created 15 days ago, migrated 16 days ago.
	createdAt30d := targetHour.Add(-15 * 24 * time.Hour)
	migratedAt30d := targetHour.Add(-16 * 24 * time.Hour)
	_, err = storage.Exec(ctx, db, `UPDATE tokens SET created_at = $1, bonding_curve_migrated = true, migrated_at = $2 WHERE external_address = $3`,
		createdAt30d, migratedAt30d, "0:snap_c3:")
	require.NoError(t, err)

	// token_1y: created 60 days ago, migrated 61 days ago.
	createdAt1y := targetHour.Add(-60 * 24 * time.Hour)
	migratedAt1y := targetHour.Add(-61 * 24 * time.Hour)
	_, err = storage.Exec(ctx, db, `UPDATE tokens SET created_at = $1, bonding_curve_migrated = true, migrated_at = $2 WHERE external_address = $3`,
		createdAt1y, migratedAt1y, "0:snap_c4:")
	require.NoError(t, err)

	// volume_1h = amount / 1e18 * price_in_usd
	// token_24h: 1e21/1e18 * 1.0 = 1000 USD
	helperWriteTradeToQuestDB(t, ctx, ta, "0:snap_c1:", "1000000000000000000000", "1.0", TradeTypeBuy, createdAt24h)
	// token_7d: 2e21/1e18 * 1.5 = 3000 USD
	helperWriteTradeToQuestDB(t, ctx, ta, "0:snap_c2:", "2000000000000000000000", "1.5", TradeTypeBuy, createdAt7d)
	// token_30d: 3e21/1e18 * 2.0 = 6000 USD
	helperWriteTradeToQuestDB(t, ctx, ta, "0:snap_c3:", "3000000000000000000000", "2.0", TradeTypeBuy, createdAt30d)
	// token_1y: 4e21/1e18 * 2.5 = 10000 USD
	helperWriteTradeToQuestDB(t, ctx, ta, "0:snap_c4:", "4000000000000000000000", "2.5", TradeTypeBuy, createdAt1y)

	snapAddresses := []string{"0:snap_c1:", "0:snap_c2:", "0:snap_c3:", "0:snap_c4:"}
	require.Eventually(t, func() bool {
		rows, err := questdb.Select[struct {
			Cnt int64 `db:"cnt"`
		}](ctx, ta.questDB,
			`SELECT count() AS cnt FROM trades WHERE external_address IN ($1, $2, $3, $4)`,
			snapAddresses[0], snapAddresses[1], snapAddresses[2], snapAddresses[3])

		return err == nil && len(rows) > 0 && rows[0].Cnt >= 4
	}, 30*time.Second, 200*time.Millisecond, "all 4 snap trades should be in QuestDB trades table")

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
	}, 30*time.Second, 300*time.Millisecond, "token_volume_1h should have 4 rows for snap tokens")

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
