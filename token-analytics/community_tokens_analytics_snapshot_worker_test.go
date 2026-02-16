// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func setupAnalyticsTestData(t *testing.T, db *storage.DB) time.Time {
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

	helperCreateSwapAtTime(t, ctx, db, "0xSNAP1111111111111111111111111111111111", "0:snap_c1:", "0xSNAPBUY1", false,
		"100000000000000000000", "1000000000000000000000", 1.0, createdAt24h)
	// token_7d swap: 3 days ago, buy, output=2e21 * priceUSD=1.5 -> volume=3e21.
	helperCreateSwapAtTime(t, ctx, db, "0xSNAP2222222222222222222222222222222222", "0:snap_c2:", "0xSNAPBUY2", false,
		"200000000000000000000", "2000000000000000000000", 1.5, createdAt7d)
	// token_30d swap: 15 days ago, buy, output=3e21 * priceUSD=2.0 -> volume=6e21.
	helperCreateSwapAtTime(t, ctx, db, "0xSNAP3333333333333333333333333333333333", "0:snap_c3:", "0xSNAPBUY3", false,
		"300000000000000000000", "3000000000000000000000", 2.0, createdAt30d)
	// token_1y swap: 60 days ago, buy, output=4e21 * priceUSD=2.5 -> volume=1e22.
	helperCreateSwapAtTime(t, ctx, db, "0xSNAP4444444444444444444444444444444444", "0:snap_c4:", "0xSNAPBUY4", false,
		"400000000000000000000", "4000000000000000000000", 2.5, createdAt1y)

	return targetHour
}

func TestAnalyticsSnapshotWorker_Interval24h(t *testing.T) {
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()
	ta := helperNewForTest(t, db)

	targetHour := setupAnalyticsTestData(t, db)

	err := ta.computeAndStoreAnalyticsSnapshot(ctx, targetHour, "24h")
	require.NoError(t, err)

	processed, err := ta.isSnapshotProcessed(ctx, targetHour, "24h")
	require.NoError(t, err)
	require.True(t, processed)

	time.Sleep(500 * time.Millisecond)

	stats, err := ta.GetGlobalTokenStatistics(ctx, "24h")
	require.NoError(t, err)

	require.Equal(t, uint64(1), stats.Launched, "24h: only token_24h created within window")
	require.Equal(t, uint64(1), stats.Migrated, "24h: only token_24h migrated within window")
	require.Greater(t, stats.TotalVolume, float64(0), "24h: should have volume from token_24h swap")
}

func TestAnalyticsSnapshotWorker_Interval7d(t *testing.T) {
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()
	ta := helperNewForTest(t, db)

	targetHour := setupAnalyticsTestData(t, db)

	err := ta.computeAndStoreAnalyticsSnapshot(ctx, targetHour, "7d")
	require.NoError(t, err)

	processed, err := ta.isSnapshotProcessed(ctx, targetHour, "7d")
	require.NoError(t, err)
	require.True(t, processed)

	time.Sleep(500 * time.Millisecond)

	stats, err := ta.GetGlobalTokenStatistics(ctx, "7d")
	require.NoError(t, err)

	require.Equal(t, uint64(2), stats.Launched, "7d: token_24h + token_7d created within window")
	require.Equal(t, uint64(2), stats.Migrated, "7d: token_24h + token_7d migrated within window")
	require.Greater(t, stats.TotalVolume, float64(0), "7d: should have volume from both swaps")
}

func TestAnalyticsSnapshotWorker_Interval30d(t *testing.T) {
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()
	ta := helperNewForTest(t, db)

	targetHour := setupAnalyticsTestData(t, db)

	err := ta.computeAndStoreAnalyticsSnapshot(ctx, targetHour, "30d")
	require.NoError(t, err)

	processed, err := ta.isSnapshotProcessed(ctx, targetHour, "30d")
	require.NoError(t, err)
	require.True(t, processed)

	time.Sleep(500 * time.Millisecond)

	stats, err := ta.GetGlobalTokenStatistics(ctx, "30d")
	require.NoError(t, err)

	require.Equal(t, uint64(3), stats.Launched, "30d: 3 tokens created within window")
	require.Equal(t, uint64(3), stats.Migrated, "30d: 3 tokens migrated within window")
	require.Greater(t, stats.TotalVolume, float64(0), "30d: should have volume from 3 swaps")
}

func TestAnalyticsSnapshotWorker_Interval1y(t *testing.T) {
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()
	ta := helperNewForTest(t, db)

	targetHour := setupAnalyticsTestData(t, db)

	err := ta.computeAndStoreAnalyticsSnapshot(ctx, targetHour, "1y")
	require.NoError(t, err)

	processed, err := ta.isSnapshotProcessed(ctx, targetHour, "1y")
	require.NoError(t, err)
	require.True(t, processed)

	time.Sleep(500 * time.Millisecond)

	stats, err := ta.GetGlobalTokenStatistics(ctx, "1y")
	require.NoError(t, err)

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

	time.Sleep(500 * time.Millisecond)

	stats, err := ta.GetGlobalTokenStatistics(ctx, "24h")
	require.NoError(t, err)
	require.Equal(t, uint64(2), stats.Migrated, "should count exactly 2 migrated tokens in 24h window")
}

func TestAnalyticsSnapshotWorker_VolumeAccuracy(t *testing.T) {
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()
	ta := helperNewForTest(t, db)

	targetHour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)

	helperInsertTestUser(t, ctx, db, "vol_c1", "vol_one", "Vol One", "", true, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, db, "0xVOL1111111111111111111111111111111111111", "0:vol_c1:", "VOL1", "profile", "vol_c1", "1000000000000000000000000", 100.0, 0.0001, 5, PlatformGroupIonConnect)

	swapTime := targetHour.Add(-1 * time.Hour)
	// Buy: direction=false -> volume = output_amount * price_usd = 1000000000000000000000 * 2.5
	helperCreateSwapAtTime(t, ctx, db, "0xVOL1111111111111111111111111111111111111", "0:vol_c1:", "0xVOLBUY1", false,
		"100000000000000000000", "1000000000000000000000", 2.5, swapTime)
	// Sell: direction=true -> volume = input_amount * price_usd = 500000000000000000000 * 3.0
	helperCreateSwapAtTime(t, ctx, db, "0xVOL1111111111111111111111111111111111111", "0:vol_c1:", "0xVOLSELL1", true,
		"500000000000000000000", "5000000000000000000000", 3.0, swapTime.Add(time.Minute))

	err := ta.computeAndStoreAnalyticsSnapshot(ctx, targetHour, "24h")
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)

	stats, err := ta.GetGlobalTokenStatistics(ctx, "24h")
	require.NoError(t, err)

	// Expected volume = (1e21 * 2.5) + (5e20 * 3.0) = 2.5e21 + 1.5e21 = 4e21
	expectedVolume := 1000000000000000000000.0*2.5 + 500000000000000000000.0*3.0
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

	now := time.Now().UTC().Truncate(time.Hour)

	olderHour := now.Add(-3 * time.Hour)
	newerHour := now.Add(-1 * time.Hour)

	_, err := storage.Exec(ctx, db, `UPDATE tokens SET created_at = $1 WHERE external_address = $2`,
		now.Add(-2*time.Hour), "0:latest_snap_c1:")
	require.NoError(t, err)

	err = ta.computeAndStoreAnalyticsSnapshot(ctx, olderHour, "24h")
	require.NoError(t, err)

	helperInsertTestUser(t, ctx, db, "latest_snap_c2", "ls_two", "LS Two", "", false, PlatformGroupIonConnect)
	helperInsertTestToken(t, ctx, db, "0xLS222222222222222222222222222222222222222", "0:latest_snap_c2:", "LS2", "profile", "latest_snap_c2", "2000000000000000000000000", 200.0, 0.0002, 10, PlatformGroupIonConnect)
	_, err = storage.Exec(ctx, db, `UPDATE tokens SET created_at = $1 WHERE external_address = $2`,
		now.Add(-1*time.Hour), "0:latest_snap_c2:")
	require.NoError(t, err)

	err = ta.computeAndStoreAnalyticsSnapshot(ctx, newerHour, "24h")
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)

	stats, err := ta.GetGlobalTokenStatistics(ctx, "24h")
	require.NoError(t, err)

	require.GreaterOrEqual(t, stats.Launched, uint64(2), "latest snapshot should reflect the newest data")
}
