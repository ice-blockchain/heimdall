// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/ice-blockchain/heimdall/token-analytics/internal/questdb"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

var validAnalyticsIntervals = []string{"24h", "7d", "30d", "1y"}

func (t *tokenAnalytics) runAnalyticsSnapshotWorker(ctx context.Context) {
	log.Info("Analytics snapshot worker started")

	t.backfillAnalyticsSnapshots(ctx)

	ticker := time.NewTicker(analyticsSnapshotCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("Analytics snapshot worker stopped")
			return
		case <-ticker.C:
			if err := t.tryComputeCurrentAnalyticsSnapshot(ctx); err != nil {
				log.Error(fmt.Errorf("analytics snapshot worker tick failed: %w", err))
			}
		}
	}
}

func (t *tokenAnalytics) tryComputeCurrentAnalyticsSnapshot(ctx context.Context) error {
	targetHour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)

	unprocessed, err := t.unprocessedSnapshotIntervals(ctx, targetHour, validAnalyticsIntervals)
	if err != nil {
		return fmt.Errorf("failed to check processed snapshots for %v: %w", targetHour, err)
	}
	if len(unprocessed) == 0 {
		log.Debug(fmt.Sprintf("All intervals for hour %v already processed, skipping", targetHour))

		return nil
	}
	log.Debug(fmt.Sprintf("Computing %d unprocessed intervals for %v: %v", len(unprocessed), targetHour, unprocessed))
	for _, interval := range unprocessed {
		if err := t.computeAndStoreAnalyticsSnapshot(ctx, targetHour, interval); err != nil {
			log.Error(fmt.Errorf("failed to compute snapshot %v/%s: %w", targetHour, interval, err))
		}
	}
	return nil
}

func (t *tokenAnalytics) backfillAnalyticsSnapshots(ctx context.Context) {
	now := time.Now().UTC().Truncate(time.Hour)
	hoursToBackfill := t.snapshotBackfillDepth(ctx, now)
	if hoursToBackfill == 0 {
		log.Info("Analytics snapshot backfill: nothing to backfill")

		return
	}
	log.Info(fmt.Sprintf("Backfilling analytics snapshots for last %d hours", hoursToBackfill))
	filled := 0

	for h := 1; h <= hoursToBackfill; h++ {
		if ctx.Err() != nil {
			return
		}
		targetHour := now.Add(-time.Duration(h) * time.Hour)

		unprocessed, err := t.unprocessedSnapshotIntervals(ctx, targetHour, validAnalyticsIntervals)
		if err != nil {
			log.Error(fmt.Errorf("backfill: failed to check processed snapshots for %v: %w", targetHour, err))
			continue
		}
		for _, interval := range unprocessed {
			if err := t.computeAndStoreAnalyticsSnapshot(ctx, targetHour, interval); err != nil {
				log.Error(fmt.Errorf("backfill: failed to compute snapshot %v/%s: %w", targetHour, interval, err))
				continue
			}
			filled++
		}
	}

	log.Info(fmt.Sprintf("Analytics snapshot backfill complete: %d/%d snapshots filled (across %d hours)", filled, hoursToBackfill*len(validAnalyticsIntervals), hoursToBackfill))
}

func (t *tokenAnalytics) snapshotBackfillDepth(ctx context.Context, now time.Time) int {
	results, err := questdb.Select[struct {
		Latest time.Time `db:"latest"`
	}](ctx, t.questDB, `SELECT MAX(timestamp) AS latest FROM token_analytics_snapshots`)
	if err != nil || len(results) == 0 || results[0].Latest.IsZero() {
		log.Debug("Snapshot backfill: no existing data in QuestDB, starting fresh")

		return 0
	}
	hoursSince := int(now.Sub(results[0].Latest) / time.Hour)
	if hoursSince <= 1 {
		log.Debug(fmt.Sprintf("Snapshot backfill: data is up to date (latest: %v)", results[0].Latest))

		return 0
	}
	log.Debug(fmt.Sprintf("Snapshot backfill: gap detected from %v to %v (%d hours, %d total snapshots)", results[0].Latest, now, hoursSince, hoursSince*len(validAnalyticsIntervals)))

	return hoursSince
}

func (t *tokenAnalytics) unprocessedSnapshotIntervals(ctx context.Context, hour time.Time, intervals []string) ([]string, error) {
	hourKey := hour.UTC().Format(hourKeyFormat)
	pipe := t.processedDataDB.Pipeline()
	cmds := make([]*redis.BoolCmd, len(intervals))
	for i, interval := range intervals {
		cmds[i] = pipe.SIsMember(ctx, processedSnapshotsSetKey, hourKey+":"+interval)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, fmt.Errorf("failed to pipeline SIsMember for %s: %w", hourKey, err)
	}
	unprocessed := make([]string, 0, len(intervals))
	for i, cmd := range cmds {
		if !cmd.Val() {
			unprocessed = append(unprocessed, intervals[i])
		}
	}
	log.Debug(fmt.Sprintf("Checked %d intervals for %s: %d unprocessed", len(intervals), hourKey, len(unprocessed)))

	return unprocessed, nil
}

func (t *tokenAnalytics) isSnapshotProcessed(ctx context.Context, hour time.Time, interval string) (bool, error) {
	member := hour.UTC().Format(hourKeyFormat) + ":" + interval

	return t.processedDataDB.SIsMember(ctx, processedSnapshotsSetKey, member).Result()
}

func (t *tokenAnalytics) markSnapshotProcessed(ctx context.Context, hour time.Time, interval string) error {
	member := hour.UTC().Format(hourKeyFormat) + ":" + interval

	return t.processedDataDB.SAdd(ctx, processedSnapshotsSetKey, member).Err()
}

func (t *tokenAnalytics) computeAndStoreAnalyticsSnapshot(ctx context.Context, targetHour time.Time, interval string) error {
	dur := intervalToDuration(interval)
	windowEnd := targetHour.Add(time.Hour)
	windowStart := windowEnd.Add(-dur)
	log.Debug(fmt.Sprintf("Computing stats for %v/%s (window: %v to %v)", targetHour, interval, windowStart, windowEnd))
	stats, err := t.computeIntervalStats(ctx, windowStart, windowEnd)
	if err != nil {
		return fmt.Errorf("failed to compute interval stats for %s: %w", interval, err)
	}
	entry := &analyticsSnapshotEntry{
		timestamp:    targetHour,
		intervalType: interval,
		launched:     int64(stats.Launched),
		migrated:     int64(stats.Migrated),
		totalVolume:  stats.TotalVolume,
	}
	if err := questdb.Write(ctx, t.questDB, entry); err != nil {
		return fmt.Errorf("failed to write analytics snapshot to QuestDB for %v/%s: %w", targetHour, interval, err)
	}
	if err := t.markSnapshotProcessed(ctx, targetHour, interval); err != nil {
		return fmt.Errorf("failed to mark snapshot %v/%s as processed: %w", targetHour, interval, err)
	}
	log.Debug(fmt.Sprintf("Stored snapshot for %v/%s: launched=%d, migrated=%d, volume=%.2f",
		targetHour, interval, stats.Launched, stats.Migrated, stats.TotalVolume))

	return nil
}

func (t *tokenAnalytics) computeIntervalStats(ctx context.Context, from, to time.Time) (*intervalStatsRow, error) {
	pgRow, err := storage.Get[struct {
		Launched uint64 `db:"launched"`
		Migrated uint64 `db:"migrated"`
	}](ctx, t.ingestedDataDB, `
		SELECT
			(SELECT COUNT(*) FROM tokens WHERE created_at >= $1 AND created_at < $2) AS launched,
			(SELECT COUNT(*) FROM tokens WHERE migrated_at >= $1 AND migrated_at < $2) AS migrated`, from, to)
	if err != nil {
		return nil, fmt.Errorf("failed to query launched/migrated from PostgreSQL: %w", err)
	}
	volRow, err := questdb.Select[struct {
		TotalVolume float64 `db:"total_volume"`
	}](ctx, t.questDB, `
		SELECT COALESCE(sum(volume_1h), 0) AS total_volume
		FROM token_volume_1h
		WHERE timestamp >= $1 AND timestamp < $2`, from, to)
	if err != nil {
		return nil, fmt.Errorf("failed to query total_volume from QuestDB: %w", err)
	}
	result := &intervalStatsRow{
		Launched: pgRow.Launched,
		Migrated: pgRow.Migrated,
	}
	if len(volRow) > 0 {
		result.TotalVolume = volRow[0].TotalVolume
	}

	return result, nil
}

func (t *tokenAnalytics) GetGlobalTokenStatistics(ctx context.Context, interval string) (*GlobalTokenStats, error) {
	results, err := questdb.Select[GlobalTokenStats](ctx, t.questDB,
		`SELECT 
			launched,
			migrated,
			total_volume
		 FROM token_analytics_snapshots
		 WHERE interval_type = $1
		 ORDER BY timestamp DESC
		 LIMIT 1`, interval)
	if err != nil {
		return nil, fmt.Errorf("failed to get analytics stats from QuestDB for %s: %w", interval, err)
	}
	if len(results) == 0 {
		return &GlobalTokenStats{}, nil
	}

	return results[0], nil
}

func (e *analyticsSnapshotEntry) Marshal(client questdb.LineSender) questdb.At {
	return client.Table("token_analytics_snapshots").
		Symbol("interval_type", e.intervalType).
		Int64Column("launched", e.launched).
		Int64Column("migrated", e.migrated).
		Float64Column("total_volume", e.totalVolume)
}

func (e *analyticsSnapshotEntry) Time() time.Time {
	return e.timestamp
}

func intervalToDuration(interval string) time.Duration {
	switch interval {
	case "24h":
		return 24 * time.Hour
	case "7d":
		return 7 * 24 * time.Hour
	case "30d":
		return 30 * 24 * time.Hour
	case "1y":
		return 365 * 24 * time.Hour
	default:
		return 0
	}
}
