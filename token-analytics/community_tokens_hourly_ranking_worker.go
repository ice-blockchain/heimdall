// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"time"

	"github.com/ice-blockchain/heimdall/token-analytics/internal/questdb"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) runHourlyRankingWorker(ctx context.Context) {
	log.Info("Hourly ranking worker started")
	t.backfillHourlyRankings(ctx)
	ticker := time.NewTicker(hourlyRankingCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info("Hourly ranking worker stopped")
			return
		case <-ticker.C:
			if err := t.tryComputeCurrentHourlyRanking(ctx); err != nil {
				log.Error(fmt.Errorf("hourly ranking worker tick failed: %w", err))
			}
		}
	}
}

func (t *tokenAnalytics) tryComputeCurrentHourlyRanking(ctx context.Context) error {
	targetHour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)

	processed, err := t.isHourProcessed(ctx, targetHour)
	if err != nil {
		return fmt.Errorf("failed to check if hour %v is processed: %w", targetHour, err)
	}
	if processed {
		return nil
	}
	log.Debug(fmt.Sprintf("Computing hourly ranking for %v", targetHour))

	return t.computeAndStoreHourlyRanking(ctx, targetHour)
}

func (t *tokenAnalytics) backfillHourlyRankings(ctx context.Context) {
	now := time.Now().UTC().Truncate(time.Hour)
	hoursToBackfill := t.rankingBackfillDepth(ctx, now)
	if hoursToBackfill == 0 {
		log.Info("Hourly ranking backfill: nothing to backfill")

		return
	}
	log.Info(fmt.Sprintf("Backfilling hourly rankings for last %d hours", hoursToBackfill))
	filled := 0

	for h := 1; h <= hoursToBackfill; h++ {
		if ctx.Err() != nil {
			return
		}
		targetHour := now.Add(-time.Duration(h) * time.Hour)

		processed, err := t.isHourProcessed(ctx, targetHour)
		if err != nil {
			log.Error(fmt.Errorf("backfill: failed to check hour %v: %w", targetHour, err))

			continue
		}
		if processed {
			continue
		}
		if err := t.computeAndStoreHourlyRanking(ctx, targetHour); err != nil {
			log.Error(fmt.Errorf("backfill: failed to compute ranking for %v: %w", targetHour, err))

			continue
		}
		filled++
	}

	log.Info(fmt.Sprintf("Hourly ranking backfill complete: %d/%d hours filled", filled, hoursToBackfill))
}

func (t *tokenAnalytics) rankingBackfillDepth(ctx context.Context, now time.Time) int {
	results, err := questdb.Select[struct {
		Latest time.Time `db:"latest"`
	}](ctx, t.questDB, `SELECT MAX(timestamp) AS latest FROM hourly_token_rankings`)
	if err != nil || len(results) == 0 || results[0].Latest.IsZero() {
		log.Debug("Ranking backfill: no existing data in QuestDB, starting fresh")

		return 0
	}
	hoursSince := int(now.Sub(results[0].Latest) / time.Hour)
	if hoursSince <= 1 {
		log.Debug(fmt.Sprintf("Ranking backfill: data is up to date (latest: %v)", results[0].Latest))

		return 0
	}
	log.Debug(fmt.Sprintf("Ranking backfill: gap detected from %v to %v (%d hours)", results[0].Latest, now, hoursSince))

	return hoursSince
}

func (t *tokenAnalytics) isHourProcessed(ctx context.Context, hour time.Time) (bool, error) {
	member := hour.UTC().Format(hourKeyFormat)

	return t.processedDataDB.SIsMember(ctx, processedHoursSetKey, member).Result()
}

func (t *tokenAnalytics) markHourProcessed(ctx context.Context, hour time.Time) error {
	member := hour.UTC().Format(hourKeyFormat)

	return t.processedDataDB.SAdd(ctx, processedHoursSetKey, member).Err()
}

func (t *tokenAnalytics) computeAndStoreHourlyRanking(ctx context.Context, targetHour time.Time) error {
	hourStart := targetHour.Truncate(time.Hour)
	hourEnd := hourStart.Add(time.Hour)
	volumes, err := t.fetchHourlyVolumes(ctx, hourStart, hourEnd)
	if err != nil {
		return fmt.Errorf("failed to fetch hourly volumes for %v: %w", hourStart, err)
	}
	if len(volumes) == 0 {
		log.Debug(fmt.Sprintf("No volume data for hour %v, skipping QuestDB write", hourStart))
	} else {
		log.Debug(fmt.Sprintf("Fetched %d tokens with volume for hour %v (top: %.6f)", len(volumes), hourStart, volumes[0].Volume1h))
		entries := make([]questdb.StructMarshaller, 0, len(volumes))
		for i, vol := range volumes {
			entries = append(entries, &hourlyTokenRankingEntry{
				timestamp:       hourStart,
				externalAddress: vol.ExternalAddress,
				contractAddress: vol.ContractAddress,
				rank:            i + 1,
				volume1h:        vol.Volume1h,
			})
		}
		if err := questdb.Write(ctx, t.questDB, entries...); err != nil {
			return fmt.Errorf("failed to write hourly rankings to QuestDB for %v: %w", hourStart, err)
		}
		log.Debug(fmt.Sprintf("Wrote %d rankings to QuestDB for %v", len(entries), hourStart))
	}
	if err := t.markHourProcessed(ctx, hourStart); err != nil {
		return fmt.Errorf("failed to mark hour %v as processed: %w", hourStart, err)
	}

	return nil
}

func (t *tokenAnalytics) fetchHourlyVolumes(ctx context.Context, hourStart, hourEnd time.Time) ([]*hourlyVolumeRow, error) {
	query := `
		SELECT
			ts.contract_address,
			t.external_address,
			SUM(
				CASE
					WHEN ts.direction = true THEN ts.input_amount::numeric * ts.price_usd
					ELSE ts.output_amount::numeric * ts.price_usd
				END
			) AS volume_1h
		FROM token_swaps ts
		JOIN tokens t ON t.contract_address = ts.contract_address
		WHERE ts.created_at >= $1 AND ts.created_at < $2
		GROUP BY ts.contract_address, t.external_address
		HAVING SUM(
			CASE
				WHEN ts.direction = true THEN ts.input_amount::numeric * ts.price_usd
				ELSE ts.output_amount::numeric * ts.price_usd
			END
		) > 0
		ORDER BY volume_1h DESC
		LIMIT $3
	`
	volumes, err := storage.Select[hourlyVolumeRow](ctx, t.ingestedDataDB, query, hourStart, hourEnd, HourlyRankingTopN)
	if err != nil {
		return nil, fmt.Errorf("failed to query hourly volumes: %w", err)
	}

	return volumes, nil
}

func (e *hourlyTokenRankingEntry) Marshal(client questdb.LineSender) questdb.At {
	return client.Table("hourly_token_rankings").
		Symbol("external_address", e.externalAddress).
		StringColumn("contract_address", e.contractAddress).
		Int64Column("rank", int64(e.rank)).
		Float64Column("volume_1h", e.volume1h)
}

func (e *hourlyTokenRankingEntry) Time() time.Time {
	return e.timestamp
}
