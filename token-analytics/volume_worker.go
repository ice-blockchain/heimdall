// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) runVolumeWorker(ctx context.Context) {
	ticker := time.NewTicker(volumeUpdateInterval)
	defer ticker.Stop()

	log.Info("Volume worker started, updating trending data every minute")
	if err := t.updateTrendingVolumes(ctx); err != nil {
		log.Error(fmt.Errorf("failed to update trending volumes on startup: %w", err))
	}
	for {
		select {
		case <-ctx.Done():
			log.Info("Volume worker stopped")
			return
		case <-ticker.C:
			if err := t.updateTrendingVolumes(ctx); err != nil {
				log.Error(fmt.Errorf("failed to update trending volumes: %w", err))
			}
		}
	}
}

func (t *tokenAnalytics) updateTrendingVolumes(ctx context.Context) error {
	startTime := time.Now()

	const batchSize = 10000
	totalUpdated := 0
	lastAddress := ""

	for ctx.Err() == nil {
		baseQuery := `
			SELECT 
				contract_address as token_address,
				COALESCE(SUM(
					CASE 
						WHEN direction = true THEN input_amount::numeric * price_usd
						ELSE output_amount::numeric * price_usd
					END
				), 0) as volume_24h
			FROM token_swaps
			WHERE 
				created_at >= NOW() - INTERVAL '24 hours'
		`
		var query string
		var volumes []*tokenVolume24h
		var args []any
		var err error
		if lastAddress == "" {
			query = baseQuery + `
				GROUP BY contract_address
				ORDER BY contract_address
				LIMIT $1
			`
			args = append(args, batchSize)
		} else {
			query = baseQuery + `
				AND contract_address > $1
				GROUP BY contract_address
				ORDER BY contract_address
				LIMIT $2
			`
			args = append(args, lastAddress, batchSize)
		}
		volumes, err = storage.Select[tokenVolume24h](ctx, t.ingestedDataDB, query, args...)
		if err != nil {
			return fmt.Errorf("failed to query 24h volumes from database: %w", err)
		}
		if len(volumes) == 0 {
			break
		}
		pipe := t.processedDataDB.Pipeline()
		for _, vol := range volumes {
			pipe.ZAdd(ctx, globalTrendingSetKey, redis.Z{
				Score:  vol.Volume24h,
				Member: vol.TokenAddress,
			})
			lastAddress = vol.TokenAddress
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("failed to update trending set in Redis: %w", err)
		}
		totalUpdated += len(volumes)
		if len(volumes) < batchSize {
			break
		}
	}

	duration := time.Since(startTime)
	log.Debug(fmt.Sprintf("Updated trending volumes: %d tokens in %v", totalUpdated, duration))

	return nil
}
