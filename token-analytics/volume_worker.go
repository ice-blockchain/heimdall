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

func (t *tokenAnalytics) runMaterializedViewRefreshWorker(ctx context.Context) {
	ticker := time.NewTicker(volume24hMaterializedViewRefreshInterval)
	defer ticker.Stop()

	log.Info(fmt.Sprintf("Materialized view refresh worker started, refreshing every %s", volume24hMaterializedViewRefreshInterval))
	if err := t.refreshMaterializedView(ctx); err != nil {
		if storage.IsErr(err, storage.ErrReadOnly) {
			log.Warn("Database is read-only, stopping materialized view refresh worker")

			return
		}
		log.Error(fmt.Errorf("failed to refresh materialized view on startup: %w", err))
	}

	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
			log.Info("Materialized view refresh worker stopped")

			return
		case <-ticker.C:
			if err := t.refreshMaterializedView(ctx); err != nil {
				if storage.IsErr(err, storage.ErrReadOnly) {
					log.Warn("Database is read-only, stopping materialized view refresh worker")

					return
				}
				log.Error(fmt.Errorf("failed to refresh materialized view: %w", err))
			}
		}
	}
}

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

func (t *tokenAnalytics) refreshMaterializedView(ctx context.Context) error {
	startTime := time.Now()
	if _, err := storage.Exec(ctx, t.ingestedDataDB, "SELECT refresh_token_volumes_24h()"); err != nil {
		return fmt.Errorf("failed to refresh materialized view: %w", err)
	}
	duration := time.Since(startTime)
	log.Debug(fmt.Sprintf("Refreshed materialized view in %v", duration))

	return nil
}

func (t *tokenAnalytics) updateTrendingVolumes(ctx context.Context) error {
	startTime := time.Now()
	const batchSize = 10000
	totalUpdated := 0
	lastAddress := ""

	for ctx.Err() == nil {
		var query string
		var args []any
		if lastAddress == "" {
			query = `
				SELECT 
					contract_address as token_address,
					volume_24h,
					external_address,
					COALESCE(token_type, '') as token_type
				FROM token_volumes_24h
				ORDER BY contract_address
				LIMIT $1
			`
			args = append(args, batchSize)
		} else {
			query = `
				SELECT 
					contract_address as token_address,
					volume_24h,
					external_address, 
					COALESCE(token_type, '') as token_type
				FROM token_volumes_24h
				WHERE contract_address > $1
				ORDER BY contract_address
				LIMIT $2
			`
			args = append(args, lastAddress, batchSize)
		}

		type volumeWithType struct {
			TokenAddress    string  `db:"token_address"`
			Volume24h       float64 `db:"volume_24h"`
			ExternalAddress string  `db:"external_address"`
			TokenType       string  `db:"token_type"`
		}

		volumes, err := storage.Select[volumeWithType](ctx, t.ingestedDataDB, query, args...)
		if err != nil {
			return fmt.Errorf("failed to query 24h volumes from database: %w", err)
		}
		if len(volumes) == 0 {
			break
		}
		pipe := t.processedDataDB.TxPipeline()
		for _, vol := range volumes {
			pipe.ZAdd(ctx, globalTrendingSetKey, redis.Z{
				Score:  vol.Volume24h,
				Member: vol.ExternalAddress,
			})
			if vol.TokenType != "" {
				typeSpecificKey := getTrendingSetKeyByType(vol.TokenType)
				if typeSpecificKey != "" {
					pipe.ZAdd(ctx, typeSpecificKey, redis.Z{
						Score:  vol.Volume24h,
						Member: vol.ExternalAddress,
					})
				}
				if IsContentType(vol.TokenType) {
					pipe.ZAdd(ctx, globalTrendingAnyPostSetKey, redis.Z{
						Score:  vol.Volume24h,
						Member: vol.ExternalAddress,
					})
				}
			}
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
