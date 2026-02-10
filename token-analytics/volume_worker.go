// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/redis/go-redis/v9"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

type volumeWithType struct {
	Platform        *string `db:"platform"`
	TokenAddress    string  `db:"token_address"`
	Volume24h       float64 `db:"volume_24h"`
	ExternalAddress string  `db:"external_address"`
	TokenType       string  `db:"token_type"`
}

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
	if r := execOnRealMasterWithLock(ctx, t.ingestedDataDB, "refresh_token_volumes_24h", "SELECT refresh_token_volumes_24h()"); r.Error != nil {
		return fmt.Errorf("failed to refresh materialized view: %w", r.Error)
	}
	duration := time.Since(startTime)
	log.Debug(fmt.Sprintf("Refreshed materialized view in %v", duration))

	return nil
}

func (t *tokenAnalytics) updateTrendingVolumes(ctx context.Context) error {
	startTime := time.Now()
	tempSetKey := fmt.Sprintf("token_analytics:temp:volumes_update:%d", time.Now().Unix())
	defer func() {
		_ = t.processedDataDB.Del(ctx, tempSetKey).Err()
	}()
	totalUpdated, err := t.updateTokenVolumesInRedis(ctx, tempSetKey)
	if err != nil {
		return err
	}
	totalRemoved, err := t.removeZeroVolumeTokens(ctx, tempSetKey)
	if err != nil {
		return err
	}
	duration := time.Since(startTime)
	log.Debug(fmt.Sprintf("Updated trending volumes: %d tokens updated, %d tokens removed (zero volume) in %v", totalUpdated, totalRemoved, duration))

	return nil
}

func (t *tokenAnalytics) updateTokenVolumesInRedis(ctx context.Context, tempSetKey string) (int, error) {
	const batchSize = 10000
	totalUpdated := 0
	lastAddress := ""

	for ctx.Err() == nil {
		volumes, err := t.fetchVolumesBatch(ctx, lastAddress, batchSize)
		if err != nil {
			return totalUpdated, err
		}
		if len(volumes) == 0 {
			break
		}
		if err := t.updateTrendingSetsForBatch(ctx, tempSetKey, volumes); err != nil {
			return totalUpdated, err
		}
		totalUpdated += len(volumes)
		lastAddress = volumes[len(volumes)-1].TokenAddress

		if len(volumes) < batchSize {
			break
		}
	}

	return totalUpdated, nil
}

func (t *tokenAnalytics) fetchVolumesBatch(ctx context.Context, lastAddress string, batchSize int) ([]*volumeWithType, error) {
	var query string
	var args []any

	if lastAddress == "" {
		query = `
			SELECT 
				contract_address as token_address,
				volume_24h,
				external_address,
				COALESCE(token_type, '') as token_type,
				platform
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
				COALESCE(token_type, '') as token_type,
				platform
			FROM token_volumes_24h
			WHERE contract_address > $1
			ORDER BY contract_address
			LIMIT $2
		`
		args = append(args, lastAddress, batchSize)
	}

	volumes, err := storage.Select[volumeWithType](ctx, t.ingestedDataDB, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query 24h volumes from database: %w", err)
	}

	return volumes, nil
}

func (t *tokenAnalytics) updateTrendingSetsForBatch(ctx context.Context, tempSetKey string, volumes []*volumeWithType) error {
	pipe := t.processedDataDB.TxPipeline()
	for _, vol := range volumes {
		pipe.SAdd(ctx, tempSetKey, vol.ExternalAddress)
		t.addTokenToTrendingSets(ctx, pipe, vol)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to update trending set in Redis: %w", err)
	}

	return nil
}

func (t *tokenAnalytics) addTokenToTrendingSets(ctx context.Context, pipe redis.Pipeliner, vol *volumeWithType) {
	pipe.ZAdd(ctx, globalTrendingSetKey, redis.Z{
		Score:  vol.Volume24h,
		Member: vol.ExternalAddress,
	})

	if vol.Platform != nil && *vol.Platform == PlatformGroupXCom {
		pipe.ZAdd(ctx, globalTrendingXcomSetKey, redis.Z{
			Score:  vol.Volume24h,
			Member: vol.ExternalAddress,
		})
	} else if vol.TokenType != "" {
		t.addTokenToTypeSpecificSets(ctx, pipe, vol)
	}
}

func (t *tokenAnalytics) addTokenToTypeSpecificSets(ctx context.Context, pipe redis.Pipeliner, vol *volumeWithType) {
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

func (t *tokenAnalytics) removeZeroVolumeTokens(ctx context.Context, tempSetKey string) (int, error) {
	totalRemoved := 0
	trendingSetKeys := t.getAllTrendingSetKeys()

	for _, setKey := range trendingSetKeys {
		if setKey == "" {
			continue
		}
		removed, err := t.removeZeroVolumeTokensFromSet(ctx, setKey, tempSetKey)
		if err != nil {
			return totalRemoved, err
		}
		totalRemoved += removed
	}

	return totalRemoved, nil
}

func (t *tokenAnalytics) getAllTrendingSetKeys() []string {
	return []string{
		globalTrendingSetKey,
		globalTrendingXcomSetKey,
		globalTrendingAnyPostSetKey,
		getTrendingSetKeyByType(TokenTypeProfile),
		getTrendingSetKeyByType(TokenTypePost),
		getTrendingSetKeyByType(TokenTypeVideo),
		getTrendingSetKeyByType(TokenTypeArticle),
	}
}

func (t *tokenAnalytics) removeZeroVolumeTokensFromSet(ctx context.Context, setKey, tempSetKey string) (int, error) {
	const scanBatchSize = 1000
	totalRemoved := 0
	cursor := uint64(0)

	for ctx.Err() == nil {
		members, nextCursor, err := t.processedDataDB.ZScan(ctx, setKey, cursor, "*", scanBatchSize).Result()
		if err != nil {
			return totalRemoved, fmt.Errorf("failed to scan trending set %s: %w", setKey, err)
		}
		if len(members) > 0 {
			removed, err := t.removeNonExistentTokens(ctx, setKey, tempSetKey, members)
			if err != nil {
				return totalRemoved, errors.Wrapf(err, "failed to remove non-existent tokens from %s", setKey)
			}
			totalRemoved += removed
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return totalRemoved, nil
}

func (t *tokenAnalytics) removeNonExistentTokens(ctx context.Context, setKey, tempSetKey string, members []string) (int, error) {
	pipe := t.processedDataDB.Pipeline()
	removed := 0
	for i := 0; i < len(members); i += 2 {
		externalAddr := members[i]
		exists, err := t.processedDataDB.SIsMember(ctx, tempSetKey, externalAddr).Result()
		if err != nil {
			return removed, fmt.Errorf("failed to check token existence: %w", err)
		}
		if !exists {
			pipe.ZRem(ctx, setKey, externalAddr)
			removed++
		}
	}
	if removed > 0 {
		if _, err := pipe.Exec(ctx); err != nil {
			return removed, fmt.Errorf("failed to remove zero-volume tokens from %s: %w", setKey, err)
		}
	}

	return removed, nil
}
