// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/redis/go-redis/v9"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

const (
	redisKeyLastBondingSync = "token_analytics:last_bonding_sync"
	redisKeyLastBalanceSync = "token_analytics:last_balance_sync"
	repopulateBatchSize     = 10000
)

type (
	bondingCurveData struct {
		ExternalAddress              string     `db:"external_address"`
		Type                         string     `db:"type"`
		Platform                     string     `db:"platform"`
		BondingCurveMigrated         bool       `db:"bonding_curve_migrated"`
		BondingCurveCurrentAmount    string     `db:"bonding_curve_current_amount"`
		BondingCurveCurrentAmountUSD float64    `db:"bonding_curve_current_amount_usd"`
		BondingCurveGoalAmountUSD    float64    `db:"bonding_curve_goal_amount_usd"`
		BondingCurveNotifiedAt       *time.Time `db:"bonding_curve_notified_at"`
	}

	userPositionData struct {
		UserExternalAddress   *string    `db:"user_external_address"`
		BalanceNotifiedAt     *time.Time `db:"balance_notified_at"`
		UserBlockchainAddress string     `db:"user_blockchain_address"`
		ExternalAddress       string     `db:"external_address"`
		Amount                string     `db:"amount"`
	}
)

func (t *tokenAnalytics) RepopulateRedisFromPostgres(ctx context.Context) error {
	log.Info("Starting Redis repopulation from PostgreSQL...")
	start := time.Now()

	bondingCount, err := t.repopulateBondingCurve(ctx)
	if err != nil {
		log.Error(errors.Wrap(err, "failed to repopulate bonding curve"))
	}
	balanceCount, err := t.repopulateUserBalances(ctx)
	if err != nil {
		log.Error(errors.Wrap(err, "failed to repopulate user balances"))
	}
	elapsed := time.Since(start)
	log.Info(fmt.Sprintf("Redis repopulation completed in %v: %d bonding curve tokens, %d user balance positions",
		elapsed, bondingCount, balanceCount))

	return nil
}

func (t *tokenAnalytics) repopulateBondingCurve(ctx context.Context) (int, error) {
	var since time.Time
	lastSync, err := t.processedDataDB.Get(ctx, redisKeyLastBondingSync).Result()
	if errors.Is(err, redis.Nil) {
		since = time.Unix(0, 0)
		log.Info("Bonding curve repopulation: first run detected, starting from epoch (will process all tokens)")
	} else if err != nil {
		return 0, errors.Wrap(err, "failed to get last bonding sync from Redis")
	} else {
		since, err = time.Parse(time.RFC3339, lastSync)
		if err != nil {
			return 0, errors.Wrapf(err, "failed to parse last bonding sync: %s", lastSync)
		}
		log.Debug(fmt.Sprintf("Bonding curve repopulation: checking tokens updated since %v", since.Format(time.RFC3339)))
	}

	totalProcessed := 0
	for {
		tokens, err := storage.Select[bondingCurveData](ctx, t.ingestedDataDB, `
			SELECT 
				external_address,
				type,
				platform,
				bonding_curve_migrated,
				bonding_curve_current_amount,
				bonding_curve_current_amount_usd,
				bonding_curve_goal_amount_usd,
				bonding_curve_notified_at
			FROM tokens
			WHERE bonding_curve_notified_at >= $1
			OR (bonding_curve_current_amount_usd IS NOT NULL 
				AND bonding_curve_notified_at IS NULL)
			ORDER BY bonding_curve_notified_at ASC NULLS FIRST
			LIMIT $2
		`, since, repopulateBatchSize)

		if err != nil {
			return totalProcessed, errors.Wrap(err, "failed to query bonding curve tokens")
		}
		if len(tokens) == 0 {
			break
		}

		log.Debug(fmt.Sprintf("Bonding curve repopulation: processing batch of %d tokens", len(tokens)))
		var maxSyncedAt time.Time
		updatedCount := 0
		skippedCount := 0
		migratedCount := 0

		for _, token := range tokens {
			notifiedAt := "NULL"
			if token.BondingCurveNotifiedAt != nil {
				notifiedAt = token.BondingCurveNotifiedAt.Format(time.RFC3339)
			}
			if token.BondingCurveNotifiedAt != nil && token.BondingCurveNotifiedAt.After(maxSyncedAt) {
				maxSyncedAt = *token.BondingCurveNotifiedAt
			}

			if token.BondingCurveMigrated {
				if err := t.updateBondingCurveInRedis(ctx, token.ExternalAddress, token.Type, token.Platform, 0, true); err != nil {
					log.Error(errors.Wrapf(err, "failed to remove migrated token from Redis: token=%s, type=%s, notified_at=%s",
						token.ExternalAddress, token.Type, notifiedAt))
				} else {
					log.Debug(fmt.Sprintf("Bonding curve: removed migrated token from Redis: token=%s, type=%s, notified_at=%s",
						token.ExternalAddress, token.Type, notifiedAt))
					migratedCount++
				}
				continue
			}

			currentAmountBig := new(big.Int)
			var expectedScore float64
			if _, ok := currentAmountBig.SetString(token.BondingCurveCurrentAmount, 10); ok {
				currentAmountWei := new(big.Float).SetInt(currentAmountBig)
				expectedScore, _ = currentAmountWei.Float64()
			} else {
				log.Warn(fmt.Sprintf("Bonding curve: skipping token with invalid amount: token=%s, type=%s, amount=%s, notified_at=%s",
					token.ExternalAddress, token.Type, token.BondingCurveCurrentAmount, notifiedAt))

				continue
			}

			actualScore, err := t.processedDataDB.ZScore(ctx, globalBondingCurveProgressSetKey, token.ExternalAddress).Result()
			if errors.Is(err, redis.Nil) || math.Abs(expectedScore-actualScore) > 1.0 {
				if err := t.updateBondingCurveInRedis(ctx, token.ExternalAddress, token.Type, token.Platform, expectedScore, false); err != nil {
					log.Error(errors.Wrapf(err, "failed to update bonding curve in Redis: token=%s, type=%s, expected_score=%.2e, notified_at=%s",
						token.ExternalAddress, token.Type, expectedScore, notifiedAt))
				} else {
					progressPercent := 0.0
					if token.BondingCurveGoalAmountUSD > 0 {
						progressPercent = (token.BondingCurveCurrentAmountUSD / token.BondingCurveGoalAmountUSD) * 100
					}
					log.Debug(fmt.Sprintf("Bonding curve: updated token in Redis: token=%s, type=%s, progress=%.2f%% ($%.2f/$%.2f), score: %.2e → %.2e, notified_at=%s",
						token.ExternalAddress, token.Type, progressPercent,
						token.BondingCurveCurrentAmountUSD, token.BondingCurveGoalAmountUSD,
						actualScore, expectedScore, notifiedAt))
					updatedCount++
				}
			} else {
				skippedCount++
			}
		}

		if updatedCount > 0 || skippedCount > 0 || migratedCount > 0 {
			log.Debug(fmt.Sprintf("Bonding curve batch summary: updated=%d, skipped=%d (already up-to-date), migrated=%d (removed), total=%d",
				updatedCount, skippedCount, migratedCount, len(tokens)))
		}
		totalProcessed += len(tokens)
		if !maxSyncedAt.IsZero() {
			since = maxSyncedAt
			if err := t.processedDataDB.Set(ctx, redisKeyLastBondingSync, maxSyncedAt.Format(time.RFC3339Nano), 0).Err(); err != nil {
				return totalProcessed, errors.Wrap(err, "failed to update last bonding sync timestamp")
			}
			log.Debug(fmt.Sprintf("Bonding curve: updated last_sync_timestamp to %s", maxSyncedAt.Format(time.RFC3339)))
		}
		if len(tokens) < repopulateBatchSize {
			break
		}
		select {
		case <-ctx.Done():
			return totalProcessed, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}

	return totalProcessed, nil
}

func (t *tokenAnalytics) repopulateUserBalances(ctx context.Context) (int, error) {
	var since time.Time
	lastSync, err := t.processedDataDB.Get(ctx, redisKeyLastBalanceSync).Result()
	if errors.Is(err, redis.Nil) {
		since = time.Unix(0, 0)
		log.Info("User balance repopulation: first run detected, starting from epoch (will process all positions)")
	} else if err != nil {
		return 0, errors.Wrap(err, "failed to get last balance sync from Redis")
	} else {
		since, err = time.Parse(time.RFC3339, lastSync)
		if err != nil {
			return 0, errors.Wrapf(err, "failed to parse last balance sync: %s", lastSync)
		}
		log.Debug(fmt.Sprintf("User balance repopulation: checking positions updated since %v", since.Format(time.RFC3339)))
	}
	totalProcessed := 0
	for {
		positions, err := storage.Select[userPositionData](ctx, t.ingestedDataDB, `
			SELECT 
				user_blockchain_address,
				user_external_address,
				external_address,
				amount,
				balance_notified_at
			FROM user_token_positions
			WHERE balance_notified_at >= $1
			OR balance_notified_at IS NULL
			ORDER BY balance_notified_at ASC NULLS FIRST
			LIMIT $2
		`, since, repopulateBatchSize)
		if err != nil {
			return totalProcessed, errors.Wrap(err, "failed to query user positions")
		}
		if len(positions) == 0 {
			break
		}
		log.Debug(fmt.Sprintf("User balance repopulation: processing batch of %d positions", len(positions)))

		var maxSyncedAt time.Time
		updatedCount := 0
		skippedCount := 0
		zeroBalanceCount := 0

		for _, pos := range positions {
			notifiedAt := "NULL"
			if pos.BalanceNotifiedAt != nil {
				notifiedAt = pos.BalanceNotifiedAt.Format(time.RFC3339)
			}

			amountBig, ok := new(big.Int).SetString(pos.Amount, 10)
			if !ok {
				log.Error(errors.Errorf("User balance: skipping position with invalid amount: user=%s, token=%s, amount=%s, notified_at=%s",
					pos.UserBlockchainAddress, pos.ExternalAddress, pos.Amount, notifiedAt))

				continue
			}
			expectedAmount := weiToFloat64FromBigInt(amountBig)

			if pos.BalanceNotifiedAt != nil && pos.BalanceNotifiedAt.After(maxSyncedAt) {
				maxSyncedAt = *pos.BalanceNotifiedAt
			}

			userExternal := ""
			if pos.UserExternalAddress != nil {
				userExternal = *pos.UserExternalAddress
			}
			userPositionKey := keyUserPositionOfToken(pos.ExternalAddress)
			actualAmount, err := t.processedDataDB.ZScore(ctx, userPositionKey, userExternal).Result()

			if expectedAmount == 0 {
				if !errors.Is(err, redis.Nil) {
					if err := t.updateUserPositionInRedis(ctx, pos.UserBlockchainAddress, userExternal, pos.ExternalAddress, 0); err != nil {
						log.Error(errors.Wrapf(err, "failed to remove zero balance from Redis: user=%s (external=%s), token=%s",
							pos.UserBlockchainAddress, userExternal, pos.ExternalAddress))
					} else {
						zeroBalanceCount++
					}
				}

				continue
			}
			log.Debug(fmt.Sprintf("User balance: processing position | user=%s (external=%s), token=%s, amount_wei=%s, amount_float=%.2f, notified_at=%s",
				pos.UserBlockchainAddress, userExternal, pos.ExternalAddress, pos.Amount, expectedAmount, notifiedAt))

			if errors.Is(err, redis.Nil) || actualAmount != expectedAmount {
				if err := t.updateUserPositionInRedis(ctx, pos.UserBlockchainAddress, userExternal, pos.ExternalAddress, expectedAmount); err != nil {
					log.Error(errors.Wrapf(err, "failed to update user position in Redis: user=%s (external=%s), token=%s, expected_balance=%.2f, notified_at=%s",
						pos.UserBlockchainAddress, userExternal, pos.ExternalAddress, expectedAmount, notifiedAt))
				} else {
					action := "updated"
					if errors.Is(err, redis.Nil) {
						action = "created"
					}
					log.Debug(fmt.Sprintf("User balance: %s position in Redis: user=%s (external=%s), token=%s, balance: %.2f → %.2f, notified_at=%s",
						action, pos.UserBlockchainAddress, userExternal, pos.ExternalAddress, actualAmount, expectedAmount, notifiedAt))
					updatedCount++
				}
			} else {
				skippedCount++
			}
		}

		if updatedCount > 0 || skippedCount > 0 || zeroBalanceCount > 0 {
			log.Debug(fmt.Sprintf("User balance batch summary: updated=%d, skipped=%d (already up-to-date), zero_balance=%d (removed), total=%d",
				updatedCount, skippedCount, zeroBalanceCount, len(positions)))
		}
		totalProcessed += len(positions)
		if !maxSyncedAt.IsZero() {
			since = maxSyncedAt
			if err := t.processedDataDB.Set(ctx, redisKeyLastBalanceSync,
				maxSyncedAt.Format(time.RFC3339Nano), 0).Err(); err != nil {

				log.Error(errors.Wrap(err, "failed to update last balance sync timestamp"))
			} else {
				log.Debug(fmt.Sprintf("User balance: updated last_sync_timestamp to %s", maxSyncedAt.Format(time.RFC3339)))
			}
		}
		if len(positions) < repopulateBatchSize {
			break
		}

		select {
		case <-ctx.Done():
			return totalProcessed, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}

	return totalProcessed, nil
}
