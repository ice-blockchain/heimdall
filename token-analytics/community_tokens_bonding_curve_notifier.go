// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/cockroachdb/errors"
	"github.com/redis/go-redis/v9"

	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/time"
)

type (
	bondingCurveUpdate struct {
		ExternalAddress              string     `json:"external_address"`
		Type                         string     `json:"type"`
		BondingCurveMigrated         bool       `json:"bonding_curve_migrated"`
		BondingCurveCurrentAmount    string     `json:"bonding_curve_current_amount"`
		BondingCurveGoalAmount       string     `json:"bonding_curve_goal_amount"`
		BondingCurveRaisedAmount     string     `json:"bonding_curve_raised_amount"`
		BondingCurveCurrentAmountUSD float64    `json:"bonding_curve_current_amount_usd"`
		BondingCurveGoalAmountUSD    float64    `json:"bonding_curve_goal_amount_usd"`
		LiquidityUSD                 float64    `json:"liquidity_usd"`
		UpdatedAt                    *time.Time `json:"updated_at"`
	}
)

func (t *tokenAnalytics) startBondingCurveNotifier(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				log.Info("Bonding curve notifier stopped due to context cancellation")
				return
			default:
			}

			if err := t.listenBondingCurveUpdates(ctx); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					log.Info("Bonding curve notifier stopped due to context cancellation")
					return
				}
				log.Error(errors.Wrap(err, "bonding curve notifier error, restarting immediately"))
			}
		}
	}()

	log.Info(fmt.Sprintf("Bonding curve notifier starting, subscribing to %s notifications", tokenBondingCurveUpdatesChannel))
}

func (t *tokenAnalytics) listenBondingCurveUpdates(ctx context.Context) error {
	listener, err := t.ingestedDataDB.Listen(ctx, tokenBondingCurveUpdatesChannel)
	if err != nil {
		return errors.Wrapf(err, "failed to create listener for %s", tokenBondingCurveUpdatesChannel)
	}
	defer listener.Close()

	myPID := listener.BackendPID()
	log.Info(fmt.Sprintf("Successfully subscribed to %s pg channel (backend PID: %d)", tokenBondingCurveUpdatesChannel, myPID))
	ch := listener.Channel()

	for {
		select {
		case <-ctx.Done():
			log.Info("Bonding curve notifier stopped due to context cancellation")

			return nil

		case notification, ok := <-ch:
			if !ok {
				if err := listener.Err(); err != nil {
					return errors.Wrapf(err, "listener pg channel closed due to error")
				}

				return errors.New("listener pg channel closed normally")
			}
			if notification.PID == myPID {
				log.Debug(fmt.Sprintf("Ignoring self-notification from backend PID %d for bonding curve update", myPID))

				continue
			}
			if err := t.handleBondingCurveUpdate(ctx, notification.Payload); err != nil {
				log.Error(errors.Wrapf(err, "failed to handle bonding curve update notification: %s", notification.Payload))
			}
		}
	}
}

func (t *tokenAnalytics) handleBondingCurveUpdate(ctx context.Context, payload string) error {
	var update bondingCurveUpdate
	if err := json.Unmarshal([]byte(payload), &update); err != nil {
		return errors.Wrapf(err, "failed to unmarshal bonding curve update payload: %s", payload)
	}

	log.Debug(fmt.Sprintf("Received bonding curve update notification: token=%s, migrated=%v",
		update.ExternalAddress, update.BondingCurveMigrated))

	if !update.BondingCurveMigrated {
		currentAmountBig := new(big.Int)
		if _, ok := currentAmountBig.SetString(update.BondingCurveCurrentAmount, 10); ok {
			currentAmountWei := new(big.Float).SetInt(currentAmountBig)
			currentAmountScore, _ := currentAmountWei.Float64()

			if err := t.processedDataDB.ZAdd(ctx, globalBondingCurveProgressSetKey, redis.Z{
				Score:  currentAmountScore,
				Member: update.ExternalAddress,
			}).Err(); err != nil {
				return errors.Wrap(err, "failed to update bonding curve progress in Redis")
			}

			if update.Type != "" {
				if typeSpecificKey := getBondingCurveProgressSetKeyByType(update.Type); typeSpecificKey != "" {
					if err := t.processedDataDB.ZAdd(ctx, typeSpecificKey, redis.Z{
						Score:  currentAmountScore,
						Member: update.ExternalAddress,
					}).Err(); err != nil {
						return errors.Wrapf(err, "failed to update type-specific bonding curve progress in Redis for type %s", update.Type)
					}
				}
				if update.Type == TokenTypePost || update.Type == TokenTypeVideo || update.Type == TokenTypeArticle {
					if err := t.processedDataDB.ZAdd(ctx, globalBondingCurveProgressAnyPostSetKey, redis.Z{
						Score:  currentAmountScore,
						Member: update.ExternalAddress,
					}).Err(); err != nil {
						return errors.Wrap(err, "failed to update anyPost bonding curve progress in Redis")
					}
				}
			}
		}
	} else {
		if err := t.processedDataDB.ZRem(ctx, globalBondingCurveProgressSetKey, update.ExternalAddress).Err(); err != nil {
			return errors.Wrap(err, "failed to remove token from bonding curve progress in Redis")
		}
		if update.Type != "" {
			if typeSpecificKey := getBondingCurveProgressSetKeyByType(update.Type); typeSpecificKey != "" {
				if err := t.processedDataDB.ZRem(ctx, typeSpecificKey, update.ExternalAddress).Err(); err != nil {
					return errors.Wrapf(err, "failed to remove token from type-specific bonding curve progress in Redis for type %s", update.Type)
				}
			}
			if update.Type == TokenTypePost || update.Type == TokenTypeVideo || update.Type == TokenTypeArticle {
				if err := t.processedDataDB.ZRem(ctx, globalBondingCurveProgressAnyPostSetKey, update.ExternalAddress).Err(); err != nil {
					return errors.Wrap(err, "failed to remove token from anyPost bonding curve progress in Redis")
				}
			}
		}
	}

	log.Debug(fmt.Sprintf("Updated Redis bonding curve for token %s from notifier", update.ExternalAddress))

	bondingProgress := &BondingCurveProgress{
		CurrentAmount:    update.BondingCurveCurrentAmount,
		GoalAmount:       update.BondingCurveGoalAmount,
		CurrentAmountUSD: update.BondingCurveCurrentAmountUSD,
		GoalAmountUSD:    update.BondingCurveGoalAmountUSD,
		RaisedAmount:     update.BondingCurveRaisedAmount,
		Migrated:         update.BondingCurveMigrated,
		LiquidityUSD:     update.LiquidityUSD,
	}
	t.subscriptions.NotifyBondingCurveProgress(update.ExternalAddress, bondingProgress)

	return nil
}
