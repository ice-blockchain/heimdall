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
)

type (
	tokenPriceUpdate struct {
		ExternalAddress              string  `json:"external_address"`
		ContractAddress              string  `json:"contract_address"`
		PriceUSD                     float64 `json:"price_usd"`
		TotalSupply                  string  `json:"total_supply"`
		LiquidityUSD                 float64 `json:"liquidity_usd"`
		BondingCurveMigrated         bool    `json:"bonding_curve_migrated"`
		BondingCurveCurrentAmount    string  `json:"bonding_curve_current_amount"`
		BondingCurveGoalAmount       string  `json:"bonding_curve_goal_amount"`
		BondingCurveRaisedAmount     string  `json:"bonding_curve_raised_amount"`
		BondingCurveCurrentAmountUSD float64 `json:"bonding_curve_current_amount_usd"`
		BondingCurveGoalAmountUSD    float64 `json:"bonding_curve_goal_amount_usd"`
		UpdatedAt                    float64 `json:"updated_at"`
	}
)

func (t *tokenAnalytics) startPriceNotifier(ctx context.Context) {
	go func() {
		if err := t.listenPriceUpdates(ctx); err != nil {
			log.Error(errors.Wrap(err, "price notifier stopped with error"))
		}
	}()

	log.Info(fmt.Sprintf("Price notifier starting, subscribing to %s notifications", tokenPriceUpdatesChannel))
}

func (t *tokenAnalytics) listenPriceUpdates(ctx context.Context) error {
	listener, err := t.ingestedDataDB.Listen(ctx, tokenPriceUpdatesChannel)
	if err != nil {
		return errors.Wrapf(err, "failed to create listener for %s", tokenPriceUpdatesChannel)
	}
	defer listener.Close()

	myPID := listener.BackendPID()
	log.Info(fmt.Sprintf("Successfully subscribed to %s pg channel (backend PID: %d)", tokenPriceUpdatesChannel, myPID))
	ch := listener.Channel()

	for {
		select {
		case <-ctx.Done():
			log.Info("Price notifier stopped due to context cancellation")

			return nil

		case notification, ok := <-ch:
			if !ok {
				return errors.New("listener pg channel closed")
			}
			if notification.PID == myPID {
				log.Debug(fmt.Sprintf("Ignoring self-notification from backend PID %d for token update", myPID))

				continue
			}
			if err := t.handlePriceUpdate(ctx, notification.Payload); err != nil {
				log.Error(errors.Wrapf(err, "failed to handle price update notification: %s", notification.Payload))
			}
		}
	}
}

func (t *tokenAnalytics) handlePriceUpdate(ctx context.Context, payload string) error {
	var update tokenPriceUpdate
	if err := json.Unmarshal([]byte(payload), &update); err != nil {
		return errors.Wrapf(err, "failed to unmarshal price update payload: %s", payload)
	}

	totalSupplyBig := new(big.Int)
	if _, ok := totalSupplyBig.SetString(update.TotalSupply, 10); !ok {
		return fmt.Errorf("failed to parse total supply: %s", update.TotalSupply)
	}
	totalSupplyFloat := weiToFloat64FromBigInt(totalSupplyBig)
	marketCapUSD := update.PriceUSD * totalSupplyFloat

	log.Debug(fmt.Sprintf("Received price update notification: token=%s, price_usd=%.6f, market_cap_usd=%.2f",
		update.ExternalAddress, update.PriceUSD, marketCapUSD))

	pipeline := t.processedDataDB.TxPipeline()
	pipeline.ZAdd(ctx, globalTopSetKey, redis.Z{
		Score:  marketCapUSD,
		Member: update.ExternalAddress,
	})
	if !update.BondingCurveMigrated {
		currentAmountBig := new(big.Int)
		if _, ok := currentAmountBig.SetString(update.BondingCurveCurrentAmount, 10); ok {
			currentAmountFloat := weiToFloat64FromBigInt(currentAmountBig)
			pipeline.ZAdd(ctx, globalBondingCurveProgressSetKey, redis.Z{
				Score:  currentAmountFloat,
				Member: update.ExternalAddress,
			})
		}
	} else {
		pipeline.ZRem(ctx, globalBondingCurveProgressSetKey, update.ExternalAddress)
	}

	if _, err := pipeline.Exec(ctx); err != nil {
		return errors.Wrap(err, "failed to execute Redis pipeline")
	}

	log.Debug(fmt.Sprintf("Updated Redis from price notifier for token %s: price_usd=%.6f, market_cap_usd=%.2f",
		update.ExternalAddress, update.PriceUSD, marketCapUSD))

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
