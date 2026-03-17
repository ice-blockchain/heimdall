// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"strings"
	stdlibtime "time"

	"github.com/cockroachdb/errors"
	"github.com/redis/go-redis/v9"

	"github.com/ice-blockchain/wintr/log"
)

type (
	bondingCurveUpdate struct {
		FeeSponsor                   *string `json:"fee_sponsor"`
		ExternalAddress              string  `json:"external_address"`
		ContractAddress              string  `json:"contract_address"`
		Type                         string  `json:"type"`
		Platform                     string  `json:"platform"`
		BondingCurveCurrentAmount    string  `json:"bonding_curve_current_amount"`
		BondingCurveGoalAmount       string  `json:"bonding_curve_goal_amount"`
		BondingCurveRaisedAmount     string  `json:"bonding_curve_raised_amount"`
		BondingCurveCurrentAmountUSD float64 `json:"bonding_curve_current_amount_usd"`
		BondingCurveGoalAmountUSD    float64 `json:"bonding_curve_goal_amount_usd"`
		LiquidityUSD                 float64 `json:"liquidity_usd"`
		StartPrice                   string  `json:"start_price"`
		EndPrice                     string  `json:"end_price"`
		TotalSupply                  string  `json:"total_supply"`
		PriceModel                   string  `json:"price_model"`
		BaseToken                    string  `json:"base_token"`
		UpdatedAt                    int64   `json:"updated_at"`
		BondingCurveMigrated         bool    `json:"bonding_curve_migrated"`
		PriceUSD                     float64 `json:"price_usd"` // TODO
	}
)

func (t *tokenAnalytics) startBondingCurveNotifier(ctx context.Context) {
	log.Info(fmt.Sprintf("Bonding curve notifier starting, subscribing to %s notifications", tokenBondingCurveUpdatesChannel))

	go func() {
		if err := t.listenBondingCurveUpdates(ctx); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				log.Info("Bonding curve notifier stopped due to context cancellation")
				return
			}
			log.Error(errors.Wrap(err, "bonding curve notifier initial start failed, starting retry loop"))

			retryWithBackoff(ctx, "Bonding curve notifier", t.listenBondingCurveUpdates)
		}
	}()
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
			if update.Platform == PlatformGroupXCom {
				if err := t.processedDataDB.ZAdd(ctx, globalBondingCurveProgressXcomSetKey, redis.Z{
					Score:  currentAmountScore,
					Member: update.ExternalAddress,
				}).Err(); err != nil {
					return errors.Wrap(err, "failed to update xcom bonding curve progress in Redis")
				}
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
				if IsContentType(update.Type) {
					if err := t.processedDataDB.ZAdd(ctx, globalBondingCurveProgressAnyPostSetKey, redis.Z{
						Score:  currentAmountScore,
						Member: update.ExternalAddress,
					}).Err(); err != nil {
						return errors.Wrap(err, "failed to update anyPost bonding curve progress in Redis")
					}
				}
			}
			if update.Platform == PlatformGroupIonConnect && update.Type == TokenTypeProfile {
				if err := t.processedDataDB.ZAdd(ctx, globalBondingCurveProgressOnlinePlusCreatorSetKey, redis.Z{
					Score:  currentAmountScore,
					Member: update.ExternalAddress,
				}).Err(); err != nil {
					return errors.Wrap(err, "failed to update onlineplus_creator bonding curve progress in Redis")
				}
			}
			if update.Platform == PlatformGroupIonConnect && IsContentType(update.Type) {
				if err := t.processedDataDB.ZAdd(ctx, globalBondingCurveProgressOnlinePlusContentSetKey, redis.Z{
					Score:  currentAmountScore,
					Member: update.ExternalAddress,
				}).Err(); err != nil {
					return errors.Wrap(err, "failed to update onlineplus_content bonding curve progress in Redis")
				}
			}
		}
	} else {
		if err := t.processedDataDB.ZRem(ctx, globalBondingCurveProgressSetKey, update.ExternalAddress).Err(); err != nil {
			return errors.Wrap(err, "failed to remove token from bonding curve progress in Redis")
		}
		if update.Platform == PlatformGroupXCom {
			if err := t.processedDataDB.ZRem(ctx, globalBondingCurveProgressXcomSetKey, update.ExternalAddress).Err(); err != nil {
				return errors.Wrap(err, "failed to remove token from xcom bonding curve progress in Redis")
			}
		}
		if update.Type != "" {
			if typeSpecificKey := getBondingCurveProgressSetKeyByType(update.Type); typeSpecificKey != "" {
				if err := t.processedDataDB.ZRem(ctx, typeSpecificKey, update.ExternalAddress).Err(); err != nil {
					return errors.Wrapf(err, "failed to remove token from type-specific bonding curve progress in Redis for type %s", update.Type)
				}
			}
			if IsContentType(update.Type) {
				if err := t.processedDataDB.ZRem(ctx, globalBondingCurveProgressAnyPostSetKey, update.ExternalAddress).Err(); err != nil {
					return errors.Wrap(err, "failed to remove token from anyPost bonding curve progress in Redis")
				}
			}
		}
		if update.Platform == PlatformGroupIonConnect && update.Type == TokenTypeProfile {
			if err := t.processedDataDB.ZRem(ctx, globalBondingCurveProgressOnlinePlusCreatorSetKey, update.ExternalAddress).Err(); err != nil {
				return errors.Wrap(err, "failed to remove token from onlineplus_creator bonding curve progress in Redis")
			}
		}
		if update.Platform == PlatformGroupIonConnect && IsContentType(update.Type) {
			if err := t.processedDataDB.ZRem(ctx, globalBondingCurveProgressOnlinePlusContentSetKey, update.ExternalAddress).Err(); err != nil {
				return errors.Wrap(err, "failed to remove token from onlineplus_content bonding curve progress in Redis")
			}
		}
	}

	p, ok := t.cfg.BondingCurve.CreateTokenDefaults[update.Type]
	if !ok {
		return errors.Errorf("token type %s not found in bonding curve config", update.Type)
	}
	feeSponsor := ""
	if update.FeeSponsor != nil {
		feeSponsor = *update.FeeSponsor
	} else {
		feeSponsor = p.FeeSponsorAddress
	}

	log.Debug(fmt.Sprintf("Updated Redis bonding curve for token %s from notifier", update.ExternalAddress))
	startPrice, ok := new(big.Int).SetString(update.StartPrice, 10)
	if !ok {
		return errors.Errorf("malformed startPrice %v", update.StartPrice)
	}
	startPriceUSD, _, err := t.calculatePriceInUSD(ctx, weiToFloat64FromBigInt(startPrice), update.BaseToken)
	if err != nil {
		return errors.Wrapf(err, "failed to handle base token for start price usd calculation %v", update.BaseToken)
	}
	endPrice, ok := new(big.Int).SetString(update.EndPrice, 10)
	if !ok {
		return errors.Errorf("malformed endPrice %v", update.EndPrice)
	}
	endPriceUSD, _, err := t.calculatePriceInUSD(ctx, weiToFloat64FromBigInt(endPrice), update.BaseToken)
	if err != nil {
		return errors.Wrapf(err, "failed to handle base token for end price usd calculation %v", update.BaseToken)
	}
	bondingProgress := &BondingCurveProgress{
		FeeSponsorAddress: feeSponsor,
		FeeSponsorId:      p.FeeSponsorId,
		CurrentAmount:     update.BondingCurveCurrentAmount,
		GoalAmount:        update.BondingCurveGoalAmount,
		RaisedAmount:      update.BondingCurveRaisedAmount,
		CurrentAmountUSD:  update.BondingCurveCurrentAmountUSD,
		GoalAmountUSD:     update.BondingCurveGoalAmountUSD,
		Migrated:          update.BondingCurveMigrated,
		LiquidityUSD:      update.LiquidityUSD,
		StartTokenParams: &StartTokenParams{
			BondingCurveAlgAddress: update.PriceModel,
			InitialPrice:           update.StartPrice,
			InitialPriceUSD:        startPriceUSD,
			FinalPrice:             update.EndPrice,
			FinalPriceUSD:          endPriceUSD,
			EmissionVolume:         update.TotalSupply,
		},
	}
	t.subscriptions.NotifyBondingCurveProgress(update.ExternalAddress, bondingProgress)

	if update.Type == TokenTypeProfile {
		t.creatorTokenPricesUSD.Store(strings.ToLower(update.ContractAddress), update.PriceUSD)
		ionPriceUSD := t.ionPriceUSD.Load()
		if ionPriceUSD != nil && *ionPriceUSD > 0 {
			priceInION := update.PriceUSD / *ionPriceUSD
			priceInIONWei := new(big.Int).SetUint64(uint64(priceInION * 1e18))
			t.creatorTokenPricesION.Store(strings.ToLower(update.ContractAddress), priceInIONWei)
		}
	}

	return nil
}

func retryWithBackoff(ctx context.Context, name string, fn func(context.Context) error) {
	const (
		initialBackoff = 1 * stdlibtime.Second
		maxBackoff     = 60 * stdlibtime.Second
		backoffFactor  = 2.0
		jitterFraction = 0.2
	)

	backoff := initialBackoff
	consecutiveErrors := 0

	for {
		select {
		case <-ctx.Done():
			log.Info(name + " stopped due to context cancellation")

			return
		default:
		}

		err := fn(ctx)
		if err == nil {
			log.Info(name + " stopped normally")

			return
		}

		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			log.Info(name + " stopped due to context cancellation")

			return
		}

		consecutiveErrors++
		if consecutiveErrors <= 3 || consecutiveErrors%10 == 0 {
			log.Error(errors.Wrapf(err, "%s error (consecutive: %d), retrying after %v", name, consecutiveErrors, backoff))
		}
		jitter := stdlibtime.Duration(float64(backoff) * jitterFraction * (rand.Float64()*2 - 1))
		sleep := backoff + jitter

		select {
		case <-ctx.Done():
			return
		case <-stdlibtime.After(sleep):
		}

		backoff = stdlibtime.Duration(float64(backoff) * backoffFactor)
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}
