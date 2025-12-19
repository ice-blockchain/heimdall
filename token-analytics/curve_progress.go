// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	stdlibtime "time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) GetBondingCurveProgress(ctx context.Context, externalAddress string) (*BondingCurveProgress, error) {
	p, _, err := t.getBondingCurveProgress(ctx, externalAddress)
	return p, err
}
func (t *tokenAnalytics) getBondingCurveProgress(ctx context.Context, externalAddress string) (*BondingCurveProgress, string, error) {
	pairId, err := storage.Get[string](ctx, t.ingestedDataDB, `
		SELECT t.pair_id FROM tokens t WHERE t.external_address = $1`, externalAddress)
	if err != nil {
		return nil, "", fmt.Errorf("failed to find token by external address %v: %w", externalAddress, err)
	}
	if pairId == nil {
		return nil, "", fmt.Errorf("token %v not found", externalAddress)
	}
	progress, err := t.bondingCurve.Progress(ctx, common.HexToHash(*pairId))
	if err != nil {
		return nil, "", fmt.Errorf("failed to get curve progress for token %v (pair %v): %w", externalAddress, pairId, err)
	}
	basePrice := t.ionPriceUSD.Load()
	return toModel(progress, *basePrice), *pairId, nil
}

func (t *tokenAnalytics) SubscribeBondingCurveProgress(ctx context.Context, externalAddress string, addToStream func(*BondingCurveProgress, error)) error {
	currentProgress, pairId, err := t.getBondingCurveProgress(ctx, externalAddress)
	if err != nil {
		return errors.Wrapf(err, "failed to get initial bonding curve progress for token %v", externalAddress)
	}
	addToStream(currentProgress, nil)
	updates, hasAtLeastOneSubscriptionForToken, stopUpdater := t.subscriptions.SubscribeOnBondingCurveProgress(ctx, externalAddress)

	if !hasAtLeastOneSubscriptionForToken {
		if err = t.startBondingCurveProgressUpdater(stopUpdater, externalAddress, pairId); err != nil {
			return errors.Wrapf(err, "failed to start bonding curve progress updater for %v", externalAddress)
		}
	}
	go func() {
		for ctx.Err() == nil {
			newCurveProgress, ok := <-updates
			if !ok {
				return
			}
			addToStream(newCurveProgress, nil)
		}
		fmt.Println("bonding curve progress updater stopped")
	}()
	return nil
}

func progressToUSD(progress *bondingcurve.BondingCurveProgress, basePrice float64) (float64, float64) {
	goalUSD := toUSD(progress.BondingTokensGoal, basePrice)
	currentRaisedUSD := toUSD(progress.TokensRaised, basePrice)
	return goalUSD, currentRaisedUSD
}

func (t *tokenAnalytics) startBondingCurveProgressUpdater(stop <-chan struct{}, externalAddress, pairId string) error {
	ticker := stdlibtime.NewTicker(t.cfg.BondingCurve.BondingCurveProgressUpdateFrequency)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				updateCtx, updateCancel := context.WithTimeout(context.Background(), 30*stdlibtime.Second)
				if err := t.updateBondingProgress(updateCtx, externalAddress, pairId); err != nil {
					log.Error(fmt.Errorf("failed to update bonding curve progress in background: %w", err))
				}
				updateCancel()
			}
		}
	}()
	return nil
}

func (t *tokenAnalytics) updateBondingProgress(ctx context.Context, externalAddress, pairId string) error {
	log.Debug(fmt.Sprintf("updating bonding curve progress for %v", externalAddress))
	progress, err := t.bondingCurve.Progress(ctx, common.HexToHash(pairId))
	if err != nil {
		return fmt.Errorf("failed to get bonding curve progress for token %v (pair %v): %w", externalAddress, pairId, err)
	}
	basePriceInUsd := t.ionPriceUSD.Load()

	goalUSD, currentRaisedUSD := progressToUSD(progress, *basePriceInUsd)
	liquidityUSD := toUSD(progress.Liquidity, *basePriceInUsd)
	_, err = storage.Exec(ctx, t.ingestedDataDB, `
		UPDATE tokens AS t
		SET
		    bonding_curve_current_amount = $2,
		    bonding_curve_raised_amount = $3,
		    bonding_curve_goal_amount = $4,
		    bonding_curve_current_amount_usd = $5,
		    bonding_curve_goal_amount_usd = $6,
		    bonding_curve_migrated = $7,
		    liquidity_usd = $8,
			updated_at = NOW()
		WHERE t.external_address = $1`, externalAddress, progress.SoldTokens, progress.TokensRaised, progress.BondingTokensGoal, currentRaisedUSD, goalUSD, progress.Migrated, liquidityUSD)
	if err != nil {
		return fmt.Errorf("failed to update bonding curve for token %v: %w", externalAddress, err)
	}
	t.subscriptions.NotifyBondingCurveProgress(externalAddress, toModel(progress, *basePriceInUsd))
	return nil
}

func toModel(progress *bondingcurve.BondingCurveProgress, basePriceInUsd float64) *BondingCurveProgress {
	goalUSD, currentRaisedUSD := progressToUSD(progress, basePriceInUsd)
	return &BondingCurveProgress{
		GoalAmount:       progress.BondingTokensGoal.String(),
		CurrentAmount:    progress.SoldTokens.String(),
		GoalAmountUSD:    goalUSD,
		CurrentAmountUSD: currentRaisedUSD,
		Migrated:         progress.Migrated,
		RaisedAmount:     progress.TokensRaised.String(),
		LiquidityUSD:     toUSD(progress.Liquidity, basePriceInUsd),
	}
}
