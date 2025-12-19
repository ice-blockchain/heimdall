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
	p, _, _, err := t.getBondingCurveProgress(ctx, externalAddress)
	return p, err
}
func (t *tokenAnalytics) getBondingCurveProgress(ctx context.Context, externalAddress string) (*BondingCurveProgress, string, string, error) {
	type pairAndBaseToken struct {
		PairId    string `db:"pair_id"`
		BaseToken string `db:"base_token"`
	}
	pairId, err := storage.Get[pairAndBaseToken](ctx, t.ingestedDataDB, `
		SELECT t.pair_id, t.base_token FROM tokens t WHERE t.external_address = $1`, externalAddress)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to find token by external address %v: %w", externalAddress, err)
	}
	if pairId == nil {
		return nil, "", "", fmt.Errorf("token %v not found", externalAddress)
	}
	progress, err := t.bondingCurve.Progress(ctx, common.HexToHash(pairId.PairId))
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to get curve progress for token %v (pair %v): %w", externalAddress, pairId, err)
	}
	m, err := t.toBondingCurveProgressToModel(ctx, progress, pairId.BaseToken)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to convert bonding curve progress for token %v (base %v): %w", externalAddress, pairId.BaseToken, err)
	}
	return m, pairId.PairId, pairId.BaseToken, nil
}

func (t *tokenAnalytics) SubscribeBondingCurveProgress(ctx context.Context, externalAddress string, addToStream func(*BondingCurveProgress, error)) error {
	currentProgress, pairId, baseToken, err := t.getBondingCurveProgress(ctx, externalAddress)
	if err != nil {
		return errors.Wrapf(err, "failed to get initial bonding curve progress for token %v", externalAddress)
	}
	addToStream(currentProgress, nil)
	updates, hasAtLeastOneSubscriptionForToken, stopUpdater := t.subscriptions.SubscribeOnBondingCurveProgress(ctx, externalAddress)

	if !hasAtLeastOneSubscriptionForToken {
		t.startBondingCurveProgressUpdater(ctx, stopUpdater, externalAddress, pairId, baseToken)
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

func (t *tokenAnalytics) progressToUSD(ctx context.Context, progress *bondingcurve.BondingCurveProgress, baseToken string) (float64, float64, error) {
	goalUSD, _, err := t.calculatePriceInUSD(ctx, weiToFloat64FromBigInt(progress.BondingTokensGoal), baseToken)
	if err != nil {
		return 0, 0, err
	}
	currentRaisedUSD, _, err := t.calculatePriceInUSD(ctx, weiToFloat64FromBigInt(progress.TokensRaised), baseToken)
	if err != nil {
		return 0, 0, err
	}
	return goalUSD, currentRaisedUSD, nil
}

func (t *tokenAnalytics) startBondingCurveProgressUpdater(ctx context.Context, stop <-chan struct{}, externalAddress, pairId, baseToken string) {
	ticker := stdlibtime.NewTicker(t.cfg.BondingCurve.BondingCurveProgressUpdateFrequency)
	go func() {
		defer ticker.Stop()

		log.Info(fmt.Sprintf("Bonding curve progress updater started for %v, updating every %s", externalAddress, t.cfg.BondingCurve.BondingCurveProgressUpdateFrequency))
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				updateCtx, updateCancel := context.WithTimeout(ctx, 30*stdlibtime.Second)
				if _, err := t.updateBondingProgress(updateCtx, externalAddress, pairId, baseToken); err != nil {
					if storage.IsErr(err, storage.ErrReadOnly) {
						log.Warn(fmt.Sprintf("Database is read-only, stopping bonding curve progress updater for token %s", externalAddress))
						updateCancel()
						return
					}
					log.Error(fmt.Errorf("failed to update bonding curve progress in background: %w", err))
				}
				updateCancel()
			}
		}
	}()
}

func (t *tokenAnalytics) updateBondingProgress(ctx context.Context, externalAddress, pairId, baseToken string) (*BondingCurveProgress, error) {
	log.Debug(fmt.Sprintf("updating bonding curve progress for %v", externalAddress))
	progress, err := t.bondingCurve.Progress(ctx, common.HexToHash(pairId))
	if err != nil {
		return nil, fmt.Errorf("failed to get bonding curve progress for token %v (pair %v): %w", externalAddress, pairId, err)
	}

	goalUSD, currentRaisedUSD, err := t.progressToUSD(ctx, progress, baseToken)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate bonding curve progress for token %v: %w", externalAddress, err)
	}
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
		return nil, fmt.Errorf("failed to update bonding curve for token %v: %w", externalAddress, err)
	}
	m, err := t.toBondingCurveProgressToModel(ctx, progress, baseToken)
	if err != nil {
		return nil, fmt.Errorf("failed to update bonding curve for token %v: %w", externalAddress, err)
	}
	t.subscriptions.NotifyBondingCurveProgress(externalAddress, m)
	return m, nil
}

func (t *tokenAnalytics) toBondingCurveProgressToModel(ctx context.Context, progress *bondingcurve.BondingCurveProgress, baseToken string) (*BondingCurveProgress, error) {
	goalUSD, currentRaisedUSD, err := t.progressToUSD(ctx, progress, baseToken)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to handle base token %v", baseToken)
	}
	return &BondingCurveProgress{
		GoalAmount:       progress.BondingTokensGoal.String(),
		CurrentAmount:    progress.SoldTokens.String(),
		GoalAmountUSD:    goalUSD,
		CurrentAmountUSD: currentRaisedUSD,
		Migrated:         progress.Migrated,
		RaisedAmount:     progress.TokensRaised.String(),
		LiquidityUSD:     toUSD(progress.Liquidity, basePriceInUsd),
	},nil
}
