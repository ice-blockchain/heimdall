// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"

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
	currentProgress, _, _, err := t.getBondingCurveProgress(ctx, externalAddress)
	if err != nil {
		return errors.Wrapf(err, "failed to get initial bonding curve progress for token %v", externalAddress)
	}
	addToStream(currentProgress, nil)
	updates, _, _ := t.subscriptions.SubscribeOnBondingCurveProgress(ctx, externalAddress)
	go func() {
		for ctx.Err() == nil {
			newCurveProgress, ok := <-updates
			if !ok {
				return
			}
			addToStream(newCurveProgress, nil)
		}
		log.Debug(fmt.Sprintf("bonding curve progress subscriber stopped for %v", externalAddress))
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

func (t *tokenAnalytics) toBondingCurveProgressToModel(ctx context.Context, progress *bondingcurve.BondingCurveProgress, baseToken string) (*BondingCurveProgress, error) {
	goalUSD, currentRaisedUSD, err := t.progressToUSD(ctx, progress, baseToken)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to handle base token %v", baseToken)
	}
	liquidityUSD, _, err := t.calculatePriceInUSD(ctx, weiToFloat64FromBigInt(progress.Liquidity), baseToken)
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
		LiquidityUSD:     liquidityUSD,
	}, nil
}
