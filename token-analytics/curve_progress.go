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
		PairId            string  `db:"pair_id"`
		BaseToken         string  `db:"base_token"`
		TotalSupply       string  `db:"total_supply"`
		PriceModel        string  `db:"price_model"`
		Type              string  `db:"type"`
		FeeSponsorAddress *string `db:"fee_sponsor"`
	}
	pairId, err := storage.Get[pairAndBaseToken](ctx, t.ingestedDataDB, `
		SELECT 
		    t.pair_id,
		    t.base_token,
		    t.total_supply,
		    t.price_model,
		    t."type",
		    t.fee_sponsor
		FROM tokens t WHERE t.external_address = $1`, externalAddress)
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
	m, err := t.toBondingCurveProgressToModel(ctx, progress, pairId.BaseToken, pairId.Type, pairId.PriceModel, pairId.TotalSupply, pairId.FeeSponsorAddress)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to convert bonding curve progress for token %v (base %v): %w", externalAddress, pairId.BaseToken, err)
	}

	return m, pairId.PairId, pairId.BaseToken, nil
}

func (t *tokenAnalytics) SubscribeBondingCurveProgress(ctx context.Context, externalAddress, user string, addToStream func(*BondingCurveProgress, error)) error {
	currentProgress, _, _, err := t.getBondingCurveProgress(ctx, externalAddress)
	if err != nil {
		return errors.Wrapf(err, "failed to get initial bonding curve progress for token %v", externalAddress)
	}
	addToStream(currentProgress, nil)
	updates := t.subscriptions.SubscribeOnBondingCurveProgress(ctx, externalAddress, user)
	go func() {
		defer log.Debug(fmt.Sprintf("bonding curve progress subscriber stopped for %v", externalAddress))
		for {
			select {
			case <-ctx.Done():
				return
			case newCurveProgress, ok := <-updates:
				if !ok {
					return
				}
				addToStream(newCurveProgress, nil)
			}
		}
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

func (t *tokenAnalytics) toBondingCurveProgressToModel(ctx context.Context, progress *bondingcurve.BondingCurveProgress, baseToken, tokenType, priceModel, totalSupply string, feeSponsorAddressPtr *string) (*BondingCurveProgress, error) {
	goalUSD, currentRaisedUSD, err := t.progressToUSD(ctx, progress, baseToken)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to handle base token for goal/raised calculation %v", baseToken)
	}
	liquidityUSD, _, err := t.calculatePriceInUSD(ctx, weiToFloat64FromBigInt(progress.Liquidity), baseToken)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to handle base token for liquidity usd calculation %v", baseToken)
	}
	startPriceUSD, _, err := t.calculatePriceInUSD(ctx, weiToFloat64FromBigInt(progress.StartPrice), baseToken)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to handle base token for start price usd calculation %v", baseToken)
	}
	endPriceUSD, _, err := t.calculatePriceInUSD(ctx, weiToFloat64FromBigInt(progress.EndPrice), baseToken)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to handle base token for end price usd calculation %v", baseToken)
	}
	feeSponsorAddress := ""
	_, feeSponsorId, feeSponsorAddr, err := t.defaultStartTokenParamsForBase(ctx, baseToken, tokenType)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to find bonding curve start token params for type %s and base %s", tokenType, baseToken)
	}
	if feeSponsorAddressPtr != nil {
		feeSponsorAddress = *feeSponsorAddressPtr
	} else {
		feeSponsorAddress = feeSponsorAddr
	}
	return &BondingCurveProgress{
		FeeSponsorAddress: feeSponsorAddress,
		FeeSponsorId:      feeSponsorId,
		CurrentAmount:     progress.SoldTokens.String(),
		GoalAmount:        progress.BondingTokensGoal.String(),
		RaisedAmount:      progress.TokensRaised.String(),
		CurrentAmountUSD:  currentRaisedUSD,
		GoalAmountUSD:     goalUSD,
		Migrated:          progress.Migrated,
		LiquidityUSD:      liquidityUSD,
		StartTokenParams: &StartTokenParams{
			BondingCurveAlgAddress: priceModel,
			InitialPrice:           progress.StartPrice.String(),
			InitialPriceUSD:        startPriceUSD,
			FinalPrice:             progress.EndPrice.String(),
			FinalPriceUSD:          endPriceUSD,
			EmissionVolume:         totalSupply,
		},
	}, nil
}
