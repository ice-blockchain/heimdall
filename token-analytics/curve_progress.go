// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	stdlibtime "time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/time"
)

func (t *tokenAnalytics) GetBondingCurveProgress(ctx context.Context, externalAddress string) (*BondingCurveProgress, error) {
	type tokenInfo struct {
		PairId string `db:"pair_id"`
	}
	result, err := storage.Get[tokenInfo](ctx, t.ingestedDataDB, `
		SELECT t.pair_id FROM tokens t WHERE t.external_address = $1`, externalAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to find token by external address %v: %w", externalAddress, err)
	}
	progress, err := t.bondingCurve.Progress(ctx, common.HexToHash(result.PairId))
	if err != nil {
		return nil, fmt.Errorf("failed to get curve progress for token %v (pair %v): %w", externalAddress, result.PairId, err)
	}
	basePrice := t.ionPriceUSD.Load()
	return toModel(progress, *basePrice), nil
}

func (t *tokenAnalytics) SubscribeBondingCurveProgress(ctx context.Context, externalAddress string, addToStream func(*BondingCurveProgress, error)) error {
	currentProgress, err := t.GetBondingCurveProgress(ctx, externalAddress)
	if err != nil {
		return errors.Wrapf(err, "failed to get initial bonding curve ptogress for token %v", externalAddress)
	}
	addToStream(currentProgress, nil)
	updates := t.subscriptions.SubscribeOnBondingCurveProgress(externalAddress)
	go func() {
		for newCurveProgress := range updates {
			addToStream(newCurveProgress, nil)
		}
	}()
	return nil
}

func progressToUSD(progress *bondingcurve.BondingCurveProgress, basePrice float64) (float64, float64) {
	toTokensGoal := new(big.Float).Quo(new(big.Float).SetInt(progress.BondingTokensGoal), big.NewFloat(1e18))
	goalUSDBig := new(big.Float).Mul(toTokensGoal, big.NewFloat(basePrice))
	goalUSD, _ := goalUSDBig.Float64()
	toTokensRaised := new(big.Float).Quo(new(big.Float).SetInt(progress.TokensRaised), big.NewFloat(1e18))
	currentRaisedUSDBig := new(big.Float).Mul(toTokensRaised, big.NewFloat(basePrice))
	currentRaisedUSD, _ := currentRaisedUSDBig.Float64()
	return goalUSD, currentRaisedUSD
}

func (t *tokenAnalytics) bondingCurveProgressUpdater(ctx context.Context) {
	ticker := stdlibtime.NewTicker(500 * stdlibtime.Millisecond)
	go func() {
		defer ticker.Stop()
		for ctx.Err() == nil {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				updateCtx, updateCancel := context.WithTimeout(ctx, 30*stdlibtime.Second)
				if err := t.updateBondingProgress(updateCtx); err != nil {
					log.Error(fmt.Errorf("failed to update bonding curve progress in background: %w", err))
				}
				updateCancel()
			}
		}
	}()
}

type progressResult struct {
	*bondingcurve.BondingCurveProgress
	ContractAddress string
}

func (t *tokenAnalytics) updateBondingProgress(ctx context.Context) error {
	now := time.Now()
	type tokenToUpdate struct {
		ContractAddress string `db:"contract_address"`
		PairID          string `db:"pair_id"`
		ExternalAddress string `db:"external_address"`
	}
	tokens, err := storage.Select[tokenToUpdate](ctx, t.ingestedDataDB, `
		SELECT contract_address, pair_id, external_address FROM tokens 
		WHERE NOT (contract_address LIKE '0xdeadbeef%') -- TODO: remove with dummy inserter
		ORDER BY updated_at DESC 
		LIMIT $1`, t.cfg.ConcurrentBondingCurveUpdates)
	if err != nil {
		return fmt.Errorf("failed to select tokens for bonding curve progress update: %w", err)
	}
	if len(tokens) == 0 {
		return nil
	}

	var eg errgroup.Group
	res := make(chan progressResult, t.cfg.ConcurrentBondingCurveUpdates)
	for _, token := range tokens {
		eg.Go(func() error {
			p, e := t.bondingCurve.Progress(ctx, common.HexToHash(token.PairID))
			res <- progressResult{
				BondingCurveProgress: p,
				ContractAddress:      token.ContractAddress,
			}
			return e
		})
	}
	if err = eg.Wait(); err != nil {
		return fmt.Errorf("failed to fetch tokens bonding curve progress: %w", err)
	}
	close(res)
	progressResults := make(map[string]progressResult, len(res))
	for r := range res {
		progressResults[r.ContractAddress] = r
	}
	basePriceInUsd := t.ionPriceUSD.Load()
	params := []any{now}
	placeholders, extraParams := t.buildBondingCurveProgressUpdate(now, *basePriceInUsd, progressResults)
	params = append(params, extraParams...)

	query := fmt.Sprintf(`
		UPDATE tokens AS t
		SET
		    bonding_curve_current_amount = v.bonding_curve_current_amount,
		    bonding_curve_raised_amount = v.bonding_curve_raised_amount,
		    bonding_curve_goal_amount = v.bonding_curve_goal_amount,
		    bonding_curve_current_amount_usd = v.bonding_curve_current_amount_usd,
		    bonding_curve_goal_amount_usd = v.bonding_curve_goal_amount_usd,
		    bonding_curve_migrated = v.bonding_curve_migrated,
			updated_at = $1
		FROM (VALUES %v) AS v(contract_address, bonding_curve_current_amount, bonding_curve_raised_amount, bonding_curve_goal_amount, bonding_curve_current_amount_usd, bonding_curve_goal_amount_usd, bonding_curve_migrated)
		WHERE t.contract_address = v.contract_address
	`, placeholders)

	updated, err := storage.Exec(ctx, t.ingestedDataDB, query, params...)
	if updated != uint64(len(tokens)) && err == nil {
		err = errors.Errorf("expected to update %v tokens, but updated only %v (%v)", len(tokens), updated, func() string {
			ids := ""
			for _, t := range tokens {
				ids += fmt.Sprintf("%v,", t.ContractAddress)
			}
			return ids
		}())
	}
	if err != nil {
		return fmt.Errorf("failed to batch update bonding curves for tokens %v: %w", func() string {
			ids := ""
			for _, t := range tokens {
				ids += fmt.Sprintf("%v,", t.ContractAddress)
			}
			return ids
		}(), err)
	}
	for _, token := range tokens {
		progressRes := progressResults[token.ContractAddress]
		t.subscriptions.NotifyBondingCurveProgress(token.ExternalAddress, toModel(progressRes.BondingCurveProgress, *basePriceInUsd))
	}
	return nil
}

func toModel(progress *bondingcurve.BondingCurveProgress, basePriceInUsd float64) *BondingCurveProgress {
	goalUSD, currentRaisedUSD := progressToUSD(progress, basePriceInUsd)
	return &BondingCurveProgress{
		GoalAmount:       weiToUint64FromBigInt(progress.BondingTokensGoal),
		CurrentAmount:    weiToUint64FromBigInt(progress.SoldTokens), // bonded tokens
		GoalAmountUSD:    goalUSD,
		CurrentAmountUSD: currentRaisedUSD,
		Migrated:         progress.Migrated,
		RaisedAmount:     weiToUint64FromBigInt(progress.TokensRaised), // base tokens
	}
}

func (t *tokenAnalytics) buildBondingCurveProgressUpdate(now *time.Time, basePriceInUsd float64, progress map[string]progressResult) (sql string, params []any) {
	placeholders := make([]string, 0, len(progress))
	idx := 2
	params = make([]any, 0, len(progress)*7)
	for _, res := range progress {
		goalUSD, currentRaisedUSD := progressToUSD(res.BondingCurveProgress, basePriceInUsd)
		// TODO: liquidity_usd, once progress will return it
		params = append(params, res.ContractAddress, res.SoldTokens, res.TokensRaised, res.BondingTokensGoal, currentRaisedUSD, goalUSD, res.Migrated)
		placeholders = append(placeholders, fmt.Sprintf(""+
			"(                  $%[1]v,                $%[2]v::uint256, $%[3]v::uint256, $%[4]v::uint256,     $%[5]v::usd_amount,  $%[6]v::usd_amount,  $%[7]v::BOOLEAN)", idx, idx+1, idx+2, idx+3, idx+4, idx+5, idx+6))
		idx += 7
	}
	return strings.Join(placeholders, ", \n"), params
}
