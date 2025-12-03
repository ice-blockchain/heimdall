// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"math/big"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) onRecipientsSet(ctx context.Context, tx *txEvent, ev *bondingcurve.LogRecipientsSet) error {
	log.Debug(fmt.Sprintf("Recipients set: pairId=%x, creator=%s, tx=%s", ev.PairId, ev.Creator.Hex(), tx.TransactionHash))

	return nil
}

func (t *tokenAnalytics) onMigrated(ctx context.Context, tx *txEvent, ev *bondingcurve.LogMigrated) error {
	log.Debug(fmt.Sprintf("Migrated: pairId=%x, tx=%s", ev.PairId, tx.TransactionHash))

	return nil
}

func (t *tokenAnalytics) onFeeAccrued(ctx context.Context, tx *txEvent, ev *bondingcurve.LogFeeAccrued) error {
	log.Debug(fmt.Sprintf("Fee accrued: pairId=%x, tx=%s", ev.PairId, tx.TransactionHash))

	return nil
}

func (t *tokenAnalytics) onFeeTransfer(ctx context.Context, tx *txEvent, ev *bondingcurve.LogFeeTransfer) error {
	log.Debug(fmt.Sprintf("Fee transfer: pairId=%x, tx=%s", ev.PairId, tx.TransactionHash))

	return nil
}

func (t *tokenAnalytics) onLiquidityClaimed(ctx context.Context, tx *txEvent, ev *bondingcurve.LogLiquidityClaimed) error {
	log.Debug(fmt.Sprintf("Liquidity claimed: pairId=%x, tx=%s", ev.PairId, tx.TransactionHash))

	return nil
}

func (t *tokenAnalytics) onSlippageChecked(ctx context.Context, tx *txEvent, ev *bondingcurve.LogSlippageChecked) error {
	log.Debug(fmt.Sprintf("Slippage checked: pairId=%x, tx=%s", ev.PairId, tx.TransactionHash))

	return nil
}

func (t *tokenAnalytics) onLiquidityLocked(ctx context.Context, tx *txEvent, ev *bondingcurve.LogLiquidityLocked) error {
	log.Debug(fmt.Sprintf("Liquidity locked: pairId=%x, tx=%s", ev.PairId, tx.TransactionHash))

	return nil
}

func (t *tokenAnalytics) onFeeWaived(ctx context.Context, tx *txEvent, ev *bondingcurve.LogFeeWaived) error {
	log.Debug(fmt.Sprintf("Fee waived: pairId=%x, tx=%s", ev.PairId, tx.TransactionHash))

	return nil
}

func (t *tokenAnalytics) onRefundIssued(ctx context.Context, tx *txEvent, ev *bondingcurve.LogRefundIssued) error {
	log.Debug(fmt.Sprintf("Refund issued: pairId=%x, tx=%s", ev.PairId, tx.TransactionHash))

	return nil
}

func (t *tokenAnalytics) onRouteSelected(ctx context.Context, tx *txEvent, ev *bondingcurve.LogRouteSelected) error {
	log.Debug(fmt.Sprintf("Route selected: pairId=%x, tx=%s", ev.PairId, tx.TransactionHash))

	return nil
}

func (t *tokenAnalytics) onVerificationChecked(ctx context.Context, tx *txEvent, ev *bondingcurve.LogVerificationChecked) error {
	log.Debug(fmt.Sprintf("Verification checked: user=%s, verified=%t, tx=%s", ev.User.Hex(), ev.Verified, tx.TransactionHash))

	return nil
}

func (t *tokenAnalytics) onPairRegistered(ctx context.Context, tx *txEvent, ev *bondingcurve.LogPairRegistered) error {
	log.Debug(fmt.Sprintf("Pair registered: pairId=%x, baseToken=%s, otherToken=%s, tx=%s", ev.PairId, ev.BaseToken.Hex(), ev.OtherToken.Hex(), tx.TransactionHash))

	return nil
}

func bigIntToFloat(val *big.Int) float64 {
	if val == nil {
		return 0
	}
	f := new(big.Float).SetInt(val)
	divisor := new(big.Float).SetFloat64(1e18)
	f.Quo(f, divisor)
	result, _ := f.Float64()
	return result
}
