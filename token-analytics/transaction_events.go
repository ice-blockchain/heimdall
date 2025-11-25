// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"math/big"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) onRecipientsSet(ctx context.Context, tx *txEvent, ev *bondingcurve.LogRecipientsSet) error {
	log.Info("Recipients set:%+v, tx:%v", ev, tx.TransactionHash)

	return nil
}

func (t *tokenAnalytics) onMigrated(ctx context.Context, tx *txEvent, ev *bondingcurve.LogMigrated) error {
	log.Info("Migrated:%+v, tx:%v", ev, tx.TransactionHash)

	return nil
}

func (t *tokenAnalytics) onFeeAccrued(ctx context.Context, tx *txEvent, ev *bondingcurve.LogFeeAccrued) error {
	log.Info("Fee accrued:%+v, tx:%v", ev, tx.TransactionHash)

	return nil
}

func (t *tokenAnalytics) onFeeTransfer(ctx context.Context, tx *txEvent, ev *bondingcurve.LogFeeTransfer) error {
	log.Info("Fee transfer:%+v, tx:%v", ev, tx.TransactionHash)

	return nil
}

func (t *tokenAnalytics) onLiquidityClaimed(ctx context.Context, tx *txEvent, ev *bondingcurve.LogLiquidityClaimed) error {
	log.Info("Liquidity claimed:%+v, tx:%v", ev, tx.TransactionHash)

	return nil
}

func (t *tokenAnalytics) onSlippageChecked(ctx context.Context, tx *txEvent, ev *bondingcurve.LogSlippageChecked) error {
	log.Info("Slippage checked:%+v, tx:%v", ev, tx.TransactionHash)

	return nil
}

func (t *tokenAnalytics) onLiquidityLocked(ctx context.Context, tx *txEvent, ev *bondingcurve.LogLiquidityLocked) error {
	log.Info("Liquidity locked:%+v, tx:%v", ev, tx.TransactionHash)

	return nil
}

func (t *tokenAnalytics) onFeeWaived(ctx context.Context, tx *txEvent, ev *bondingcurve.LogFeeWaived) error {
	log.Info("Fee waived:%+v, tx:%v", ev, tx.TransactionHash)

	return nil
}

func (t *tokenAnalytics) onRefundIssued(ctx context.Context, tx *txEvent, ev *bondingcurve.LogRefundIssued) error {
	log.Info("Refund issued:%+v, tx:%v", ev, tx.TransactionHash)

	return nil
}

func (t *tokenAnalytics) onRouteSelected(ctx context.Context, tx *txEvent, ev *bondingcurve.LogRouteSelected) error {
	log.Info("Route selected:%+v, tx:%v", ev, tx.TransactionHash)

	return nil
}

func (t *tokenAnalytics) onVerificationChecked(ctx context.Context, tx *txEvent, ev *bondingcurve.LogVerificationChecked) error {
	log.Info("Verification checked:%+v, tx:%v", ev, tx.TransactionHash)

	return nil
}

func (t *tokenAnalytics) onPairRegistered(ctx context.Context, tx *txEvent, ev *bondingcurve.LogPairRegistered) error {
	log.Info("Pair registered:%+v, tx:%v", ev, tx.TransactionHash)

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
