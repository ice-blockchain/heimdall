// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"math/big"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/wintr/log"
)

func (t *tokenAnalytics) getMasterPubkeyByAddress(ctx context.Context, blockchainAddr string) (string, error) {
	// TODO: Implement extraction of master_pubkey from transaction.
	return blockchainAddr, nil
}

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

func (t *tokenAnalytics) onTransfer(ctx context.Context, tx *txEvent, ev *bondingcurve.LogTransfer) error {
	log.Info(fmt.Sprintf("Transfer: from=%v, to=%v, amount=%v, tx:%v",
		ev.From.String(), ev.To.String(), ev.Amount, tx.TransactionHash))

	return nil
}

func (t *tokenAnalytics) onOwnershipTransferred(ctx context.Context, tx *txEvent, ev *bondingcurve.LogOwnershipTransferred) error {
	log.Info(fmt.Sprintf("OwnershipTransferred: from=%v, to=%v, tx:%v",
		ev.PreviousOwner.String(), ev.NewOwner.String(), tx.TransactionHash))

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
