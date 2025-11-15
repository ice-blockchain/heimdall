// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/wintr/log"
	"github.com/pkg/errors"
)

func (t *tokenAnalytics) onTokenCreated(ctx context.Context, tx *txEvent, logEvent *JSON, ev *bondingcurve.LogTokenCreated) error {
	topics, _ := logEvent.getStringSlice("topics")
	address, _ := logEvent.getString("address")

	if len(topics) > 1 {
		ev.Address = common.HexToAddress(topics[1])
	}
	log.Info(fmt.Sprintf("Token created from BondingCurve:%v, token address:%v, tx:%v", address, ev.Address.String(), tx.TransactionHash))

	if strings.EqualFold(address, t.cfg.BondingCurveContract) {
		log.Info(fmt.Sprintf("Creating stream for bonded token: %v", ev.Address.String()))
		if err := t.createStreamForContractAddress(ctx, ev.Address.String()); err != nil {
			return errors.Wrapf(err, "failed to create stream to monitor contract %v", ev.Address.String())
		}
		log.Info(fmt.Sprintf("Successfully created stream for bonded token: %v", ev.Address.String()))
	}

	return nil
}

func (t *tokenAnalytics) onTransfer(ctx context.Context, tx *txEvent, logEvent *JSON, ev *bondingcurve.LogTransfer) error {
	topics, _ := logEvent.getStringSlice("topics")
	address, _ := logEvent.getString("address")

	if len(topics) >= 3 {
		ev.From = common.HexToAddress(topics[1])
		ev.To = common.HexToAddress(topics[2])
	}

	log.Info(fmt.Sprintf("Transfer on token %v: from=%v, to=%v, amount=%v, tx:%v",
		address, ev.From.String(), ev.To.String(), ev.Amount, tx.TransactionHash))

	return nil
}

func (t *tokenAnalytics) onOwnershipTransferred(ctx context.Context, tx *txEvent, logEvent *JSON, ev *bondingcurve.LogOwnershipTransferred) error {
	topics, _ := logEvent.getStringSlice("topics")
	address, _ := logEvent.getString("address")

	if len(topics) >= 3 {
		ev.PreviousOwner = common.HexToAddress(topics[1])
		ev.NewOwner = common.HexToAddress(topics[2])
	}

	log.Info(fmt.Sprintf("OwnershipTransferred on token %v: from=%v, to=%v, tx:%v",
		address, ev.PreviousOwner.String(), ev.NewOwner.String(), tx.TransactionHash))

	return nil
}

func (t *tokenAnalytics) onSwap(ctx context.Context, tx *txEvent, logEvent *JSON, ev *bondingcurve.LogTokenSwapped) error {
	log.Info("Token swapped:%+v, tx:%v", ev, tx.TransactionHash)

	return nil
}

func (t *tokenAnalytics) onPairRegistered(ctx context.Context, tx *txEvent, logEvent *JSON, ev *bondingcurve.LogPairRegistered) error {
	log.Info("Pair registered:%+v, tx:%v", ev, tx.TransactionHash)

	return nil
}

func (t *tokenAnalytics) onRecipientsSet(ctx context.Context, tx *txEvent, logEvent *JSON, ev *bondingcurve.LogRecipientsSet) error {
	log.Info("Recipients set:%+v, tx:%v", ev, tx.TransactionHash)

	return nil
}

func (t *tokenAnalytics) onMigrated(ctx context.Context, tx *txEvent, logEvent *JSON, ev *bondingcurve.LogMigrated) error {
	log.Info("Migrated:%+v, tx:%v", ev, tx.TransactionHash)

	return nil
}

func (t *tokenAnalytics) onFeeAccrued(ctx context.Context, tx *txEvent, logEvent *JSON, ev *bondingcurve.LogFeeAccrued) error {
	log.Info("Fee accrued:%+v, tx:%v", ev, tx.TransactionHash)

	return nil
}

func (t *tokenAnalytics) onFeeTransfer(ctx context.Context, tx *txEvent, logEvent *JSON, ev *bondingcurve.LogFeeTransfer) error {
	log.Info("Fee transfer:%+v, tx:%v", ev, tx.TransactionHash)

	return nil
}

func (t *tokenAnalytics) onLiquidityClaimed(ctx context.Context, tx *txEvent, logEvent *JSON, ev *bondingcurve.LogLiquidityClaimed) error {
	log.Info("Liquidity claimed:%+v, tx:%v", ev, tx.TransactionHash)

	return nil
}

func (t *tokenAnalytics) onSlippageChecked(ctx context.Context, tx *txEvent, logEvent *JSON, ev *bondingcurve.LogSlippageChecked) error {
	log.Info("Slippage checked:%+v, tx:%v", ev, tx.TransactionHash)

	return nil
}

func (t *tokenAnalytics) onLiquidityLocked(ctx context.Context, tx *txEvent, logEvent *JSON, ev *bondingcurve.LogLiquidityLocked) error {
	log.Info("Liquidity locked:%+v, tx:%v", ev, tx.TransactionHash)

	return nil
}
