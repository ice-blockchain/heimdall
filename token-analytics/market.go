// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/pkg/errors"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/heimdall/token-analytics/internal/questdb"
)

func (i *Interval) String() string {
	return string(*i)
}

func (i *Interval) Validate() error {
	_, valid := validIntervals[*i]
	if !valid {
		return errors.Errorf("invalid interval: %v", *i)
	}
	if _, err := time.ParseDuration(i.String()); err != nil {
		return errors.Wrapf(err, "interval is malformed duration")
	}
	return nil
}
func (i *Interval) WindowSize() WindowSize {
	window := validIntervals[*i]
	return window
}
func (i *Interval) Duration() time.Duration {
	dur, _ := time.ParseDuration(i.String()) // error checked on validate
	return dur
}

func (t *trade) Time() time.Time {
	return *t.Timestamp.Time
}

func (t *trade) Marshal(client questdb.LineSender) questdb.At {
	return client.Table("trades").
		Symbol("pair_address", t.PairAddress).
		Symbol("contract_address", t.ContractAddress).
		Symbol("ion_connect_address", t.ContentIONConnectAddress).
		Symbol("trade_type", string(t.Type)).
		Symbol("trader_address", t.TraderAddress).
		Symbol("transaction_hash", t.TransactionHash).
		DecimalColumnFromString("base_price_in_usd", fmt.Sprintf("%.18f", t.BasePriceInUsd)).
		DecimalColumn("base_amount", t.BaseAmount).
		DecimalColumn("amount", t.Amount).
		DecimalColumnFromString("price_in_usd", t.PriceInUsd.String())
}

func (t *tokenAnalytics) registerTrade(ctx context.Context, tx *txEvent, logEvent *JSON, ev *bondingcurve.LogTokenSwapped) error {
	tradeTyp, baseAmount, amount, priceInBase := buyOrSell(ev)
	contractAddress, _ := logEvent.getString("address")
	basePrice := t.ionPriceUSD.Load()
	tradeData := &trade{
		Timestamp:                *tx.BlockTimestamp,
		PairAddress:              hex.EncodeToString(ev.Pair[:]),
		ContractAddress:          contractAddress,
		ContentIONConnectAddress: "TODO",
		BasePriceInUsd:           *basePrice,
		BaseAmount:               baseAmount,
		Amount:                   amount,
		Type:                     tradeTyp,
		TraderAddress:            ev.Address.String(),
		TransactionHash:          tx.TransactionHash,
		PriceInUsd:               new(big.Float).Mul(priceInBase, new(big.Float).SetFloat64(*basePrice)),
	}

	err := questdb.Write[*trade](ctx, t.timescaleDB, tradeData)
	return errors.Wrapf(err, "failed to insert trading data into questdb")
}

func buyOrSell(ev *bondingcurve.LogTokenSwapped) (trade tradeType, baseTokenAmount, creatorOrContentTokenAmount questdb.Decimal, priceInBase *big.Float) {
	input := questdb.NewDecimal(ev.InputAmount)
	output := questdb.NewDecimal(ev.OutputAmount)
	// Price calculation: how much base token per 1 community token
	// For buy: price = input (base token) / output (community tokens)
	// For sell: price = output (base token) / input (community tokens)
	priceInBaseFloat := new(big.Float)
	if ev.Direction { // buy
		if ev.OutputAmount.Sign() > 0 {
			priceInBaseFloat.Quo(new(big.Float).SetInt(ev.InputAmount), new(big.Float).SetInt(ev.OutputAmount))
		}
		return tradeTypeBuy, input, output, priceInBaseFloat
	} else { // sell
		if ev.InputAmount.Sign() > 0 {
			priceInBaseFloat.Quo(new(big.Float).SetInt(ev.OutputAmount), new(big.Float).SetInt(ev.InputAmount))
		}
		return tradeTypeSell, output, input, priceInBaseFloat
	}
}

func (t *tokenAnalytics) GetOHLVC(ctx context.Context, ionContentAddress string, interval Interval, startPoint time.Time) (res []*OHLCV, lastTs time.Time, err error) {
	if err := interval.Validate(); err != nil {
		return nil, time.Time{}, errors.Wrapf(err, "invalid interval %v", interval.String())
	}

	ohlcvs, err := questdb.Select[ohlcv](ctx, t.timescaleDB, fmt.Sprintf(`
		SELECT * from ohlcv_%v WHERE timestamp >= $1 AND ion_connect_address = $2 ORDER BY timestamp;
	`, interval.String()), startPoint, ionContentAddress)
	if err != nil {
		return nil, time.Time{}, errors.Wrapf(err, "failed to get ohlvc data for %v", startPoint)
	}
	res = make([]*OHLCV, len(ohlcvs), len(ohlcvs))
	maxTs := time.Time{}
	for i := range ohlcvs {
		if ohlcvs[i].Timestamp.After(maxTs) {
			maxTs = *ohlcvs[i].Timestamp.Time
		}
		res[i] = &OHLCV{
			Timestamp: uint64(ohlcvs[i].Timestamp.UnixNano()),
			Open:      ohlcvs[i].Open,
			High:      ohlcvs[i].High,
			Low:       ohlcvs[i].Low,
			Close:     ohlcvs[i].Close,
			Volume:    ohlcvs[i].Volume,
		}
	}
	return res, maxTs, nil
}
