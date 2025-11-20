// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	stdlibtime "time"

	"github.com/pkg/errors"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/heimdall/token-analytics/internal/questdb"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/time"
)

func (i *Interval) String() string {
	return string(*i)
}

func (i *Interval) Validate() error {
	_, valid := validIntervals[*i]
	if !valid {
		return errors.Errorf("invalid interval: %v", *i)
	}
	if _, err := stdlibtime.ParseDuration(i.String()); err != nil {
		return errors.Wrapf(err, "interval is malformed duration")
	}
	return nil
}
func (i *Interval) WindowSize() WindowSize {
	window := validIntervals[*i]
	return window
}
func (i *Interval) Duration() stdlibtime.Duration {
	dur, _ := stdlibtime.ParseDuration(i.String()) // error checked on validate
	return dur
}

func (t *trade) Time() stdlibtime.Time {
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

func (t *tokenAnalytics) registerTrade(ctx context.Context, tx *txEvent, ev *bondingcurve.LogTokenSwapped) error {
	tradeTyp, baseAmount, amount, priceInBase := buyOrSell(ev)
	basePrice := t.ionPriceUSD.Load()
	tradeData := &trade{
		Timestamp:                *tx.BlockTimestamp,
		PairAddress:              hex.EncodeToString(ev.Pair[:]),
		ContractAddress:          ev.Address.String(),
		ContentIONConnectAddress: "TODO",
		BasePriceInUsd:           *basePrice,
		BaseAmount:               baseAmount,
		Amount:                   amount,
		Type:                     tradeTyp,
		TraderAddress:            ev.Address.String(),
		TransactionHash:          tx.TransactionHash,
		PriceInUsd:               new(big.Float).Mul(priceInBase, new(big.Float).SetFloat64(*basePrice)),
	}

	err := questdb.Write[*trade](ctx, t.questDB, tradeData)
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

func (t *tokenAnalytics) GetOHLVCHistory(ctx context.Context, now, startPoint stdlibtime.Time, ionContentAddress string, interval Interval) (res []*OHLCV, err error) {
	if err = interval.Validate(); err != nil {
		return nil, errors.Wrapf(err, "invalid interval %v", interval.String())
	}
	sql := fmt.Sprintf(`
		SELECT 
		    timestamp::TIMESTAMP_NS::LONG as timestamp,
			ion_connect_address,
			open,
			high,
			low,
			close,
			volume
		    from ohlcv_%[1]v WHERE timestamp >= $1 AND timestamp < timestamp_floor('%[1]v', $3)
                         AND ion_connect_address = $2 ORDER BY timestamp;
	`, interval.String())
	ohlcvs, err := questdb.Select[OHLCV](ctx, t.questDB, sql, time.New(startPoint), ionContentAddress, time.New(now))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get ohlvc data for %v", startPoint)
	}
	return ohlcvs, nil
}

func (t *tokenAnalytics) GetOHLVCRecent(ctx context.Context, now stdlibtime.Time, ionContentAddress string, interval Interval) (res *OHLCV, err error) {
	if err = interval.Validate(); err != nil {
		return nil, errors.Wrapf(err, "invalid interval %v", interval.String())
	}
	recentOhlcvData, err := questdb.Get[OHLCV](ctx, t.questDB, fmt.Sprintf(`
		SELECT
			timestamp::TIMESTAMP_NS::LONG as timestamp,
			ion_connect_address,
			first(price_in_usd) AS open,
			max(price_in_usd) AS high,
			min(price_in_usd) AS low,
			last(price_in_usd) AS close,
			sum(price_in_usd) AS volume
		FROM trades WHERE
			timestamp >= timestamp_floor('%[1]v', $2) 
		              AND timestamp < dateadd('T', $3,timestamp_floor('%[1]v', $2)) -- if there is data newer than now
					  AND ion_connect_address = $1
		SAMPLE BY %[1]v ALIGN TO CALENDAR;
	`, interval.String()), ionContentAddress, time.New(now), int64(interval.Duration()/stdlibtime.Millisecond))
	if err != nil {
		if storage.IsErr(err, storage.ErrNotFound) {
			return &OHLCV{
				Timestamp: uint64(now.UnixNano()),
				Open:      0,
				High:      0,
				Low:       0,
				Close:     0,
				Volume:    0,
			}, nil
		}
		return nil, errors.Wrapf(err, "failed to get ohlvc data for %v", now)
	}

	return &OHLCV{
		Timestamp: uint64(recentOhlcvData.Timestamp),
		Open:      recentOhlcvData.Open,
		High:      recentOhlcvData.High,
		Low:       recentOhlcvData.Low,
		Close:     recentOhlcvData.Close,
		Volume:    recentOhlcvData.Volume,
	}, nil
}
