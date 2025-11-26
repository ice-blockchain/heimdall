// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	stdlibtime "time"

	"github.com/cockroachdb/errors"
	"github.com/redis/go-redis/v9"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/heimdall/token-analytics/internal/questdb"
	storagev3 "github.com/ice-blockchain/wintr/connectors/storage/v3"
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
		Symbol("external_address", t.ExternalAddress).
		Symbol("trade_type", string(t.Type)).
		Symbol("trader_address", t.TraderAddress).
		Symbol("transaction_hash", t.TransactionHash).
		DecimalColumnFromString("base_price_in_usd", fmt.Sprintf("%.18f", t.BasePriceInUsd)).
		DecimalColumn("base_amount", t.BaseAmount).
		DecimalColumn("amount", t.Amount).
		DecimalColumnFromString("price_in_usd", t.PriceInUsd.String())
}

func (t *tokenAnalytics) registerTrade(ctx context.Context, tx *txEvent, ev *bondingcurve.LogTokenSwapped, externalAddress string) error {
	tradeTyp, baseAmount, amount, priceInBase := buyOrSell(ev)
	basePrice := t.ionPriceUSD.Load()
	priceInUSD := new(big.Float).Mul(priceInBase, new(big.Float).SetFloat64(*basePrice))
	tradeData := &trade{
		Timestamp:       *tx.BlockTimestamp,
		PairAddress:     hex.EncodeToString(ev.Pair[:]),
		ContractAddress: ev.Address.String(),
		ExternalAddress: externalAddress,
		BasePriceInUsd:  *basePrice,
		BaseAmount:      baseAmount,
		Amount:          amount,
		Type:            tradeTyp,
		TraderAddress:   ev.Address.String(),
		TransactionHash: tx.TransactionHash,
		PriceInUsd:      priceInUSD,
	}

	if err := questdb.Write(ctx, t.questDB, tradeData); err != nil {
		return errors.Wrapf(err, "failed to insert trading data into questdb")
	}
	price, _ := priceInUSD.Float64()
	candleStick, _ := t.ohclvRecentData.LoadOrStore(ionConnectAddress, newRecentCandlestick())
	candleStick.Update(price)

	return nil
}

func buyOrSell(ev *bondingcurve.LogTokenSwapped) (trade TradeType, baseTokenAmount, creatorOrContentTokenAmount questdb.Decimal, priceInBase *big.Float) {
	input := questdb.NewDecimal(ev.InputAmount)
	output := questdb.NewDecimal(ev.OutputAmount)
	// Price calculation: how much base token per 1 community token
	// For buy: price = input (base token) / output (community tokens)
	// For sell: price = output (base token) / input (community tokens)
	priceInBaseFloat := new(big.Float)
	if !ev.Direction { // buy (Direction=false)
		if ev.OutputAmount.Sign() > 0 {
			priceInBaseFloat.Quo(new(big.Float).SetInt(ev.InputAmount), new(big.Float).SetInt(ev.OutputAmount))
		}
		return tradeTypeBuy, input, output, priceInBaseFloat
	} else { // sell (Direction=true)
		if ev.InputAmount.Sign() > 0 {
			priceInBaseFloat.Quo(new(big.Float).SetInt(ev.OutputAmount), new(big.Float).SetInt(ev.InputAmount))
		}
		return tradeTypeSell, output, input, priceInBaseFloat
	}
}

func (t *tokenAnalytics) GetOHLVCHistory(ctx context.Context, now, startPoint stdlibtime.Time, externalAddress string, interval Interval) (res []*OHLCV, err error) {
	if err = interval.Validate(); err != nil {
		return nil, errors.Wrapf(err, "invalid interval %v", interval.String())
	}
	sql := fmt.Sprintf(`
		SELECT 
		    timestamp::TIMESTAMP_NS::LONG as timestamp,
			external_address,
			open,
			high,
			low,
			close,
			volume
		    from ohlcv_%[1]v WHERE timestamp >= $1 AND timestamp < timestamp_floor('%[1]v', $3)
                         AND external_address = $2 ORDER BY timestamp;
	`, interval.String())
	ohlcvs, err := questdb.Select[OHLCV](ctx, t.questDB, sql, time.New(startPoint), externalAddress, time.New(now))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get ohlvc data for %v", startPoint)
	}
	return ohlcvs, nil
}

func (t *tokenAnalytics) GetTradingStats(ctx context.Context, now stdlibtime.Time, ionContentAddress string) (*TradeStats, error) {
	min5, err := storagev3.Get[TradeStatsAggregate](ctx, t.processedDataDB, tradingStatsCacheKey(ionContentAddress, "5m"))
	if err != nil || len(min5) == 0 {
		return t.UpdateTradingStats(ctx, now, externalAddress)
	}
	hour1, err := storagev3.Get[TradeStatsAggregate](ctx, t.processedDataDB, tradingStatsCacheKey(externalAddress, "1h"))
	if err != nil || len(hour1) == 0 {
		return t.UpdateTradingStats(ctx, now, externalAddress)
	}
	hour6, err := storagev3.Get[TradeStatsAggregate](ctx, t.processedDataDB, tradingStatsCacheKey(externalAddress, "6h"))
	if err != nil || len(hour6) == 0 {
		return t.UpdateTradingStats(ctx, now, externalAddress)
	}
	hour24, err := storagev3.Get[TradeStatsAggregate](ctx, t.processedDataDB, tradingStatsCacheKey(externalAddress, "24h"))
	if err != nil || len(hour24) == 0 {
		return t.UpdateTradingStats(ctx, now, externalAddress)
	}
	return &TradeStats{
		Bucket5Min:    min5[0],
		Bucket1Hour:   hour1[0],
		Bucket6Hours:  hour6[0],
		Bucket24Hours: hour24[0],
	}, nil
}

func tradingStatsCacheKey(ionConnectAddr, interval string) string {
	return fmt.Sprintf("trading_stats:%v:%v", ionConnectAddr, interval)
}

func (t *tokenAnalytics) UpdateTradingStats(ctx context.Context, now stdlibtime.Time, ionConnectAddress string) (*TradeStats, error) {
	stats, err := t.fetchTradingStats(ctx, now, ionConnectAddress)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to update trading stats")
	}
	if responses, txErr := t.processedDataDB.TxPipelined(ctx, func(pipeliner redis.Pipeliner) error {
		if pErr := pipeliner.HSet(ctx, tradingStatsCacheKey(ionConnectAddress, "5m"), storagev3.SerializeValue(stats.Bucket5Min)...).Err(); pErr != nil {
			return pErr
		}
		if pErr := pipeliner.HSet(ctx, tradingStatsCacheKey(ionConnectAddress, "1h"), storagev3.SerializeValue(stats.Bucket1Hour)...).Err(); pErr != nil {
			return pErr
		}
		if pErr := pipeliner.HSet(ctx, tradingStatsCacheKey(ionConnectAddress, "6h"), storagev3.SerializeValue(stats.Bucket6Hours)...).Err(); pErr != nil {
			return pErr
		}
		if pErr := pipeliner.HSet(ctx, tradingStatsCacheKey(ionConnectAddress, "24h"), storagev3.SerializeValue(stats.Bucket24Hours)...).Err(); pErr != nil {
			return pErr
		}
		return nil
	}); txErr != nil {
		return nil, errors.Wrapf(txErr, "failed to update trading stats cache for %v", ionConnectAddress)
	} else {
		for _, response := range responses {
			if rerr := response.Err(); rerr != nil {
				err = errors.Join(err, errors.Wrapf(rerr, "failed to `%v`", response.FullName()))
			}
		}
	}
	if err != nil {
		return nil, errors.Wrapf(err, "failed to update trading stats in cache for %v", ionConnectAddress)
	}
	return stats, nil
}

func (t *tokenAnalytics) SubscribeOHLVC(ctx context.Context, now stdlibtime.Time, ionContentAddress string, interval Interval, handler func(*OHLCV, error, ...string)) error {
	start := now.Add(-stdlibtime.Duration(interval.WindowSize()))
	ohlcvs, err := t.GetOHLVCHistory(ctx, now, start, ionContentAddress, interval)
	if err != nil {
		return errors.Wrapf(err, "failed to get initial ohlcv data (history)")
	}
	for i := range ohlcvs {
		handler(ohlcvs[i], nil, fmt.Sprintf("ohlcv_%v", ohlcvs[i].Timestamp))
	}
	swaps := t.subscribeOnSwaps(ionContentAddress)
	candleStick, _ := t.ohclvRecentData.LoadOrStore(ionContentAddress, newRecentCandlestick())
	candleStick.SetInterval(ctx, interval)
	go func() {
		for _ = range swaps {
			rec, ok := t.ohclvRecentData.Load(ionContentAddress)
			if ok {
				data := rec.OHLCV()
				handler(data, nil, fmt.Sprintf("ohlcv_%v", data.Timestamp))
			}
		}
	}()

	return nil
}

func (t *tokenAnalytics) subscribeOnSwaps(ionContentAddress string) <-chan *bondingcurve.LogTokenSwapped {
	swaps := make(chan *bondingcurve.LogTokenSwapped)
	t.swapSubs.Store(ionContentAddress, swaps)
	return swaps
}

func (t *tokenAnalytics) fetchTradingStats(ctx context.Context, now stdlibtime.Time, externalAddress string) (res *TradeStats, err error) {
	sql := `SELECT
              '5m' as aggregation_interval,
              COALESCE(SUM(CASE WHEN trade_type = 'buy' THEN amount * price_in_usd ELSE 0 END)/1e18::DECIMAL(76,18),0) AS buys_total_amount_usd,
              COALESCE(SUM(CASE WHEN trade_type = 'sell' THEN amount * price_in_usd ELSE 0 END)/1e18::DECIMAL(76,18),0) AS sells_total_amount_usd,
              COALESCE(SUM(CASE WHEN trade_type = 'buy' THEN 1 ELSE 0 END),0)                    AS number_of_buys,
              COALESCE(SUM(CASE WHEN trade_type = 'sell' THEN 1 ELSE 0 END),0)                   AS number_of_sells,
              COALESCE(SUM(amount * price_in_usd)/1e18::DECIMAL(76,18),0)                                             AS volume_usd
       FROM trades
       WHERE timestamp >= dateadd('m', -5, $2) AND external_address = $1
       UNION ALL (
            SELECT
                   '1h' as aggregation_interval,
                   COALESCE(SUM(CASE WHEN trade_type = 'buy' THEN amount * price_in_usd ELSE 0 END)/1e18::DECIMAL(76,18),0)  AS buys_total_amount_usd,
                   COALESCE(SUM(CASE WHEN trade_type = 'sell' THEN amount * price_in_usd ELSE 0 END)/1e18::DECIMAL(76,18),0) AS sells_total_amount_usd,
                   COALESCE(SUM(CASE WHEN trade_type = 'buy' THEN 1 ELSE 0 END),0)                      AS number_of_buys,
                   COALESCE(SUM(CASE WHEN trade_type = 'sell' THEN 1 ELSE 0 END),0)                     AS number_of_sells,
                   COALESCE(SUM(amount * price_in_usd)/1e18::DECIMAL(76,18),0)                                               AS volume_usd
            FROM trades
            WHERE timestamp >= dateadd('h', -1, $2) AND external_address = $1
       )
       UNION ALL (
            SELECT
                   '6h' as aggregation_interval,
                   COALESCE(SUM(CASE WHEN trade_type = 'buy' THEN amount * price_in_usd ELSE 0 END)/1e18::DECIMAL(76,18),0)  AS buys_total_amount_usd,
                   COALESCE(SUM(CASE WHEN trade_type = 'sell' THEN amount * price_in_usd ELSE 0 END)/1e18::DECIMAL(76,18),0) AS sells_total_amount_usd,
                   COALESCE(SUM(CASE WHEN trade_type = 'buy' THEN 1 ELSE 0 END),0)                      AS number_of_buys,
                   COALESCE(SUM(CASE WHEN trade_type = 'sell' THEN 1 ELSE 0 END),0)                     AS number_of_sells,
                   COALESCE(SUM(amount * price_in_usd)/1e18::DECIMAL(76,18),0)                                               AS volume_usd
            FROM trades
            WHERE timestamp >= dateadd('h', -6, $2) AND external_address = $1
       )
       UNION ALL (
            SELECT
                   '24h' as aggregation_interval,
                   COALESCE(SUM(CASE WHEN trade_type = 'buy' THEN amount * price_in_usd ELSE 0 END)/1e18::DECIMAL(76,18),0)  AS buys_total_amount_usd,
                   COALESCE(SUM(CASE WHEN trade_type = 'sell' THEN amount * price_in_usd ELSE 0 END)/1e18::DECIMAL(76,18),0) AS sells_total_amount_usd,
                   COALESCE(SUM(CASE WHEN trade_type = 'buy' THEN 1 ELSE 0 END),0)                      AS number_of_buys,
                   COALESCE(SUM(CASE WHEN trade_type = 'sell' THEN 1 ELSE 0 END),0)                     AS number_of_sells,
                   COALESCE(SUM(amount * price_in_usd)/1e18::DECIMAL(76,18),0)                                               AS volume_usd
            FROM trades
            WHERE timestamp >= dateadd('h', -24, $2) AND external_address = $1
       )`
	aggregates, err := questdb.Select[TradeStatsAggregate](ctx, t.questDB, sql, externalAddress, time.New(now))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch trading stats for %v", externalAddress)
	}
	res = new(TradeStats)
	for i := range aggregates {
		aggregates[i].NetBuy = aggregates[i].BuysTotalAmountUSD - aggregates[i].SellsTotalAmountUSD
		switch aggregates[i].AggregationInterval {
		case "5m":
			res.Bucket5Min = aggregates[i]
		case "1h":
			res.Bucket1Hour = aggregates[i]
		case "6h":
			res.Bucket6Hours = aggregates[i]
		case "24h":
			res.Bucket24Hours = aggregates[i]
		}
	}
	return res, nil
}
func newRecentCandlestick() *recentCandlestick {
	r := &recentCandlestick{
		mx: new(sync.RWMutex),
	}
	r.reset(stdlibtime.Now())
	return r
}
func (o *OHLCV) Empty() bool {
	return o.Open == 0 && o.High == 0 && o.Low == 0 && o.Close == 0 && o.Volume == 0
}

func (r *recentCandlestick) SetInterval(ctx context.Context, interval Interval) {
	r.interval = interval
	now := stdlibtime.Now()
	if uint64(now.UnixNano())-r.o.Timestamp >= uint64(interval.Duration()) {
		r.reset(now)
	}
	go r.startResetTicker(ctx, interval)
}

func (r *recentCandlestick) Update(priceInUsd float64) {
	r.mx.Lock()
	defer r.mx.Unlock()
	if r.o.Empty() {
		r.o.Open = priceInUsd
	}
	if priceInUsd > r.o.High {
		r.o.High = priceInUsd
	}
	if priceInUsd < r.o.Low || r.o.Low == 0 {
		r.o.Low = priceInUsd
	}
	r.o.Close = priceInUsd
	r.o.Volume += priceInUsd
}
func (r *recentCandlestick) OHLCV() *OHLCV {
	r.mx.RLock()
	defer r.mx.RUnlock()
	return r.o
}

func (r *recentCandlestick) startResetTicker(ctx context.Context, interval Interval) {
	ticker := stdlibtime.NewTicker(interval.Duration()) // TODO: cfg?
	go func() {
		defer ticker.Stop()
		for ctx.Err() == nil {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.reset(stdlibtime.Now())
			}
		}
	}()
}

func (r *recentCandlestick) reset(now stdlibtime.Time) {
	r.mx.Lock()
	defer r.mx.Unlock()
	r.o = &OHLCV{Open: 0, High: 0, Low: 0, Close: 0, Volume: 0, Timestamp: uint64(now.Truncate(r.interval.Duration()).UnixNano())}
}
