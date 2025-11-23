// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	stdlibtime "time"

	"github.com/cockroachdb/errors"
	"github.com/redis/go-redis/v9"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/heimdall/token-analytics/internal/questdb"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
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

func buyOrSell(ev *bondingcurve.LogTokenSwapped) (trade TradeType, baseTokenAmount, creatorOrContentTokenAmount questdb.Decimal, priceInBase *big.Float) {
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

func (t *tokenAnalytics) GetTradingStats(ctx context.Context, now stdlibtime.Time, ionContentAddress string) (*TradeStats, error) {
	min5, err := storagev3.Get[TradeStatsAggregate](ctx, t.processedDataDB, tradingStatsCacheKey(ionContentAddress, "5m"))
	if err != nil || len(min5) == 0 {
		return t.UpdateTradingStats(ctx, now, ionContentAddress)
	}
	hour1, err := storagev3.Get[TradeStatsAggregate](ctx, t.processedDataDB, tradingStatsCacheKey(ionContentAddress, "1h"))
	if err != nil || len(hour1) == 0 {
		return t.UpdateTradingStats(ctx, now, ionContentAddress)
	}
	hour6, err := storagev3.Get[TradeStatsAggregate](ctx, t.processedDataDB, tradingStatsCacheKey(ionContentAddress, "6h"))
	if err != nil || len(hour6) == 0 {
		return t.UpdateTradingStats(ctx, now, ionContentAddress)
	}
	hour24, err := storagev3.Get[TradeStatsAggregate](ctx, t.processedDataDB, tradingStatsCacheKey(ionContentAddress, "24h"))
	if err != nil || len(hour24) == 0 {
		return t.UpdateTradingStats(ctx, now, ionContentAddress)
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

func (t *tokenAnalytics) fetchTradingStats(ctx context.Context, now stdlibtime.Time, ionContentAddress string) (res *TradeStats, err error) {
	sql := `SELECT
              '5m' as aggregation_interval,
              COALESCE(SUM(CASE WHEN trade_type = 'buy' THEN amount * price_in_usd ELSE 0 END)/1e18::DECIMAL(76,18),0) AS buys_total_amount_usd,
              COALESCE(SUM(CASE WHEN trade_type = 'sell' THEN amount * price_in_usd ELSE 0 END)/1e18::DECIMAL(76,18),0) AS sells_total_amount_usd,
              COALESCE(SUM(CASE WHEN trade_type = 'buy' THEN 1 ELSE 0 END),0)                    AS number_of_buys,
              COALESCE(SUM(CASE WHEN trade_type = 'sell' THEN 1 ELSE 0 END),0)                   AS number_of_sells,
              COALESCE(SUM(amount * price_in_usd)/1e18::DECIMAL(76,18),0)                                             AS volume_usd
       FROM trades
       WHERE timestamp >= dateadd('m', -5, $2) AND ion_connect_address = $1
       UNION ALL (
            SELECT
                   '1h' as aggregation_interval,
                   COALESCE(SUM(CASE WHEN trade_type = 'buy' THEN amount * price_in_usd ELSE 0 END)/1e18::DECIMAL(76,18),0)  AS buys_total_amount_usd,
                   COALESCE(SUM(CASE WHEN trade_type = 'sell' THEN amount * price_in_usd ELSE 0 END)/1e18::DECIMAL(76,18),0) AS sells_total_amount_usd,
                   COALESCE(SUM(CASE WHEN trade_type = 'buy' THEN 1 ELSE 0 END),0)                      AS number_of_buys,
                   COALESCE(SUM(CASE WHEN trade_type = 'sell' THEN 1 ELSE 0 END),0)                     AS number_of_sells,
                   COALESCE(SUM(amount * price_in_usd)/1e18::DECIMAL(76,18),0)                                               AS volume_usd
            FROM trades
            WHERE timestamp >= dateadd('h', -1, $2) AND ion_connect_address = $1
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
            WHERE timestamp >= dateadd('h', -6, $2) AND ion_connect_address = $1
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
            WHERE timestamp >= dateadd('h', -24, $2) AND ion_connect_address = $1
       )`
	aggregates, err := questdb.Select[TradeStatsAggregate](ctx, t.questDB, sql, ionContentAddress, time.New(now))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch trading stats for %v", ionContentAddress)
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
