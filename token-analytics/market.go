// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	stdlibtime "time"

	"github.com/cockroachdb/errors"
	"github.com/elliotchance/orderedmap/v3"

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

func (i *Interval) InitialBufferSize() int {
	window := validIntervals[*i]
	dur := i.Duration()
	return int(stdlibtime.Duration(window)/dur) + 10
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
		DecimalColumnFromString("price_in_usd", t.PriceInUsd.Text('f', 18)).
		DecimalColumnFromString("market_cap_usd", t.MarketcapUsd.Text('f', 18))
}

func (t *tokenAnalytics) registerTrade(ctx context.Context, tx *txEvent, direction bool, inputAmount, outputAmount *big.Int, contractAddress, userAddress, externalAddress, baseToken string, pairId []byte, totalSupply, burned *big.Int, priceInUSD, marketCapUSD float64) (bool, error) {
	dedupKey := strings.ToLower(tx.TransactionHash) + ":" + strings.ToLower(contractAddress) + ":" + strings.ToLower(userAddress)
	if _, alreadyProcessed := t.recentlyRegisteredTrades.LoadOrStore(dedupKey, stdlibtime.Now().UnixNano()); alreadyProcessed {
		return false, nil
	}

	tradeTyp, baseAmount, amount, priceInBase := buyOrSell(direction, inputAmount, outputAmount)
	priceInBaseF, _ := priceInBase.Float64()
	basePrice := priceInUSD / priceInBaseF
	tradeData := &trade{
		Timestamp:       *tx.BlockTimestamp,
		PairAddress:     hex.EncodeToString(pairId[:]),
		ContractAddress: contractAddress,
		ExternalAddress: externalAddress,
		BasePriceInUsd:  basePrice,
		BaseAmount:      baseAmount,
		Amount:          amount,
		Type:            tradeTyp,
		TraderAddress:   userAddress,
		TransactionHash: tx.TransactionHash,
		PriceInUsd:      big.NewFloat(priceInUSD),
		MarketcapUsd:    big.NewFloat(marketCapUSD),
	}

	if err := questdb.Write(ctx, t.questDB, tradeData); err != nil {
		t.recentlyRegisteredTrades.Delete(dedupKey)

		return false, errors.Wrapf(err, "failed to insert trading data into questdb")
	}
	for interval := range validIntervals {
		candleStick, _ := t.ohclvRecentData.LoadOrCompute(interval.String()+"_"+externalAddress, func() (newValue *recentCandlestick, cancel bool) {
			return newRecentCandlestick(), false
		})
		candleStick.Update(priceInUSD, totalSupply, burned)
	}
	if recentTradingStats, ok := t.tradingStatsRecentData.Load(externalAddress); ok {
		recentTradingStats.update(tx.BlockTimestamp.UnixNano(), priceInUSD, tradeTyp == TradeTypeSell)
	}

	return true, nil
}

func buyOrSell(direction bool, inputAmount, outputAmount *big.Int) (trade TradeType, baseTokenAmount, creatorOrContentTokenAmount questdb.Decimal, priceInBase *big.Float) {
	input := questdb.NewDecimal(inputAmount)
	output := questdb.NewDecimal(outputAmount)
	// Price calculation: how much base token per 1 community token
	// For buy: price = input (base token) / output (community tokens)
	// For sell: price = output (base token) / input (community tokens)
	priceInBaseFloat := new(big.Float)
	if !direction { // buy (Direction=false)
		if outputAmount.Sign() > 0 {
			priceInBaseFloat.Quo(new(big.Float).SetInt(inputAmount), new(big.Float).SetInt(outputAmount))
		}
		return TradeTypeBuy, input, output, priceInBaseFloat
	} else { // sell (Direction=true)
		if inputAmount.Sign() > 0 {
			priceInBaseFloat.Quo(new(big.Float).SetInt(outputAmount), new(big.Float).SetInt(inputAmount))
		}
		return TradeTypeSell, output, input, priceInBaseFloat
	}
}

func (t *tokenAnalytics) GetOHLVCHistory(ctx context.Context, now stdlibtime.Time, externalAddress string, interval Interval, limit, offset uint64) (res []*OHLCV, err error) {
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
			volume,
		    COALESCE(market_cap_usd, 0) AS market_cap_usd
		    from ohlcv_%[1]v WHERE timestamp < timestamp_floor('%[1]v', $2)
                         AND external_address = $1 ORDER BY timestamp DESC LIMIT $4, $4+$3;
	`, interval.String())
	ohlcvs, err := questdb.Select[OHLCV](ctx, t.questDB, sql, externalAddress, time.New(now), limit, offset)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get ohlvc data for %v", externalAddress)
	}
	return ohlcvs, nil
}

func (t *tokenAnalytics) GetTradingStats(ctx context.Context, now stdlibtime.Time, externalAddress string) (*TradeStats, error) {
	return t.fetchTradingStats(ctx, now, externalAddress)
}

func tradingStatsCacheKey(ionConnectAddr, interval string) string {
	return fmt.Sprintf("trading_stats:%v:%v", ionConnectAddr, interval)
}

func (t *tokenAnalytics) SubscribeTradingStats(ctx context.Context, now stdlibtime.Time, externalAddress, user string, addToStream func(*TradeStats, error)) error {
	initialStats, err := t.GetTradingStats(ctx, now, externalAddress)
	if err != nil {
		return errors.Wrapf(err, "failed to get initial trading stats")
	}
	addToStream(initialStats, nil)

	swaps := t.subscriptions.SubscribeOnSwaps(ctx, externalAddress, user)
	recentStats, _ := t.tradingStatsRecentData.LoadOrCompute(externalAddress, func() (*recentTradeStats, bool) {
		return newRecentTradingStats(initialStats, now), false
	})
	recentStats.startExpirationTicker(ctx, func() {
		rec, ok := t.tradingStatsRecentData.Load(externalAddress)
		if ok {
			stats := rec.TradeStats()
			addToStream(stats, nil)
		}
	})

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case _, open := <-swaps:
				if !open {
					return
				}
				rec, ok := t.tradingStatsRecentData.Load(externalAddress)
				if ok {
					stats := rec.TradeStats()
					addToStream(stats, nil)
				}
			}
		}
	}()
	return nil
}

func (t *tokenAnalytics) SubscribeOHLVC(ctx context.Context, now stdlibtime.Time, externalAddress, user string, interval Interval, addToStream func(*OHLCV, error)) error {
	swaps := t.subscriptions.SubscribeOnSwaps(ctx, externalAddress, user)
	candleStick, loaded := t.ohclvRecentData.Load(interval.String() + "_" + externalAddress)
	if loaded {
		o := candleStick.OHLCV()
		if o.Empty() {
			recentCandle, err := t.GetOHLVCHistory(ctx, now.Add(interval.Duration()), externalAddress, interval, 1, 0)
			if len(recentCandle) == 0 || err != nil {
				if len(recentCandle) == 0 || storage.IsErr(err, storage.ErrNotFound) {
					recentCandle = append(recentCandle, &OHLCV{})
					err = nil
				}
				if err != nil {
					return errors.Wrapf(err, "failed to get initial ohlvc data for %v (%v", externalAddress, interval.String())
				}
			}
			o = recentCandle[0]
			if !o.Empty() {
				candleStick = newRecentCandlestick()
				candleStick.o.Store(o)
				t.ohclvRecentData.Store(interval.String()+"_"+externalAddress, candleStick)
			}
		}
		if !o.Empty() {
			addToStream(o, nil)
		}
		candleStick.SetInterval(ctx, interval)
		go func() {
			for _ = range swaps {
				rec, ok := t.ohclvRecentData.Load(interval.String() + "_" + externalAddress)
				if ok {
					addToStream(rec.OHLCV(), nil)
				}
			}
		}()
	} else {
		recentCandle, err := t.GetOHLVCHistory(ctx, now.Add(interval.Duration()), externalAddress, interval, 1, 0)
		if len(recentCandle) == 0 || err != nil {
			if len(recentCandle) == 0 || storage.IsErr(err, storage.ErrNotFound) {
				recentCandle = append(recentCandle, &OHLCV{})
				err = nil
			}
			if err != nil {
				return errors.Wrapf(err, "failed to get initial ohlvc data for %v (%v", externalAddress, interval.String())
			}
		}
		o := recentCandle[0]
		if !o.Empty() {
			addToStream(o, nil)
		}
	}

	return nil
}

func (t *tokenAnalytics) fetchTradingStats(ctx context.Context, now stdlibtime.Time, externalAddress string) (res *TradeStats, err error) {
	sql := `SELECT
              '5m' as aggregation_interval,
               COALESCE(SUM(CASE WHEN trade_type = 'buy' THEN amount/1e18::DECIMAL(76,18) * price_in_usd ELSE 0 END),0)  AS buys_total_amount_usd,
               COALESCE(SUM(CASE WHEN trade_type = 'sell' THEN amount/1e18::DECIMAL(76,18) * price_in_usd ELSE 0 END),0) AS sells_total_amount_usd,
               COALESCE(SUM(CASE WHEN trade_type = 'buy' THEN 1 ELSE 0 END),0)                                           AS number_of_buys,
               COALESCE(SUM(CASE WHEN trade_type = 'sell' THEN 1 ELSE 0 END),0)                                          AS number_of_sells,
               COALESCE(SUM(amount/1e18::DECIMAL(76,18) * price_in_usd),0)                                               AS volume_usd,
               COALESCE(last(price_in_usd), 0)                                                                           AS current_price,
               COALESCE(first(price_in_usd), 0)                                                                          AS price_ago
       FROM trades
       WHERE timestamp >= dateadd('m', -5, $2) AND external_address = $1
       UNION ALL (
            SELECT
                   '1h' as aggregation_interval,
                  COALESCE(SUM(CASE WHEN trade_type = 'buy' THEN amount/1e18::DECIMAL(76,18) * price_in_usd ELSE 0 END),0)  AS buys_total_amount_usd,
                  COALESCE(SUM(CASE WHEN trade_type = 'sell' THEN amount/1e18::DECIMAL(76,18) * price_in_usd ELSE 0 END),0) AS sells_total_amount_usd,
                  COALESCE(SUM(CASE WHEN trade_type = 'buy' THEN 1 ELSE 0 END),0)                                           AS number_of_buys,
                  COALESCE(SUM(CASE WHEN trade_type = 'sell' THEN 1 ELSE 0 END),0)                                          AS number_of_sells,
                  COALESCE(SUM(amount/1e18::DECIMAL(76,18) * price_in_usd),0)                                               AS volume_usd,
                  COALESCE(last(price_in_usd), 0)                                                                           AS current_price,
                  COALESCE(first(price_in_usd), 0)                                                                          AS price_ago
           FROM trades
           WHERE timestamp >= dateadd('h', -1, $2) AND external_address = $1
       )
       UNION ALL (
            SELECT
                   '6h' as aggregation_interval,
                  COALESCE(SUM(CASE WHEN trade_type = 'buy' THEN amount/1e18::DECIMAL(76,18) * price_in_usd ELSE 0 END),0)  AS buys_total_amount_usd,
                  COALESCE(SUM(CASE WHEN trade_type = 'sell' THEN amount/1e18::DECIMAL(76,18) * price_in_usd ELSE 0 END),0) AS sells_total_amount_usd,
                  COALESCE(SUM(CASE WHEN trade_type = 'buy' THEN 1 ELSE 0 END),0)                                           AS number_of_buys,
                  COALESCE(SUM(CASE WHEN trade_type = 'sell' THEN 1 ELSE 0 END),0)                                          AS number_of_sells,
                  COALESCE(SUM(amount/1e18::DECIMAL(76,18) * price_in_usd),0)                                               AS volume_usd,
                  COALESCE(last(price_in_usd), 0)                                                                           AS current_price,
                  COALESCE(first(price_in_usd), 0)                                                                          AS price_ago
           FROM trades
           WHERE timestamp >= dateadd('h', -6, $2) AND external_address = $1
       )
       UNION ALL (
            SELECT
                   '24h' as aggregation_interval,
                  COALESCE(SUM(CASE WHEN trade_type = 'buy' THEN amount/1e18::DECIMAL(76,18) * price_in_usd ELSE 0 END),0)  AS buys_total_amount_usd,
                  COALESCE(SUM(CASE WHEN trade_type = 'sell' THEN amount/1e18::DECIMAL(76,18) * price_in_usd ELSE 0 END),0) AS sells_total_amount_usd,
                  COALESCE(SUM(CASE WHEN trade_type = 'buy' THEN 1 ELSE 0 END),0)                                           AS number_of_buys,
                  COALESCE(SUM(CASE WHEN trade_type = 'sell' THEN 1 ELSE 0 END),0)                                          AS number_of_sells,
                  COALESCE(SUM(amount/1e18::DECIMAL(76,18) * price_in_usd),0)                                               AS volume_usd,
                  COALESCE(last(price_in_usd), 0)                                                                           AS current_price,
                  COALESCE(first(price_in_usd), 0)                                                                          AS price_ago
           FROM trades
           WHERE timestamp >= dateadd('h', -24, $2) AND external_address = $1
       )
       UNION ALL (
       		SELECT
                  'is_first_swap' 																							AS aggregation_interval,
                  0::DECIMAL(76,18)  																						AS buys_total_amount_usd,
                  0::DECIMAL(76,18)  																						AS sells_total_amount_usd,
                  COALESCE(SUM(CASE WHEN trade_type = 'buy' THEN 1 ELSE 0 END),0)                                           AS number_of_buys,
                  COALESCE(SUM(CASE WHEN trade_type = 'sell' THEN 1 ELSE 0 END),0)                                          AS number_of_sells,
                  0::DECIMAL(76,18)                                               											AS volume_usd,
                  0::DECIMAL(76,18)                                                                           				AS current_price,
                  0::DECIMAL(76,18)                                                                           				AS price_ago
           FROM trades
           WHERE external_address = $1 LIMIT 2
       );`

	aggregates, err := questdb.Select[TradeStatsAggregate](ctx, t.questDB, sql, externalAddress, time.New(now))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch trading stats for %v", externalAddress)
	}
	res = new(TradeStats)
	var firstSwap bool
	for i := range aggregates {
		if aggregates[i].AggregationInterval != "is_first_swap" {
			continue
		}
		if aggregates[i].NumberOfBuys == 1 && aggregates[i].NumberOfSells == 0 {
			firstSwap = true
			break
		}
	}
	var startingPrice float64
	if firstSwap {
		token, err := storage.Get[tokenAndUserInfo](ctx, t.ingestedDataDB, `
			SELECT tokens."type" as token_type, tokens.base_token, tokens.platform from tokens where tokens.external_address = $1
		`, externalAddress)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to fetch pg token info for %v", externalAddress)
		}
		startedTokensParams, _, _, err := defaultStartTokenParamsForBase(ctx, t.cfg, t.creatorTokenPricesION, t.ingestedDataDB, t.bondingCurve,
			token.BaseToken, token.Type, token.Platform, nil, nil)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to fetch start token params for %v", externalAddress)
		}
		initialPriceBig, ok := new(big.Int).SetString(startedTokensParams.InitialPrice, 10)
		if !ok {
			return nil, errors.Errorf("failed to parse initial price for %v %v", externalAddress, startedTokensParams.InitialPrice)
		}
		startingPrice, _, err = t.calculatePriceInUSD(ctx, weiToFloat64FromBigInt(initialPriceBig), token.BaseToken)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to calculate price usd for starting price of %v (%v), base %v", externalAddress, startedTokensParams.InitialPrice, token.BaseToken)
		}
	}
	for i := range aggregates {
		aggregates[i].NetBuy = aggregates[i].BuysTotalAmountUSD - aggregates[i].SellsTotalAmountUSD
		if firstSwap && startingPrice > 0 && aggregates[i].CurrentPrice > 0 {
			aggregates[i].PriceAgo = startingPrice
		}
		if aggregates[i].PriceAgo > 0 {
			aggregates[i].PriceDiff = ((aggregates[i].CurrentPrice - aggregates[i].PriceAgo) / aggregates[i].PriceAgo) * 100
		}
		switch aggregates[i].AggregationInterval {
		case "5m":
			res.Bucket5Min = aggregates[i]
		case "1h":
			res.Bucket1Hour = aggregates[i]
		case "6h":
			res.Bucket6Hours = aggregates[i]
		case "24h":
			res.Bucket24Hours = aggregates[i]
		default:
			continue
		}
	}
	return res, nil
}

func newRecentCandlestick() *recentCandlestick {
	r := &recentCandlestick{}
	r.reset(stdlibtime.Now().In(stdlibtime.UTC))
	return r
}

func (o *OHLCV) Empty() bool {
	return o.Open == 0 && o.High == 0 && o.Low == 0 && o.Close == 0 && o.Volume == 0
}

func (r *recentCandlestick) SetInterval(ctx context.Context, interval Interval) {
	r.interval = interval
	now := stdlibtime.Now().In(stdlibtime.UTC)
	current := r.o.Load()
	if uint64(now.UnixNano())-current.Timestamp >= uint64(interval.Duration()) {
		r.reset(now)
	}
	r.onceStartTicker.Do(func() { go r.startResetTicker(ctx, interval) })
}

func (r *recentCandlestick) Update(priceInUsd float64, totalSupply, burned *big.Int) {
	marketCapUSD := marketCap(priceInUsd, totalSupply, burned)
	current := r.o.Load()
	updated := *current
	if current.Empty() {
		updated.Open = priceInUsd
	}
	if priceInUsd > current.High {
		updated.High = priceInUsd
	}
	if priceInUsd < current.Low || current.Low == 0 {
		updated.Low = priceInUsd
	}
	updated.Close = priceInUsd
	updated.Volume += priceInUsd
	updated.MarketCap, _ = marketCapUSD.Float64()
	r.o.Store(&updated)
}

func (r *recentCandlestick) OHLCV() *OHLCV {
	return r.o.Load()
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
				r.reset(stdlibtime.Now().In(stdlibtime.UTC))
			}
		}
	}()
}

func (r *recentCandlestick) reset(now stdlibtime.Time) {
	r.o.Store(&OHLCV{Open: 0, High: 0, Low: 0, Close: 0, Volume: 0, Timestamp: uint64(now.Truncate(r.interval.Duration()).UnixNano())})
}

func (t *recentTradeStats) updateBucket(b *TradeStatsAggregate, priceInUSD float64, sell bool) {
	if sell {
		b.SellsTotalAmountUSD += priceInUSD
		b.NumberOfSells += 1
	} else {
		b.BuysTotalAmountUSD += priceInUSD
		b.NumberOfBuys += 1
	}
	b.VolumeUSD += priceInUSD
	b.NetBuy = b.BuysTotalAmountUSD - b.SellsTotalAmountUSD
	b.CurrentPrice = priceInUSD
	if b.PriceAgo > 0 {
		b.PriceDiff = ((b.CurrentPrice - b.PriceAgo) / b.PriceAgo) * 100
	}
}

func (t *recentTradeStats) update(now int64, priceInUSD float64, sell bool) {
	t.mx.Lock()
	defer t.mx.Unlock()
	diff := TradeStatsAggregate{}
	if sell {
		diff.SellsTotalAmountUSD = priceInUSD
		diff.NumberOfSells = 1
		diff.NetBuy = -priceInUSD
	} else {
		diff.BuysTotalAmountUSD = priceInUSD
		diff.NumberOfBuys = 1
		diff.NetBuy = priceInUSD
	}
	diff.VolumeUSD = priceInUSD
	diff.CurrentPrice = priceInUSD

	t.expirations5M.Set(now+int64(5*stdlibtime.Minute), diff)
	t.expirations1H.Set(now+int64(1*stdlibtime.Hour), diff)
	t.expirations6H.Set(now+int64(6*stdlibtime.Hour), diff)
	t.expirations24H.Set(now+int64(24*stdlibtime.Hour), diff)
	t.updateBucket(t.stats.Bucket5Min, priceInUSD, sell)
	t.updateBucket(t.stats.Bucket1Hour, priceInUSD, sell)
	t.updateBucket(t.stats.Bucket6Hours, priceInUSD, sell)
	t.updateBucket(t.stats.Bucket24Hours, priceInUSD, sell)
	t.expire(now, t.expirations5M, t.stats.Bucket5Min)
	t.expire(now, t.expirations1H, t.stats.Bucket1Hour)
	t.expire(now, t.expirations6H, t.stats.Bucket6Hours)
	t.expire(now, t.expirations24H, t.stats.Bucket24Hours)
}

func (t *recentTradeStats) expireValueInBucket(now, ts int64, valToExpire TradeStatsAggregate, bucket *TradeStatsAggregate) (expired bool) {
	if ts <= now {
		bucket.NetBuy -= valToExpire.NetBuy
		bucket.NumberOfBuys -= valToExpire.NumberOfBuys
		bucket.NumberOfSells -= valToExpire.NumberOfSells
		bucket.SellsTotalAmountUSD -= valToExpire.SellsTotalAmountUSD
		bucket.BuysTotalAmountUSD -= valToExpire.BuysTotalAmountUSD
		bucket.VolumeUSD -= valToExpire.VolumeUSD
		return true
	}
	return false
}

func (t *recentTradeStats) expire(now int64, expirations *orderedmap.OrderedMap[int64, TradeStatsAggregate], bucket *TradeStatsAggregate) bool {
	hasExpired := false
	for ts, valToExpire := range expirations.AllFromFront() {
		if ts >= now {
			break
		}
		expired := t.expireValueInBucket(now, ts, valToExpire, bucket)
		if expired {
			expirations.Delete(ts)
			hasExpired = true
		}
	}

	if hasExpired {
		hasOldest := false
		oldestPrice := 0.0
		for _, val := range expirations.AllFromFront() {
			if val.CurrentPrice > 0 {
				oldestPrice = val.CurrentPrice
				hasOldest = true
				break
			}
		}

		if hasOldest {
			bucket.PriceAgo = oldestPrice
		} else {
			bucket.PriceAgo = 0
			bucket.CurrentPrice = 0
			bucket.PriceDiff = 0
		}
		if bucket.PriceAgo > 0 {
			bucket.PriceDiff = ((bucket.CurrentPrice - bucket.PriceAgo) / bucket.PriceAgo) * 100
		}
	}

	return hasExpired
}

func (src *TradeStats) cpy() *TradeStats {
	if src == nil {
		return nil
	}
	dst := *src
	if src.Bucket5Min != nil {
		b := *src.Bucket5Min
		dst.Bucket5Min = &b
	}
	if src.Bucket1Hour != nil {
		b := *src.Bucket1Hour
		dst.Bucket1Hour = &b
	}
	if src.Bucket6Hours != nil {
		b := *src.Bucket6Hours
		dst.Bucket6Hours = &b
	}
	if src.Bucket24Hours != nil {
		b := *src.Bucket24Hours
		dst.Bucket24Hours = &b
	}
	return &dst
}

func (t *recentTradeStats) TradeStats() *TradeStats {
	t.mx.Lock()
	defer t.mx.Unlock()
	cpy := t.stats.cpy()
	return cpy
}

func (t *recentTradeStats) startExpirationTicker(ctx context.Context, onChanged func()) {
	t.onceStartTicker.Do(func() {
		ticker := stdlibtime.NewTicker(30 * stdlibtime.Second)
		go func() {
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					t.mx.Lock()
					oldStats := t.stats.cpy()
					now := stdlibtime.Now().UnixNano()
					expired5M := t.expire(now, t.expirations5M, t.stats.Bucket5Min)
					expired1H := t.expire(now, t.expirations1H, t.stats.Bucket1Hour)
					expired6H := t.expire(now, t.expirations6H, t.stats.Bucket6Hours)
					expired24H := t.expire(now, t.expirations24H, t.stats.Bucket24Hours)

					anyExpired := expired5M || expired1H || expired6H || expired24H
					newStats := t.stats.cpy()
					t.mx.Unlock()
					if anyExpired {
						changed := (oldStats.Bucket5Min != nil && newStats.Bucket5Min != nil && oldStats.Bucket5Min.PriceDiff != newStats.Bucket5Min.PriceDiff) ||
							(oldStats.Bucket1Hour != nil && newStats.Bucket1Hour != nil && oldStats.Bucket1Hour.PriceDiff != newStats.Bucket1Hour.PriceDiff) ||
							(oldStats.Bucket6Hours != nil && newStats.Bucket6Hours != nil && oldStats.Bucket6Hours.PriceDiff != newStats.Bucket6Hours.PriceDiff) ||
							(oldStats.Bucket24Hours != nil && newStats.Bucket24Hours != nil && oldStats.Bucket24Hours.PriceDiff != newStats.Bucket24Hours.PriceDiff)

						if changed {
							onChanged()
						}
					}
				}
			}
		}()
	})
}

func newRecentTradingStats(initialStats *TradeStats, now stdlibtime.Time) *recentTradeStats {
	cpy := initialStats.cpy()
	stat := &recentTradeStats{
		stats:          cpy,
		initTime:       now.UnixNano(),
		expirations5M:  orderedmap.NewOrderedMapWithCapacity[int64, TradeStatsAggregate](1),
		expirations1H:  orderedmap.NewOrderedMapWithCapacity[int64, TradeStatsAggregate](1),
		expirations6H:  orderedmap.NewOrderedMapWithCapacity[int64, TradeStatsAggregate](1),
		expirations24H: orderedmap.NewOrderedMapWithCapacity[int64, TradeStatsAggregate](1),
	}

	bucket5M := *cpy.Bucket5Min
	bucket5M.CurrentPrice = cpy.Bucket5Min.PriceAgo
	stat.expirations5M.Set(now.Add(5*stdlibtime.Minute).UnixNano(), bucket5M)

	bucket1H := *cpy.Bucket1Hour
	bucket1H.CurrentPrice = cpy.Bucket1Hour.PriceAgo
	stat.expirations1H.Set(now.Add(1*stdlibtime.Hour).UnixNano(), bucket1H)

	bucket6H := *cpy.Bucket6Hours
	bucket6H.CurrentPrice = cpy.Bucket6Hours.PriceAgo
	stat.expirations6H.Set(now.Add(6*stdlibtime.Hour).UnixNano(), bucket6H)

	bucket24H := *cpy.Bucket24Hours
	bucket24H.CurrentPrice = cpy.Bucket24Hours.PriceAgo
	stat.expirations24H.Set(now.Add(24*stdlibtime.Hour).UnixNano(), bucket24H)

	return stat
}
