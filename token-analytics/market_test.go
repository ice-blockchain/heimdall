// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"encoding/hex"
	"math/big"
	stdlibsync "sync"
	"testing"
	stdlibtime "time"

	"github.com/elliotchance/orderedmap/v3"
	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/heimdall/token-analytics/internal/questdb"
	"github.com/ice-blockchain/wintr/time"
)

func TestGetTradingStats(t *testing.T) {
	t.Parallel()
	db, connString, release := helperCreateDBWithConnString(t)
	defer release()

	ta := helperNewForTestWithConnString(t, db, connString)

	externalAddress := "0:test_trading_stats:test"
	contractAddress := "0x1234567890abcdef1234567890abcdef12345678"
	pairAddress := "0xabcdef1234567890abcdef1234567890abcdef12"

	now := stdlibtime.Now().UTC()

	trades := []*trade{
		// 5m ago - 2 buys
		{
			Timestamp:       *time.New(now.Add(-4 * stdlibtime.Minute)),
			PairAddress:     pairAddress,
			ContractAddress: contractAddress,
			ExternalAddress: externalAddress,
			Type:            TradeTypeBuy,
			TraderAddress:   "0xbuyer1",
			TransactionHash: "0xtx1",
			BasePriceInUsd:  1.0,
			BaseAmount:      mustDecimal(big.NewInt(100000000000000000)),  // 0.1 ION
			Amount:          mustDecimal(big.NewInt(1000000000000000000)), // 1 token
			PriceInUsd:      big.NewFloat(0.10),                           // $0.10
			MarketcapUsd:    big.NewFloat(100.0),
		},
		{
			Timestamp:       *time.New(now.Add(-3 * stdlibtime.Minute)),
			PairAddress:     pairAddress,
			ContractAddress: contractAddress,
			ExternalAddress: externalAddress,
			Type:            TradeTypeBuy,
			TraderAddress:   "0xbuyer2",
			TransactionHash: "0xtx2",
			BasePriceInUsd:  1.0,
			BaseAmount:      mustDecimal(big.NewInt(200000000000000000)),  // 0.2 ION
			Amount:          mustDecimal(big.NewInt(2000000000000000000)), // 2 tokens
			PriceInUsd:      big.NewFloat(0.11),                           // $0.11
			MarketcapUsd:    big.NewFloat(110.0),
		},
		// 1h ago - 1 sell
		{
			Timestamp:       *time.New(now.Add(-50 * stdlibtime.Minute)),
			PairAddress:     pairAddress,
			ContractAddress: contractAddress,
			ExternalAddress: externalAddress,
			Type:            TradeTypeSell,
			TraderAddress:   "0xseller1",
			TransactionHash: "0xtx3",
			BasePriceInUsd:  1.0,
			BaseAmount:      mustDecimal(big.NewInt(150000000000000000)),  // 0.15 ION
			Amount:          mustDecimal(big.NewInt(1500000000000000000)), // 1.5 tokens
			PriceInUsd:      big.NewFloat(0.10),                           // $0.10
			MarketcapUsd:    big.NewFloat(100.0),
		},
		// 6h ago - 1 buy
		{
			Timestamp:       *time.New(now.Add(-5 * stdlibtime.Hour)),
			PairAddress:     pairAddress,
			ContractAddress: contractAddress,
			ExternalAddress: externalAddress,
			Type:            TradeTypeBuy,
			TraderAddress:   "0xbuyer3",
			TransactionHash: "0xtx4",
			BasePriceInUsd:  1.0,
			BaseAmount:      mustDecimal(big.NewInt(300000000000000000)),  // 0.3 ION
			Amount:          mustDecimal(big.NewInt(3000000000000000000)), // 3 tokens
			PriceInUsd:      big.NewFloat(0.09),                           // $0.09
			MarketcapUsd:    big.NewFloat(90.0),
		},
		// 24h ago - 1 sell
		{
			Timestamp:       *time.New(now.Add(-23 * stdlibtime.Hour)),
			PairAddress:     pairAddress,
			ContractAddress: contractAddress,
			ExternalAddress: externalAddress,
			Type:            TradeTypeSell,
			TraderAddress:   "0xseller2",
			TransactionHash: "0xtx5",
			BasePriceInUsd:  1.0,
			BaseAmount:      mustDecimal(big.NewInt(100000000000000000)),  // 0.1 ION
			Amount:          mustDecimal(big.NewInt(1000000000000000000)), // 1 token
			PriceInUsd:      big.NewFloat(0.08),                           // $0.08
			MarketcapUsd:    big.NewFloat(80.0),
		},
		// Current price reference (1 min ago)
		{
			Timestamp:       *time.New(now.Add(-1 * stdlibtime.Minute)),
			PairAddress:     pairAddress,
			ContractAddress: contractAddress,
			ExternalAddress: externalAddress,
			Type:            TradeTypeBuy,
			TraderAddress:   "0xbuyer4",
			TransactionHash: "0xtx6",
			BasePriceInUsd:  1.0,
			BaseAmount:      mustDecimal(big.NewInt(100000000000000000)),  // 0.1 ION
			Amount:          mustDecimal(big.NewInt(1000000000000000000)), // 1 token
			PriceInUsd:      big.NewFloat(0.12),                           // $0.12 (current)
			MarketcapUsd:    big.NewFloat(120.0),
		},
	}

	err := questdb.Write(t.Context(), ta.questDB, trades...)
	require.NoError(t, err, "failed to insert test trades")

	var stats *TradeStats
	require.Eventually(t, func() bool {
		stats, err = ta.GetTradingStats(t.Context(), now, externalAddress)
		return err == nil && stats != nil && stats.Bucket5Min != nil && stats.Bucket5Min.NumberOfBuys == 3
	}, 10*stdlibtime.Second, 100*stdlibtime.Millisecond, "QuestDB should flush data")

	require.NoError(t, err)
	require.NotNil(t, stats)

	// Test 5m bucket (includes trades at -4min, -3min, -1min)
	require.NotNil(t, stats.Bucket5Min, "5m bucket should not be nil")
	require.Equal(t, uint64(3), stats.Bucket5Min.NumberOfBuys, "5m should have 3 buys")
	require.Equal(t, uint64(0), stats.Bucket5Min.NumberOfSells, "5m should have 0 sells")
	require.InDelta(t, 0.44, stats.Bucket5Min.BuysTotalAmountUSD, 0.001, "5m buys total: (1*0.10) + (2*0.11) + (1*0.12) = 0.44")
	require.InDelta(t, 0.0, stats.Bucket5Min.SellsTotalAmountUSD, 0.001, "5m sells total should be 0")
	require.InDelta(t, 0.44, stats.Bucket5Min.VolumeUSD, 0.001, "5m volume: 0.44")
	require.InDelta(t, 0.44, stats.Bucket5Min.NetBuy, 0.001, "5m net buy: 0.44 - 0 = 0.44")

	// Test 1h bucket (includes 5m trades + 50min ago trade)
	require.NotNil(t, stats.Bucket1Hour, "1h bucket should not be nil")
	require.Equal(t, uint64(3), stats.Bucket1Hour.NumberOfBuys, "1h should have 3 buys (from 5m)")
	require.Equal(t, uint64(1), stats.Bucket1Hour.NumberOfSells, "1h should have 1 sell")
	require.InDelta(t, 0.44, stats.Bucket1Hour.BuysTotalAmountUSD, 0.001, "1h buys total: 0.44")
	require.InDelta(t, 0.15, stats.Bucket1Hour.SellsTotalAmountUSD, 0.001, "1h sells total: (1.5*0.10) = 0.15")
	require.InDelta(t, 0.59, stats.Bucket1Hour.VolumeUSD, 0.001, "1h volume: 0.44 + 0.15 = 0.59")
	require.InDelta(t, 0.29, stats.Bucket1Hour.NetBuy, 0.001, "1h net buy: 0.44 - 0.15 = 0.29")

	// Test 6h bucket (includes all above + 5h ago trade)
	require.NotNil(t, stats.Bucket6Hours, "6h bucket should not be nil")
	require.Equal(t, uint64(4), stats.Bucket6Hours.NumberOfBuys, "6h should have 4 buys")
	require.Equal(t, uint64(1), stats.Bucket6Hours.NumberOfSells, "6h should have 1 sell")
	require.InDelta(t, 0.71, stats.Bucket6Hours.BuysTotalAmountUSD, 0.001, "6h buys total: 0.44 + (3*0.09) = 0.71")
	require.InDelta(t, 0.15, stats.Bucket6Hours.SellsTotalAmountUSD, 0.001, "6h sells total: 0.15")
	require.InDelta(t, 0.86, stats.Bucket6Hours.VolumeUSD, 0.001, "6h volume: 0.71 + 0.15 = 0.86")
	require.InDelta(t, 0.56, stats.Bucket6Hours.NetBuy, 0.001, "6h net buy: 0.71 - 0.15 = 0.56")

	// Test 24h bucket (includes all trades)
	require.NotNil(t, stats.Bucket24Hours, "24h bucket should not be nil")
	require.Equal(t, uint64(4), stats.Bucket24Hours.NumberOfBuys, "24h should have 4 buys")
	require.Equal(t, uint64(2), stats.Bucket24Hours.NumberOfSells, "24h should have 2 sells")
	require.InDelta(t, 0.71, stats.Bucket24Hours.BuysTotalAmountUSD, 0.001, "24h buys total: 0.71")
	require.InDelta(t, 0.23, stats.Bucket24Hours.SellsTotalAmountUSD, 0.001, "24h sells total: 0.15 + (1*0.08) = 0.23")
	require.InDelta(t, 0.94, stats.Bucket24Hours.VolumeUSD, 0.001, "24h volume: 0.71 + 0.23 = 0.94")
	require.InDelta(t, 0.48, stats.Bucket24Hours.NetBuy, 0.001, "24h net buy: 0.71 - 0.23 = 0.48")

	if stats.Bucket5Min.PriceAgo > 0 {
		expectedDiff := ((0.12 - stats.Bucket5Min.PriceAgo) / stats.Bucket5Min.PriceAgo) * 100
		require.InDelta(t, expectedDiff, stats.Bucket5Min.PriceDiff, 0.1, "5m priceDiff should be calculated correctly")
	}
}

func TestGetTradingStats_NoData(t *testing.T) {
	t.Parallel()
	db, connString, release := helperCreateDBWithConnString(t)
	defer release()

	ta := helperNewForTestWithConnString(t, db, connString)

	externalAddress := "0:no_data_token:test"
	now := stdlibtime.Now().UTC()

	stats, err := ta.GetTradingStats(t.Context(), now, externalAddress)
	require.NoError(t, err)
	require.NotNil(t, stats)

	if stats.Bucket5Min != nil {
		require.Equal(t, uint64(0), stats.Bucket5Min.NumberOfBuys)
		require.Equal(t, uint64(0), stats.Bucket5Min.NumberOfSells)
		require.Equal(t, 0.0, stats.Bucket5Min.VolumeUSD)
	}

	if stats.Bucket1Hour != nil {
		require.Equal(t, uint64(0), stats.Bucket1Hour.NumberOfBuys)
		require.Equal(t, uint64(0), stats.Bucket1Hour.NumberOfSells)
		require.Equal(t, 0.0, stats.Bucket1Hour.VolumeUSD)
	}
}

func TestGetTradingStats_OnlyBuys(t *testing.T) {
	t.Parallel()
	db, connString, release := helperCreateDBWithConnString(t)
	defer release()

	ta := helperNewForTestWithConnString(t, db, connString)

	externalAddress := "0:only_buys_token:test"
	contractAddress := "0x2234567890abcdef1234567890abcdef12345678"
	pairAddress := "0xbbcdef1234567890abcdef1234567890abcdef12"

	now := stdlibtime.Now().UTC()

	trades := []*trade{
		{
			Timestamp:       *time.New(now.Add(-2 * stdlibtime.Minute)),
			PairAddress:     pairAddress,
			ContractAddress: contractAddress,
			ExternalAddress: externalAddress,
			Type:            TradeTypeBuy,
			TraderAddress:   "0xbuyer1",
			TransactionHash: "0xtxbuy1",
			BasePriceInUsd:  1.0,
			BaseAmount:      mustDecimal(big.NewInt(500000000000000000)),  // 0.5 ION
			Amount:          mustDecimal(big.NewInt(5000000000000000000)), // 5 tokens
			PriceInUsd:      big.NewFloat(0.10),
			MarketcapUsd:    big.NewFloat(50.0),
		},
		{
			Timestamp:       *time.New(now.Add(-1 * stdlibtime.Minute)),
			PairAddress:     pairAddress,
			ContractAddress: contractAddress,
			ExternalAddress: externalAddress,
			Type:            TradeTypeBuy,
			TraderAddress:   "0xbuyer2",
			TransactionHash: "0xtxbuy2",
			BasePriceInUsd:  1.0,
			BaseAmount:      mustDecimal(big.NewInt(300000000000000000)),  // 0.3 ION
			Amount:          mustDecimal(big.NewInt(3000000000000000000)), // 3 tokens
			PriceInUsd:      big.NewFloat(0.10),
			MarketcapUsd:    big.NewFloat(80.0),
		},
	}

	err := questdb.Write(t.Context(), ta.questDB, trades...)
	require.NoError(t, err)

	var stats *TradeStats
	require.Eventually(t, func() bool {
		stats, err = ta.GetTradingStats(t.Context(), now, externalAddress)
		return err == nil && stats != nil && stats.Bucket5Min != nil && stats.Bucket5Min.NumberOfBuys == 2
	}, 10*stdlibtime.Second, 100*stdlibtime.Millisecond, "QuestDB should flush data")

	require.NoError(t, err)
	require.NotNil(t, stats)

	require.NotNil(t, stats.Bucket5Min)
	require.Equal(t, uint64(2), stats.Bucket5Min.NumberOfBuys)
	require.Equal(t, uint64(0), stats.Bucket5Min.NumberOfSells)
	require.InDelta(t, 0.8, stats.Bucket5Min.BuysTotalAmountUSD, 0.001, "buys: 0.5 + 0.3 = 0.8")
	require.Equal(t, 0.0, stats.Bucket5Min.SellsTotalAmountUSD)
	require.InDelta(t, 0.8, stats.Bucket5Min.NetBuy, 0.001, "net buy should equal buys total")
}

func TestGetTradingStats_OnlySells(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, connString, release := helperCreateDBWithConnString(t)
	defer release()

	ta := helperNewForTestWithConnString(t, db, connString)

	externalAddress := "0:only_sells_token:test"
	contractAddress := "0x3234567890abcdef1234567890abcdef12345678"
	pairAddress := "0xcbcdef1234567890abcdef1234567890abcdef12"

	now := stdlibtime.Now().UTC()

	// Insert only sell trades
	trades := []*trade{
		{
			Timestamp:       *time.New(now.Add(-2 * stdlibtime.Minute)),
			PairAddress:     pairAddress,
			ContractAddress: contractAddress,
			ExternalAddress: externalAddress,
			Type:            TradeTypeSell,
			TraderAddress:   "0xseller1",
			TransactionHash: "0xtxsell1",
			BasePriceInUsd:  1.0,
			BaseAmount:      mustDecimal(big.NewInt(400000000000000000)),  // 0.4 ION
			Amount:          mustDecimal(big.NewInt(4000000000000000000)), // 4 tokens
			PriceInUsd:      big.NewFloat(0.10),
			MarketcapUsd:    big.NewFloat(40.0),
		},
		{
			Timestamp:       *time.New(now.Add(-1 * stdlibtime.Minute)),
			PairAddress:     pairAddress,
			ContractAddress: contractAddress,
			ExternalAddress: externalAddress,
			Type:            TradeTypeSell,
			TraderAddress:   "0xseller2",
			TransactionHash: "0xtxsell2",
			BasePriceInUsd:  1.0,
			BaseAmount:      mustDecimal(big.NewInt(200000000000000000)),  // 0.2 ION
			Amount:          mustDecimal(big.NewInt(2000000000000000000)), // 2 tokens
			PriceInUsd:      big.NewFloat(0.10),
			MarketcapUsd:    big.NewFloat(20.0),
		},
	}

	err := questdb.Write(ctx, ta.questDB, trades...)
	require.NoError(t, err)

	var stats *TradeStats
	require.Eventually(t, func() bool {
		stats, err = ta.GetTradingStats(ctx, now, externalAddress)
		return err == nil && stats != nil && stats.Bucket5Min != nil && stats.Bucket5Min.NumberOfSells == 2
	}, 10*stdlibtime.Second, 100*stdlibtime.Millisecond, "QuestDB should flush data")

	require.NoError(t, err)
	require.NotNil(t, stats)

	require.NotNil(t, stats.Bucket5Min)
	require.Equal(t, uint64(0), stats.Bucket5Min.NumberOfBuys)
	require.Equal(t, uint64(2), stats.Bucket5Min.NumberOfSells)
	require.Equal(t, 0.0, stats.Bucket5Min.BuysTotalAmountUSD)
	require.InDelta(t, 0.6, stats.Bucket5Min.SellsTotalAmountUSD, 0.001, "sells: 0.4 + 0.2 = 0.6")
	require.InDelta(t, -0.6, stats.Bucket5Min.NetBuy, 0.001, "net buy should be negative (net sell)")
}

func TestRegisterTrade(t *testing.T) {
	t.Parallel()
	t.Run("registers buy trade correctly", func(t *testing.T) {
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		ta := helperNewForTestWithConnString(t, db, connString)

		now := stdlibtime.Now().UTC()
		blockTimestamp := time.New(now)
		pairId, _ := hex.DecodeString("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
		totalSupply := new(big.Int)
		totalSupply.SetString("1000000000000000000000000000", 10) // 1B tokens
		burned := big.NewInt(0)

		tx := &txEvent{
			BlockTimestamp:  blockTimestamp,
			TransactionHash: "0xtx_register_buy_1",
		}

		// direction=false => buy
		inputAmount := big.NewInt(1000000000000000000)     // 1 ION (base token)
		outputAmount := mustBigInt("10000000000000000000") // 10 community tokens

		_, err := ta.registerTrade(t.Context(), tx, false, inputAmount, outputAmount,
			"0xcontract_register_1", "0xuser_register_1", "ext_register_1",
			ta.cfg.IONTokenAddress, pairId, totalSupply, burned, 0.1, 100.0)
		require.NoError(t, err)

		type tradeRow struct {
			ExternalAddress string  `db:"external_address"`
			TradeType       string  `db:"trade_type"`
			TraderAddress   string  `db:"trader_address"`
			TransactionHash string  `db:"transaction_hash"`
			PriceInUsd      float64 `db:"price_in_usd"`
			MarketCapUsd    float64 `db:"market_cap_usd"`
		}
		var row *tradeRow
		require.Eventually(t, func() bool {
			row, err = questdb.Get[tradeRow](t.Context(), ta.questDB,
				`SELECT external_address, trade_type, trader_address, transaction_hash, price_in_usd, market_cap_usd FROM trades WHERE transaction_hash = $1`,
				"0xtx_register_buy_1")
			return err == nil
		}, 10*stdlibtime.Second, 100*stdlibtime.Millisecond, "QuestDB should flush trade data")
		require.NoError(t, err)
		require.Equal(t, "ext_register_1", row.ExternalAddress)
		require.Equal(t, "buy", row.TradeType)
		require.Equal(t, "0xuser_register_1", row.TraderAddress)
		require.InDelta(t, 0.1, row.PriceInUsd, 0.001, "priceInUSD passed directly = $0.1")

		candlestick, ok := ta.ohclvRecentData.Load("15s_ext_register_1")
		require.True(t, ok, "candlestick should be created for 15s interval")
		ohlcv := candlestick.OHLCV()
		require.InDelta(t, 0.1, ohlcv.Open, 0.001)
		require.InDelta(t, 0.1, ohlcv.Close, 0.001)
		require.InDelta(t, 0.1, ohlcv.High, 0.001)
		require.InDelta(t, 0.1, ohlcv.Low, 0.001)
	})

	t.Run("registers sell trade correctly", func(t *testing.T) {
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		ta := helperNewForTestWithConnString(t, db, connString)

		now := stdlibtime.Now().UTC()
		blockTimestamp := time.New(now)
		pairId, _ := hex.DecodeString("bbcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
		totalSupply := new(big.Int)
		totalSupply.SetString("1000000000000000000000000000", 10)
		burned := big.NewInt(0)

		tx := &txEvent{
			BlockTimestamp:  blockTimestamp,
			TransactionHash: "0xtx_register_sell_1",
		}

		// direction=true => sell: user sends 10 community tokens, receives 1 ION
		inputAmount := mustBigInt("10000000000000000000") // 10 community tokens
		outputAmount := big.NewInt(1000000000000000000)   // 1 ION (base token)

		_, err := ta.registerTrade(t.Context(), tx, true, inputAmount, outputAmount,
			"0xcontract_register_2", "0xuser_register_2", "ext_register_2",
			ta.cfg.IONTokenAddress, pairId, totalSupply, burned, 0.1, 100.0)
		require.NoError(t, err)

		type tradeRow struct {
			TradeType  string  `db:"trade_type"`
			PriceInUsd float64 `db:"price_in_usd"`
		}
		var row *tradeRow
		require.Eventually(t, func() bool {
			row, err = questdb.Get[tradeRow](t.Context(), ta.questDB,
				`SELECT trade_type, price_in_usd FROM trades WHERE transaction_hash = $1`,
				"0xtx_register_sell_1")
			return err == nil
		}, 10*stdlibtime.Second, 100*stdlibtime.Millisecond, "QuestDB should flush trade data")
		require.NoError(t, err)
		require.Equal(t, "sell", row.TradeType)
		require.InDelta(t, 0.1, row.PriceInUsd, 0.001, "priceInUSD passed directly = $0.1")
	})

	t.Run("updates in-memory candlestick with multiple trades", func(t *testing.T) {
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		ta := helperNewForTestWithConnString(t, db, connString)

		pairId, _ := hex.DecodeString("cccdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
		totalSupply := new(big.Int)
		totalSupply.SetString("1000000000000000000000000000", 10)
		burned := big.NewInt(0)
		extAddr := "ext_register_multi"

		// Trade 1: buy at price 0.1 ION/token => 0.115 USD
		now := stdlibtime.Now().UTC()
		_, err := ta.registerTrade(t.Context(), &txEvent{
			BlockTimestamp:  time.New(now),
			TransactionHash: "0xtx_multi_1",
		}, false, big.NewInt(1e18), mustBigInt("10000000000000000000"),
			"0xcontract_multi", "0xuser_multi", extAddr,
			ta.cfg.IONTokenAddress, pairId, totalSupply, burned, 0.1, 100.0)
		require.NoError(t, err)

		// Trade 2: buy at price 0.2 ION/token => 0.23 USD
		_, err = ta.registerTrade(t.Context(), &txEvent{
			BlockTimestamp:  time.New(now.Add(1 * stdlibtime.Second)),
			TransactionHash: "0xtx_multi_2",
		}, false, big.NewInt(2e18), mustBigInt("10000000000000000000"),
			"0xcontract_multi", "0xuser_multi", extAddr,
			ta.cfg.IONTokenAddress, pairId, totalSupply, burned, 0.2, 200.0)
		require.NoError(t, err)

		// Trade 3: buy at price 0.05 ION/token => 0.0575 USD
		_, err = ta.registerTrade(t.Context(), &txEvent{
			BlockTimestamp:  time.New(now.Add(2 * stdlibtime.Second)),
			TransactionHash: "0xtx_multi_3",
		}, false, big.NewInt(5e17), mustBigInt("10000000000000000000"),
			"0xcontract_multi", "0xuser_multi", extAddr,
			ta.cfg.IONTokenAddress, pairId, totalSupply, burned, 0.05, 50.0)
		require.NoError(t, err)

		candlestick, ok := ta.ohclvRecentData.Load("15s_" + extAddr)
		require.True(t, ok)
		ohlcv := candlestick.OHLCV()

		// Open = first trade price = 0.1
		require.InDelta(t, 0.1, ohlcv.Open, 0.001)
		// High = max(0.1, 0.2, 0.05) = 0.2
		require.InDelta(t, 0.2, ohlcv.High, 0.001)
		// Low = min(0.1, 0.2, 0.05) = 0.05
		require.InDelta(t, 0.05, ohlcv.Low, 0.001)
		// Close = last trade price = 0.05
		require.InDelta(t, 0.05, ohlcv.Close, 0.001)
	})

	t.Run("updates in-memory trading stats when subscription exists", func(t *testing.T) {
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		ta := helperNewForTestWithConnString(t, db, connString)

		pairId, _ := hex.DecodeString("ddddef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
		totalSupply := new(big.Int)
		totalSupply.SetString("1000000000000000000000000000", 10)
		burned := big.NewInt(0)
		extAddr := "ext_register_stats"

		initialStats := &TradeStats{
			Bucket5Min:    &TradeStatsAggregate{},
			Bucket1Hour:   &TradeStatsAggregate{},
			Bucket6Hours:  &TradeStatsAggregate{},
			Bucket24Hours: &TradeStatsAggregate{},
		}
		now := stdlibtime.Now().UTC()
		recentStats := newRecentTradingStats(initialStats, now)
		ta.tradingStatsRecentData.Store(extAddr, recentStats)

		_, err := ta.registerTrade(t.Context(), &txEvent{
			BlockTimestamp:  time.New(now),
			TransactionHash: "0xtx_stats_1",
		}, false, big.NewInt(1e18), mustBigInt("10000000000000000000"),
			"0xcontract_stats", "0xuser_stats", extAddr,
			ta.cfg.IONTokenAddress, pairId, totalSupply, burned, 0.115, 115.0)
		require.NoError(t, err)

		stats := recentStats.TradeStats()
		require.Equal(t, uint64(1), stats.Bucket5Min.NumberOfBuys)
		require.Equal(t, uint64(0), stats.Bucket5Min.NumberOfSells)
		// Buy: outputAmount = 10 community tokens, priceInUSD = $0.115/token → volume = 10 * 0.115 = $1.15
		require.InDelta(t, 1.15, stats.Bucket5Min.VolumeUSD, 0.001)
		require.InDelta(t, 1.15, stats.Bucket5Min.BuysTotalAmountUSD, 0.001)
	})

	t.Run("in-memory volume uses amount*price not just price", func(t *testing.T) {
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		ta := helperNewForTestWithConnString(t, db, connString)

		pairId, _ := hex.DecodeString("eeeeef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
		totalSupply := mustBigInt("1000000000000000000000000000")
		burned := big.NewInt(0)
		extAddr := "ext_volume_calc"

		initialStats := &TradeStats{
			Bucket5Min:    &TradeStatsAggregate{},
			Bucket1Hour:   &TradeStatsAggregate{},
			Bucket6Hours:  &TradeStatsAggregate{},
			Bucket24Hours: &TradeStatsAggregate{},
		}
		now := stdlibtime.Now().UTC()
		recentStats := newRecentTradingStats(initialStats, now)
		ta.tradingStatsRecentData.Store(extAddr, recentStats)

		// Buy: 1 ION input → 100 community tokens output, priceInUSD = $0.01/token
		// Expected volume = 100 * $0.01 = $1.00
		_, err := ta.registerTrade(t.Context(), &txEvent{
			BlockTimestamp:  time.New(now),
			TransactionHash: "0xtx_vol_buy",
		}, false, big.NewInt(1e18), mustBigInt("100000000000000000000"),
			"0xcontract_vol", "0xuser_vol", extAddr,
			ta.cfg.IONTokenAddress, pairId, totalSupply, burned, 0.01, 10.0)
		require.NoError(t, err)

		stats := recentStats.TradeStats()
		require.Equal(t, uint64(1), stats.Bucket5Min.NumberOfBuys)
		require.InDelta(t, 1.0, stats.Bucket5Min.VolumeUSD, 0.01, "volume = 100 tokens * $0.01 = $1.00")
		require.InDelta(t, 1.0, stats.Bucket5Min.BuysTotalAmountUSD, 0.01)
		require.InDelta(t, 0.0, stats.Bucket5Min.SellsTotalAmountUSD, 0.01)
		require.InDelta(t, 1.0, stats.Bucket5Min.NetBuy, 0.01)

		// Sell: 50 community tokens input → 0.5 ION output, priceInUSD = $0.01/token
		// Expected volume = 50 * $0.01 = $0.50
		_, err = ta.registerTrade(t.Context(), &txEvent{
			BlockTimestamp:  time.New(now.Add(1 * stdlibtime.Second)),
			TransactionHash: "0xtx_vol_sell",
		}, true, mustBigInt("50000000000000000000"), big.NewInt(5e17),
			"0xcontract_vol", "0xuser_vol_sell", extAddr,
			ta.cfg.IONTokenAddress, pairId, totalSupply, burned, 0.01, 10.0)
		require.NoError(t, err)

		stats = recentStats.TradeStats()
		require.Equal(t, uint64(1), stats.Bucket5Min.NumberOfBuys)
		require.Equal(t, uint64(1), stats.Bucket5Min.NumberOfSells)
		require.InDelta(t, 1.5, stats.Bucket5Min.VolumeUSD, 0.01, "volume = $1.00 + $0.50 = $1.50")
		require.InDelta(t, 1.0, stats.Bucket5Min.BuysTotalAmountUSD, 0.01, "buys unchanged")
		require.InDelta(t, 0.5, stats.Bucket5Min.SellsTotalAmountUSD, 0.01, "sells = 50 * $0.01 = $0.50")
		require.InDelta(t, 0.5, stats.Bucket5Min.NetBuy, 0.01, "net = $1.00 - $0.50 = $0.50")
	})

	t.Run("deduplication: second call with same key returns false", func(t *testing.T) {
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		ta := helperNewForTestWithConnString(t, db, connString)

		now := stdlibtime.Now().UTC()
		pairId, _ := hex.DecodeString("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
		totalSupply := mustBigInt("1000000000000000000000000000")
		burned := big.NewInt(0)

		tx := &txEvent{
			BlockTimestamp:  time.New(now),
			TransactionHash: "0xtx_dedup_1",
		}

		registered1, err := ta.registerTrade(t.Context(), tx, false,
			big.NewInt(1e18), mustBigInt("10000000000000000000"),
			"0xcontract_dedup", "0xuser_dedup", "ext_dedup",
			ta.cfg.IONTokenAddress, pairId, totalSupply, burned, 0.1, 100.0)
		require.NoError(t, err)
		require.True(t, registered1, "first call must return true")

		registered2, err := ta.registerTrade(t.Context(), tx, false,
			big.NewInt(1e18), mustBigInt("10000000000000000000"),
			"0xcontract_dedup", "0xuser_dedup", "ext_dedup",
			ta.cfg.IONTokenAddress, pairId, totalSupply, burned, 0.1, 100.0)
		require.NoError(t, err)
		require.False(t, registered2, "second call with same key must return false (dedup)")
	})

	t.Run("deduplication: different trades both register", func(t *testing.T) {
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		ta := helperNewForTestWithConnString(t, db, connString)

		now := stdlibtime.Now().UTC()
		pairId, _ := hex.DecodeString("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
		totalSupply := mustBigInt("1000000000000000000000000000")
		burned := big.NewInt(0)

		registered1, err := ta.registerTrade(t.Context(), &txEvent{
			BlockTimestamp:  time.New(now),
			TransactionHash: "0xtx_diff_1",
		}, false, big.NewInt(1e18), mustBigInt("10000000000000000000"),
			"0xcontract_diff", "0xuser_diff", "ext_diff",
			ta.cfg.IONTokenAddress, pairId, totalSupply, burned, 0.1, 100.0)
		require.NoError(t, err)
		require.True(t, registered1)

		registered2, err := ta.registerTrade(t.Context(), &txEvent{
			BlockTimestamp:  time.New(now.Add(1 * stdlibtime.Second)),
			TransactionHash: "0xtx_diff_2",
		}, false, big.NewInt(2e18), mustBigInt("10000000000000000000"),
			"0xcontract_diff", "0xuser_diff", "ext_diff",
			ta.cfg.IONTokenAddress, pairId, totalSupply, burned, 0.2, 200.0)
		require.NoError(t, err)
		require.True(t, registered2, "different txHash must register independently")
	})

	t.Run("deduplication: numberOfBuys not double-counted", func(t *testing.T) {
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		ta := helperNewForTestWithConnString(t, db, connString)

		extAddr := "ext_dedup_stats"
		now := stdlibtime.Now().UTC()
		pairId, _ := hex.DecodeString("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
		totalSupply := mustBigInt("1000000000000000000000000000")
		burned := big.NewInt(0)

		initialStats := &TradeStats{
			Bucket5Min:    &TradeStatsAggregate{},
			Bucket1Hour:   &TradeStatsAggregate{},
			Bucket6Hours:  &TradeStatsAggregate{},
			Bucket24Hours: &TradeStatsAggregate{},
		}
		recentStats := newRecentTradingStats(initialStats, now)
		ta.tradingStatsRecentData.Store(extAddr, recentStats)

		tx := &txEvent{
			BlockTimestamp:  time.New(now),
			TransactionHash: "0xtx_dedup_stats_1",
		}

		registered1, err := ta.registerTrade(t.Context(), tx, false,
			big.NewInt(1e18), mustBigInt("10000000000000000000"),
			"0xcontract_dedup_stats", "0xuser_dedup_stats", extAddr,
			ta.cfg.IONTokenAddress, pairId, totalSupply, burned, 0.115, 115.0)
		require.NoError(t, err)
		require.True(t, registered1)

		registered2, err := ta.registerTrade(t.Context(), tx, false,
			big.NewInt(1e18), mustBigInt("10000000000000000000"),
			"0xcontract_dedup_stats", "0xuser_dedup_stats", extAddr,
			ta.cfg.IONTokenAddress, pairId, totalSupply, burned, 0.115, 115.0)
		require.NoError(t, err)
		require.False(t, registered2, "duplicate must be rejected")

		stats := recentStats.TradeStats()
		require.Equal(t, uint64(1), stats.Bucket5Min.NumberOfBuys,
			"numberOfBuys must be 1 despite two registerTrade calls")
		// volume = 10 tokens * $0.115/token = $1.15
		require.InDelta(t, 1.15, stats.Bucket5Min.VolumeUSD, 0.001,
			"volume must reflect single trade only")
	})
}

func TestGetOHLVCHistory(t *testing.T) {
	t.Run("returns OHLCV data for 15s interval", func(t *testing.T) {
		ctx := context.Background()
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		ta := helperNewForTestWithConnString(t, db, connString)

		extAddr := "ext_ohlvc_15s"
		contractAddr := "0xcontract_ohlvc_15s"
		pairAddr := "0xpair_ohlvc_15s"
		now := stdlibtime.Now().UTC()

		trades := []*trade{
			{
				Timestamp:       *time.New(now.Add(-45 * stdlibtime.Second)),
				PairAddress:     pairAddr,
				ContractAddress: contractAddr,
				ExternalAddress: extAddr,
				Type:            TradeTypeBuy,
				TraderAddress:   "0xbuyer1",
				TransactionHash: "0xtx_ohlvc_1",
				BasePriceInUsd:  1.0,
				BaseAmount:      mustDecimal(big.NewInt(1e18)),
				Amount:          mustDecimal(mustBigInt("10000000000000000000")),
				PriceInUsd:      big.NewFloat(0.10),
				MarketcapUsd:    big.NewFloat(100.0),
			},
			{
				Timestamp:       *time.New(now.Add(-44 * stdlibtime.Second)),
				PairAddress:     pairAddr,
				ContractAddress: contractAddr,
				ExternalAddress: extAddr,
				Type:            TradeTypeBuy,
				TraderAddress:   "0xbuyer2",
				TransactionHash: "0xtx_ohlvc_2",
				BasePriceInUsd:  1.0,
				BaseAmount:      mustDecimal(big.NewInt(2e18)),
				Amount:          mustDecimal(mustBigInt("10000000000000000000")),
				PriceInUsd:      big.NewFloat(0.20),
				MarketcapUsd:    big.NewFloat(200.0),
			},
			{
				Timestamp:       *time.New(now.Add(-30 * stdlibtime.Second)),
				PairAddress:     pairAddr,
				ContractAddress: contractAddr,
				ExternalAddress: extAddr,
				Type:            TradeTypeSell,
				TraderAddress:   "0xseller1",
				TransactionHash: "0xtx_ohlvc_3",
				BasePriceInUsd:  1.0,
				BaseAmount:      mustDecimal(big.NewInt(15e17)),
				Amount:          mustDecimal(mustBigInt("10000000000000000000")),
				PriceInUsd:      big.NewFloat(0.15),
				MarketcapUsd:    big.NewFloat(150.0),
			},
		}

		err := questdb.Write(ctx, ta.questDB, trades...)
		require.NoError(t, err)

		interval := Interval("15s")
		var result []*OHLCV
		require.Eventually(t, func() bool {
			result, err = ta.GetOHLVCHistory(ctx, now, extAddr, interval, 10, 0)
			return err == nil && len(result) > 0
		}, 30*stdlibtime.Second, 100*stdlibtime.Millisecond, "QuestDB should flush OHLVC data")

		require.NoError(t, err)
		require.NotEmpty(t, result, "should return at least one OHLCV candle")

		require.InDelta(t, 0.0, result[0].Open, 1.0, "open should be a valid price")
		require.True(t, result[0].High >= result[0].Low, "high should be >= low")
	})

	t.Run("returns empty for non-existent token", func(t *testing.T) {
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		ta := helperNewForTestWithConnString(t, db, connString)

		now := stdlibtime.Now().UTC()
		interval := Interval("15s")
		result, err := ta.GetOHLVCHistory(t.Context(), now, "ext_nonexistent", interval, 10, 0)
		require.NoError(t, err)
		require.Empty(t, result)
	})

	t.Run("rejects invalid interval", func(t *testing.T) {
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		ta := helperNewForTestWithConnString(t, db, connString)

		now := stdlibtime.Now().UTC()
		interval := Interval("999x")
		_, err := ta.GetOHLVCHistory(t.Context(), now, "ext_any", interval, 10, 0)
		require.Error(t, err)
	})

	t.Run("respects limit parameter", func(t *testing.T) {
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		ta := helperNewForTestWithConnString(t, db, connString)

		extAddr := "ext_ohlvc_limit"
		contractAddr := "0xcontract_ohlvc_limit"
		pairAddr := "0xpair_ohlvc_limit"
		now := stdlibtime.Now().UTC()

		var tradesList []*trade
		for i := 0; i < 5; i++ {
			tradesList = append(tradesList, &trade{
				Timestamp:       *time.New(now.Add(-stdlibtime.Duration(i*16) * stdlibtime.Second)),
				PairAddress:     pairAddr,
				ContractAddress: contractAddr,
				ExternalAddress: extAddr,
				Type:            TradeTypeBuy,
				TraderAddress:   "0xbuyer_limit",
				TransactionHash: "0xtx_ohlvc_limit_" + stdlibtime.Duration(i).String(),
				BasePriceInUsd:  1.0,
				BaseAmount:      mustDecimal(big.NewInt(1e18)),
				Amount:          mustDecimal(mustBigInt("10000000000000000000")),
				PriceInUsd:      big.NewFloat(float64(i+1) * 0.01),
				MarketcapUsd:    big.NewFloat(float64(i+1) * 10.0),
			})
		}

		err := questdb.Write(t.Context(), ta.questDB, tradesList...)
		require.NoError(t, err)

		interval := Interval("15s")
		var result []*OHLCV
		require.Eventually(t, func() bool {
			result, err = ta.GetOHLVCHistory(t.Context(), now, extAddr, interval, 2, 0)
			return err == nil && len(result) > 0
		}, 30*stdlibtime.Second, 100*stdlibtime.Millisecond, "QuestDB should flush OHLVC data")

		require.NoError(t, err)
		require.LessOrEqual(t, len(result), 2, "should respect limit of 2")
	})
}

func TestSubscribeTradingStats(t *testing.T) {
	t.Parallel()
	t.Run("delivers initial stats on subscribe", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*stdlibtime.Second)
		defer cancel()

		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		ta := helperNewForTestWithConnString(t, db, connString)

		extAddr := "ext_subscribe_stats_1"
		now := stdlibtime.Now().UTC()

		received := make(chan *TradeStats, 10)
		err := ta.SubscribeTradingStats(ctx, now, extAddr, "test-user", func(stats *TradeStats, err error) {
			if err == nil && stats != nil {
				received <- stats
			}
		})
		require.NoError(t, err)

		select {
		case stats := <-received:
			require.NotNil(t, stats)
		case <-stdlibtime.After(10 * stdlibtime.Second):
			t.Fatal("did not receive initial stats within 10s")
		}
	})

	t.Run("delivers updates on swap notification", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*stdlibtime.Second)
		defer cancel()

		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		ta := helperNewForTestWithConnString(t, db, connString)

		extAddr := "ext_subscribe_stats_2"
		now := stdlibtime.Now().UTC()

		received := make(chan *TradeStats, 10)
		err := ta.SubscribeTradingStats(ctx, now, extAddr, "test-user", func(stats *TradeStats, err error) {
			if err == nil && stats != nil {
				received <- stats
			}
		})
		require.NoError(t, err)

		select {
		case <-received:
		case <-stdlibtime.After(10 * stdlibtime.Second):
			t.Fatal("did not receive initial stats")
		}

		recentStats, _ := ta.tradingStatsRecentData.Load(extAddr)
		require.NotNil(t, recentStats, "recentStats should have been created by SubscribeTradingStats")

		recentStats.update(stdlibtime.Now().UnixNano(), 0.5, 0.5, false)

		var receivedStats *TradeStats
		require.Eventually(t, func() bool {
			ta.subscriptions.NotifySwap(&Trade{
				TokenExternalAddress: extAddr,
			})
			select {
			case stats := <-received:
				receivedStats = stats
				return true
			case <-stdlibtime.After(50 * stdlibtime.Millisecond):
				return false
			}
		}, 5*stdlibtime.Second, 100*stdlibtime.Millisecond, "should receive updated stats after swap notification")

		require.NotNil(t, receivedStats)
		require.Equal(t, uint64(1), receivedStats.Bucket5Min.NumberOfBuys)
		require.InDelta(t, 0.5, receivedStats.Bucket5Min.VolumeUSD, 0.01)
	})

	t.Run("expiration ticker sends update when counts change", func(t *testing.T) {
		initialStats := &TradeStats{
			Bucket5Min:    &TradeStatsAggregate{},
			Bucket1Hour:   &TradeStatsAggregate{},
			Bucket6Hours:  &TradeStatsAggregate{},
			Bucket24Hours: &TradeStatsAggregate{},
		}
		fakeNow := stdlibtime.Now().Add(-4*stdlibtime.Minute - 55*stdlibtime.Second)
		rts := newRecentTradingStats(initialStats, fakeNow)
		rts.tickerInterval = 1 * stdlibtime.Second

		tradeTime := fakeNow.Add(1 * stdlibtime.Second).UnixNano()
		rts.update(tradeTime, 0.5, 0.5, false)

		before := rts.TradeStats()
		require.Equal(t, uint64(1), before.Bucket5Min.NumberOfBuys, "5m bucket should have 1 buy before expiration")
		require.Equal(t, uint64(1), before.Bucket1Hour.NumberOfBuys, "1h bucket should have 1 buy before expiration")

		received := make(chan *TradeStats, 10)
		rts.setOnExpired(func() {
			received <- rts.TradeStats()
		})

		var expiredStats *TradeStats
		require.Eventually(t, func() bool {
			select {
			case stats := <-received:
				if stats.Bucket5Min.NumberOfBuys == 0 {
					expiredStats = stats
					return true
				}
			default:
			}
			return false
		}, 15*stdlibtime.Second, 200*stdlibtime.Millisecond, "ticker should invoke onExpired and deliver SSE update with numberOfBuys=0 for 5m bucket")

		require.NotNil(t, expiredStats)
		require.Equal(t, uint64(0), expiredStats.Bucket5Min.NumberOfBuys, "5m numberOfBuys should be 0 after expiration")
		require.InDelta(t, 0.0, expiredStats.Bucket5Min.VolumeUSD, 0.001, "5m volumeUSD should be 0 after expiration")
		require.Equal(t, uint64(0), expiredStats.Bucket5Min.NumberOfSells, "5m numberOfSells should be 0 after expiration")

		require.Equal(t, uint64(1), expiredStats.Bucket1Hour.NumberOfBuys, "1h numberOfBuys should still be 1")
		require.Equal(t, uint64(1), expiredStats.Bucket6Hours.NumberOfBuys, "6h numberOfBuys should still be 1")
		require.Equal(t, uint64(1), expiredStats.Bucket24Hours.NumberOfBuys, "24h numberOfBuys should still be 1")
	})

	t.Run("ticker restarts after maps become empty and new trade arrives", func(t *testing.T) {
		stats := &TradeStats{
			Bucket5Min:    &TradeStatsAggregate{},
			Bucket1Hour:   &TradeStatsAggregate{},
			Bucket6Hours:  &TradeStatsAggregate{},
			Bucket24Hours: &TradeStatsAggregate{},
		}
		rts := &recentTradeStats{
			stats:          stats,
			expirations5M:  orderedmap.NewOrderedMapWithCapacity[int64, TradeStatsAggregate](1),
			expirations1H:  orderedmap.NewOrderedMapWithCapacity[int64, TradeStatsAggregate](1),
			expirations6H:  orderedmap.NewOrderedMapWithCapacity[int64, TradeStatsAggregate](1),
			expirations24H: orderedmap.NewOrderedMapWithCapacity[int64, TradeStatsAggregate](1),
			tickerInterval: 1 * stdlibtime.Second,
		}

		received := make(chan *TradeStats, 10)
		rts.setOnExpired(func() {
			received <- rts.TradeStats()
		})
		rts.ensureTickerRunning()
		require.True(t, rts.tickerRunning.Load())

		require.Eventually(t, func() bool {
			return !rts.tickerRunning.Load()
		}, 10*stdlibtime.Second, 100*stdlibtime.Millisecond,
			"ticker should stop when all expiration maps are empty")

		fakeNow := stdlibtime.Now().Add(-4*stdlibtime.Minute - 55*stdlibtime.Second)
		rts.update(fakeNow.UnixNano(), 0.5, 0.5, false)

		require.True(t, rts.tickerRunning.Load(), "update() should restart the ticker")
		require.Equal(t, uint64(1), rts.TradeStats().Bucket5Min.NumberOfBuys)

		var expiredStats *TradeStats
		require.Eventually(t, func() bool {
			select {
			case stats := <-received:
				if stats.Bucket5Min.NumberOfBuys == 0 {
					expiredStats = stats
					return true
				}
			default:
			}
			return false
		}, 15*stdlibtime.Second, 200*stdlibtime.Millisecond,
			"restarted ticker should deliver expiration update")

		require.NotNil(t, expiredStats)
		require.Equal(t, uint64(0), expiredStats.Bucket5Min.NumberOfBuys)
		require.Equal(t, uint64(1), expiredStats.Bucket1Hour.NumberOfBuys, "1h should still be 1")
	})

	t.Run("expiration delivers update via SubscribeTradingStats e2e", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*stdlibtime.Second)
		defer cancel()

		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		ta := helperNewForTestWithConnString(t, db, connString)

		extAddr := "ext_subscribe_stats_e2e_expiration"
		subscriptionTime := stdlibtime.Now().Add(-4*stdlibtime.Minute - 55*stdlibtime.Second).UTC()

		initialStats := &TradeStats{
			Bucket5Min:    &TradeStatsAggregate{},
			Bucket1Hour:   &TradeStatsAggregate{},
			Bucket6Hours:  &TradeStatsAggregate{},
			Bucket24Hours: &TradeStatsAggregate{},
		}
		preSeeded := newRecentTradingStats(initialStats, subscriptionTime)
		preSeeded.tickerInterval = 1 * stdlibtime.Second
		ta.tradingStatsRecentData.Store(extAddr, preSeeded)

		received := make(chan *TradeStats, 10)
		err := ta.SubscribeTradingStats(ctx, subscriptionTime, extAddr, "test-user-e2e", func(stats *TradeStats, err error) {
			if err == nil && stats != nil {
				received <- stats
			}
		})
		require.NoError(t, err)

		select {
		case <-received:
		case <-stdlibtime.After(10 * stdlibtime.Second):
			t.Fatal("did not receive initial stats")
		}

		recentStats, ok := ta.tradingStatsRecentData.Load(extAddr)
		require.True(t, ok)

		tradeTime := subscriptionTime.Add(1 * stdlibtime.Second).UnixNano()
		recentStats.update(tradeTime, 0.5, 0.5, false)

		ta.subscriptions.NotifySwap(&Trade{TokenExternalAddress: extAddr})
		select {
		case stats := <-received:
			require.Equal(t, uint64(1), stats.Bucket5Min.NumberOfBuys, "subscriber should see buys=1 after trade")
		case <-stdlibtime.After(5 * stdlibtime.Second):
			t.Fatal("did not receive swap update")
		}

		var expiredStats *TradeStats
		require.Eventually(t, func() bool {
			select {
			case stats := <-received:
				if stats.Bucket5Min.NumberOfBuys == 0 {
					expiredStats = stats
					return true
				}
			default:
			}
			return false
		}, 15*stdlibtime.Second, 200*stdlibtime.Millisecond,
			"subscriber should receive expiration update via NotifySwap path: ticker -> onExpired -> NotifySwap -> swaps channel -> addToStream")

		require.NotNil(t, expiredStats)
		require.Equal(t, uint64(0), expiredStats.Bucket5Min.NumberOfBuys)
		require.Equal(t, uint64(1), expiredStats.Bucket1Hour.NumberOfBuys, "1h should still be 1")
	})

	t.Run("channel closure does not cause infinite event loop", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*stdlibtime.Second)
		defer cancel()

		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		ta := helperNewForTestWithConnString(t, db, connString)

		externalAddress := "0:test_trading_stats_channel:"
		now := stdlibtime.Now().UTC()

		eventCount := 0

		addToStream := func(stats *TradeStats, err error) {
			if err != nil {
				t.Logf("Error in stream: %v", err)
				return
			}
			eventCount++
		}

		streamCtx, streamCancel := context.WithCancel(ctx)
		defer streamCancel()

		err := ta.SubscribeTradingStats(streamCtx, now, externalAddress, "test-user-channel-close", addToStream)
		require.NoError(t, err, "SubscribeTradingStats should not return error")

		require.Eventually(t, func() bool {
			return eventCount >= 1
		}, 5*stdlibtime.Second, 100*stdlibtime.Millisecond, "should receive initial trading stats event")

		initialCount := eventCount
		t.Logf("Initial event count: %d", initialCount)

		streamCancel()

		stdlibtime.Sleep(500 * stdlibtime.Millisecond)

		finalCount := eventCount
		t.Logf("Final event count after cancel: %d", finalCount)

		require.Less(t, finalCount-initialCount, 100, "should not generate excessive events after channel closure")
	})

	t.Run("handles multiple swaps without event explosion", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*stdlibtime.Second)
		defer cancel()

		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		ta := helperNewForTestWithConnString(t, db, connString)

		externalAddress := "0:test_trading_stats_multi:"
		now := stdlibtime.Now().UTC()

		eventCount := 0

		addToStream := func(stats *TradeStats, err error) {
			require.NoError(t, err)
			eventCount++
		}

		streamCtx, streamCancel := context.WithCancel(ctx)
		defer streamCancel()

		err := ta.SubscribeTradingStats(streamCtx, now, externalAddress, "test-user", addToStream)
		require.NoError(t, err)

		require.Eventually(t, func() bool {
			return eventCount >= 1
		}, 5*stdlibtime.Second, 100*stdlibtime.Millisecond, "should receive initial event")

		initialCount := eventCount

		for i := 0; i < 5; i++ {
			ta.subscriptions.NotifySwap(&Trade{
				TokenExternalAddress: externalAddress,
			})
			stdlibtime.Sleep(100 * stdlibtime.Millisecond)
		}

		require.Eventually(t, func() bool {
			return eventCount > initialCount+3
		}, 10*stdlibtime.Second, 200*stdlibtime.Millisecond, "should receive multiple swap events")

		swapEventCount := eventCount - initialCount
		t.Logf("Received %d swap events for 5 notifications", swapEventCount)

		require.Less(t, swapEventCount, 100, "should not generate excessive events for 5 swaps")

		streamCancel()
		stdlibtime.Sleep(500 * stdlibtime.Millisecond)

		finalCount := eventCount
		require.Less(t, finalCount-eventCount, 50, "should not generate events after cancel")
	})

	t.Run("multiple swaps generate exactly one event per swap", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*stdlibtime.Second)
		defer cancel()

		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		ta := helperNewForTestWithConnString(t, db, connString)

		externalAddress := "0:test_one_event_per_swap:"
		now := stdlibtime.Now().UTC()

		eventCount := 0
		var eventMutex stdlibsync.Mutex

		addToStream := func(stats *TradeStats, err error) {
			if err != nil {
				return
			}
			eventMutex.Lock()
			eventCount++
			eventMutex.Unlock()
		}

		err := ta.SubscribeTradingStats(ctx, now, externalAddress, "user-multiple-swaps", addToStream)
		require.NoError(t, err)

		require.Eventually(t, func() bool {
			eventMutex.Lock()
			defer eventMutex.Unlock()
			return eventCount >= 1
		}, 5*stdlibtime.Second, 100*stdlibtime.Millisecond, "should receive initial event")

		initialCount := eventCount
		t.Logf("Initial event count: %d", initialCount)

		for i := 0; i < 10; i++ {
			ta.subscriptions.NotifySwap(&Trade{
				TokenExternalAddress: externalAddress,
			})
			stdlibtime.Sleep(50 * stdlibtime.Millisecond)
		}

		stdlibtime.Sleep(500 * stdlibtime.Millisecond)

		eventMutex.Lock()
		finalCount := eventCount
		eventMutex.Unlock()

		swapEvents := finalCount - initialCount
		t.Logf("Received %d events for 10 swaps", swapEvents)

		require.GreaterOrEqual(t, swapEvents, 10, "should receive at least 10 events for 10 swaps")
		require.Less(t, swapEvents, 100, "should not generate excessive events (max 100, got %d)", swapEvents)
	})

	t.Run("verifies fix - reconnection with same userID", func(t *testing.T) {
		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		ta := helperNewForTestWithConnString(t, db, connString)

		externalAddress := "0:test_reconnection_with_fix:"
		now := stdlibtime.Now().UTC()

		eventCount1 := 0
		var eventMutex1 stdlibsync.Mutex

		addToStream1 := func(stats *TradeStats, err error) {
			if err != nil {
				return
			}
			eventMutex1.Lock()
			eventCount1++
			eventMutex1.Unlock()
		}
		ctx1 := context.Background()
		err := ta.SubscribeTradingStats(ctx1, now, externalAddress, "same-user-id", addToStream1)
		require.NoError(t, err)

		stdlibtime.Sleep(100 * stdlibtime.Millisecond)

		initialCount1 := eventCount1
		t.Logf("First connection: initial event count: %d", initialCount1)

		eventCount2 := 0
		var eventMutex2 stdlibsync.Mutex

		addToStream2 := func(stats *TradeStats, err error) {
			if err != nil {
				return
			}
			eventMutex2.Lock()
			eventCount2++
			eventMutex2.Unlock()
		}

		ctx2 := context.Background()
		err = ta.SubscribeTradingStats(ctx2, now, externalAddress, "same-user-id", addToStream2)
		require.NoError(t, err)

		stdlibtime.Sleep(100 * stdlibtime.Millisecond)

		initialCount2 := eventCount2
		t.Logf("Second connection: initial event count: %d", initialCount2)

		ta.subscriptions.NotifySwap(&Trade{
			TokenExternalAddress: externalAddress,
		})

		stdlibtime.Sleep(500 * stdlibtime.Millisecond)

		eventMutex1.Lock()
		finalCount1 := eventCount1
		eventMutex1.Unlock()

		eventMutex2.Lock()
		finalCount2 := eventCount2
		eventMutex2.Unlock()

		explosionEvents1 := finalCount1 - initialCount1
		normalEvents2 := finalCount2 - initialCount2

		t.Logf("First connection (old, WITH FIX): %d events after swap", explosionEvents1)
		t.Logf("Second connection (new, WITH FIX): %d events after swap", normalEvents2)

		require.Less(t, explosionEvents1, 100, "FIX VERIFIED: old goroutine should exit cleanly (got %d events)", explosionEvents1)
		require.GreaterOrEqual(t, normalEvents2, 1, "New connection should receive at least 1 event")
		require.Less(t, normalEvents2, 10, "New connection should not explode")
	})
}

func TestSubscribeOHLVC(t *testing.T) {
	t.Run("delivers updates on swap notification", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*stdlibtime.Second)
		defer cancel()

		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		ta := helperNewForTestWithConnString(t, db, connString)

		extAddr := "ext_subscribe_ohlvc_2"
		now := stdlibtime.Now().UTC()
		interval := Interval("15s")

		cs := newRecentCandlestick()
		cs.Update(0.10, mustBigInt("1000000000000000000000000000"), big.NewInt(0))
		ta.ohclvRecentData.Store(interval.String()+"_"+extAddr, cs)
		cs.SetInterval(ctx, interval)

		received := make(chan *OHLCV, 10)
		err := ta.SubscribeOHLVC(ctx, now, extAddr, "test-user", interval, func(ohlcv *OHLCV, err error) {
			if err == nil && ohlcv != nil {
				received <- ohlcv
			}
		})
		require.NoError(t, err)

		select {
		case <-received:
		case <-stdlibtime.After(10 * stdlibtime.Second):
			t.Fatal("did not receive initial candle")
		}

		cs.Update(0.20, mustBigInt("1000000000000000000000000000"), big.NewInt(0))

		var receivedOHLCV *OHLCV
		require.Eventually(t, func() bool {
			ta.subscriptions.NotifySwap(&Trade{
				TokenExternalAddress: extAddr,
			})
			select {
			case ohlcv := <-received:
				receivedOHLCV = ohlcv
				return true
			case <-stdlibtime.After(50 * stdlibtime.Millisecond):
				return false
			}
		}, 5*stdlibtime.Second, 100*stdlibtime.Millisecond, "should receive updated OHLCV candle after swap notification")

		require.NotNil(t, receivedOHLCV)
		require.InDelta(t, 0.20, receivedOHLCV.High, 0.01)
		require.InDelta(t, 0.20, receivedOHLCV.Close, 0.01)
	})

	t.Run("handles no data gracefully when not loaded", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*stdlibtime.Second)
		defer cancel()

		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		ta := helperNewForTestWithConnString(t, db, connString)

		extAddr := "ext_subscribe_ohlvc_empty"
		now := stdlibtime.Now().UTC()
		interval := Interval("15s")

		received := make(chan *OHLCV, 10)
		err := ta.SubscribeOHLVC(ctx, now, extAddr, "test-user", interval, func(ohlcv *OHLCV, err error) {
			if err == nil && ohlcv != nil {
				received <- ohlcv
			}
		})
		require.NoError(t, err)

		select {
		case ohlcv := <-received:
			t.Fatalf("expected no OHLCV event when there is no data, but got: %+v", ohlcv)
		case <-stdlibtime.After(200 * stdlibtime.Millisecond):
		}
	})
}

func mustDecimal(bi *big.Int) questdb.Decimal {
	return questdb.NewDecimal(bi)
}

func mustBigInt(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("mustBigInt: failed to parse " + s)
	}

	return n
}
