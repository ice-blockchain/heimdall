// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"encoding/hex"
	"math/big"
	"testing"
	stdlibtime "time"

	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/heimdall/token-analytics/internal/questdb"
	"github.com/ice-blockchain/wintr/time"
)

func TestGetTradingStats(t *testing.T) {
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
	}, 5*stdlibtime.Second, 100*stdlibtime.Millisecond, "QuestDB should flush data")

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
	}, 5*stdlibtime.Second, 100*stdlibtime.Millisecond, "QuestDB should flush data")

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
	}, 5*stdlibtime.Second, 100*stdlibtime.Millisecond, "QuestDB should flush data")

	require.NoError(t, err)
	require.NotNil(t, stats)

	require.NotNil(t, stats.Bucket5Min)
	require.Equal(t, uint64(0), stats.Bucket5Min.NumberOfBuys)
	require.Equal(t, uint64(2), stats.Bucket5Min.NumberOfSells)
	require.Equal(t, 0.0, stats.Bucket5Min.BuysTotalAmountUSD)
	require.InDelta(t, 0.6, stats.Bucket5Min.SellsTotalAmountUSD, 0.001, "sells: 0.4 + 0.2 = 0.6")
	require.InDelta(t, -0.6, stats.Bucket5Min.NetBuy, 0.001, "net buy should be negative (net sell)")
}

func mustDecimal(bi *big.Int) questdb.Decimal {
	return questdb.NewDecimal(bi)
}

func mustBigInt(s string) *big.Int {
	n := new(big.Int)
	n.SetString(s, 10)
	return n
}

func TestRegisterTrade(t *testing.T) {

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

		err := ta.registerTrade(t.Context(), tx, false, inputAmount, outputAmount,
			"0xcontract_register_1", "0xuser_register_1", "ext_register_1",
			ta.cfg.IONTokenAddress, pairId, totalSupply, burned)
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
		}, 5*stdlibtime.Second, 100*stdlibtime.Millisecond, "QuestDB should flush trade data")
		require.NoError(t, err)
		require.Equal(t, "ext_register_1", row.ExternalAddress)
		require.Equal(t, "buy", row.TradeType)
		require.Equal(t, "0xuser_register_1", row.TraderAddress)
		require.InDelta(t, 0.115, row.PriceInUsd, 0.001, "price: 0.1 ION/token * 1.15 USD/ION = 0.115 USD")

		candlestick, ok := ta.ohclvRecentData.Load("15s_ext_register_1")
		require.True(t, ok, "candlestick should be created for 15s interval")
		ohlcv := candlestick.OHLCV()
		require.InDelta(t, 0.115, ohlcv.Open, 0.001)
		require.InDelta(t, 0.115, ohlcv.Close, 0.001)
		require.InDelta(t, 0.115, ohlcv.High, 0.001)
		require.InDelta(t, 0.115, ohlcv.Low, 0.001)
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

		err := ta.registerTrade(t.Context(), tx, true, inputAmount, outputAmount,
			"0xcontract_register_2", "0xuser_register_2", "ext_register_2",
			ta.cfg.IONTokenAddress, pairId, totalSupply, burned)
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
		}, 5*stdlibtime.Second, 100*stdlibtime.Millisecond, "QuestDB should flush trade data")
		require.NoError(t, err)
		require.Equal(t, "sell", row.TradeType)
		require.InDelta(t, 0.115, row.PriceInUsd, 0.001, "price: 0.1 ION/token * 1.15 USD/ION = 0.115 USD")
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
		err := ta.registerTrade(t.Context(), &txEvent{
			BlockTimestamp:  time.New(now),
			TransactionHash: "0xtx_multi_1",
		}, false, big.NewInt(1e18), mustBigInt("10000000000000000000"),
			"0xcontract_multi", "0xuser_multi", extAddr,
			ta.cfg.IONTokenAddress, pairId, totalSupply, burned)
		require.NoError(t, err)

		// Trade 2: buy at price 0.2 ION/token => 0.23 USD
		err = ta.registerTrade(t.Context(), &txEvent{
			BlockTimestamp:  time.New(now.Add(1 * stdlibtime.Second)),
			TransactionHash: "0xtx_multi_2",
		}, false, big.NewInt(2e18), mustBigInt("10000000000000000000"),
			"0xcontract_multi", "0xuser_multi", extAddr,
			ta.cfg.IONTokenAddress, pairId, totalSupply, burned)
		require.NoError(t, err)

		// Trade 3: buy at price 0.05 ION/token => 0.0575 USD
		err = ta.registerTrade(t.Context(), &txEvent{
			BlockTimestamp:  time.New(now.Add(2 * stdlibtime.Second)),
			TransactionHash: "0xtx_multi_3",
		}, false, big.NewInt(5e17), mustBigInt("10000000000000000000"),
			"0xcontract_multi", "0xuser_multi", extAddr,
			ta.cfg.IONTokenAddress, pairId, totalSupply, burned)
		require.NoError(t, err)

		candlestick, ok := ta.ohclvRecentData.Load("15s_" + extAddr)
		require.True(t, ok)
		ohlcv := candlestick.OHLCV()

		// Open = first trade price = 0.115
		require.InDelta(t, 0.115, ohlcv.Open, 0.001)
		// High = max(0.115, 0.23, 0.0575) = 0.23
		require.InDelta(t, 0.23, ohlcv.High, 0.001)
		// Low = min(0.115, 0.23, 0.0575) = 0.0575
		require.InDelta(t, 0.0575, ohlcv.Low, 0.001)
		// Close = last trade price = 0.0575
		require.InDelta(t, 0.0575, ohlcv.Close, 0.001)
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

		err := ta.registerTrade(t.Context(), &txEvent{
			BlockTimestamp:  time.New(now),
			TransactionHash: "0xtx_stats_1",
		}, false, big.NewInt(1e18), mustBigInt("10000000000000000000"),
			"0xcontract_stats", "0xuser_stats", extAddr,
			ta.cfg.IONTokenAddress, pairId, totalSupply, burned)
		require.NoError(t, err)

		stats := recentStats.TradeStats()
		require.Equal(t, uint64(1), stats.Bucket5Min.NumberOfBuys)
		require.Equal(t, uint64(0), stats.Bucket5Min.NumberOfSells)
		require.InDelta(t, 0.115, stats.Bucket5Min.VolumeUSD, 0.001)
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
		}, 5*stdlibtime.Second, 100*stdlibtime.Millisecond, "QuestDB should flush OHLVC data")

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
		}, 5*stdlibtime.Second, 100*stdlibtime.Millisecond, "QuestDB should flush OHLVC data")

		require.NoError(t, err)
		require.LessOrEqual(t, len(result), 2, "should respect limit of 2")
	})
}

func TestSubscribeTradingStats(t *testing.T) {

	t.Run("delivers initial stats on subscribe", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*stdlibtime.Second)
		defer cancel()

		db, connString, release := helperCreateDBWithConnString(t)
		defer release()

		ta := helperNewForTestWithConnString(t, db, connString)

		extAddr := "ext_subscribe_stats_1"
		now := stdlibtime.Now().UTC()

		received := make(chan *TradeStats, 10)
		err := ta.SubscribeTradingStats(ctx, now, extAddr, func(stats *TradeStats, err error) {
			if err == nil && stats != nil {
				received <- stats
			}
		})
		require.NoError(t, err)

		select {
		case stats := <-received:
			require.NotNil(t, stats)
		case <-stdlibtime.After(5 * stdlibtime.Second):
			t.Fatal("did not receive initial stats within 5s")
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
		err := ta.SubscribeTradingStats(ctx, now, extAddr, func(stats *TradeStats, err error) {
			if err == nil && stats != nil {
				received <- stats
			}
		})
		require.NoError(t, err)

		select {
		case <-received:
		case <-stdlibtime.After(5 * stdlibtime.Second):
			t.Fatal("did not receive initial stats")
		}

		recentStats, _ := ta.tradingStatsRecentData.Load(extAddr)
		require.NotNil(t, recentStats, "recentStats should have been created by SubscribeTradingStats")

		recentStats.update(stdlibtime.Now().UnixNano(), 0.5, false)

		ta.subscriptions.NotifySwap(&Trade{
			TokenExternalAddress: extAddr,
		})

		select {
		case stats := <-received:
			require.NotNil(t, stats)
			require.Equal(t, uint64(1), stats.Bucket5Min.NumberOfBuys)
			require.InDelta(t, 0.5, stats.Bucket5Min.VolumeUSD, 0.01)
		case <-stdlibtime.After(5 * stdlibtime.Second):
			t.Fatal("did not receive updated stats after swap notification")
		}
	})
}

func TestSubscribeOHLVC(t *testing.T) {
	// Not parallel - tests share in-memory candlestick data and subscriptions

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
		err := ta.SubscribeOHLVC(ctx, now, extAddr, interval, func(ohlcv *OHLCV, err error) {
			if err == nil && ohlcv != nil {
				received <- ohlcv
			}
		})
		require.NoError(t, err)

		select {
		case <-received:
		case <-stdlibtime.After(5 * stdlibtime.Second):
			t.Fatal("did not receive initial candle")
		}

		cs.Update(0.20, mustBigInt("1000000000000000000000000000"), big.NewInt(0))

		ta.subscriptions.NotifySwap(&Trade{
			TokenExternalAddress: extAddr,
		})

		select {
		case ohlcv := <-received:
			require.NotNil(t, ohlcv)
			require.InDelta(t, 0.20, ohlcv.High, 0.01)
			require.InDelta(t, 0.20, ohlcv.Close, 0.01)
		case <-stdlibtime.After(5 * stdlibtime.Second):
			t.Fatal("did not receive updated OHLCV candle after swap notification")
		}
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
		err := ta.SubscribeOHLVC(ctx, now, extAddr, interval, func(ohlcv *OHLCV, err error) {
			if err == nil && ohlcv != nil {
				received <- ohlcv
			}
		})
		require.NoError(t, err)

		select {
		case ohlcv := <-received:
			require.True(t, ohlcv.Empty(), "should not receive non-empty OHLCV when there is no data")
		case <-stdlibtime.After(1 * stdlibtime.Second):
		}
	})
}
