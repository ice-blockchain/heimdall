//go:build test

// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"encoding/hex"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/heimdall/token-analytics/fixture"
	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/heimdall/token-analytics/internal/questdb"
	wintrtime "github.com/ice-blockchain/wintr/time"
)

func TestRegisterTrade(t *testing.T) {
	fixture.SkipIfShort(t)

	ctx := context.Background()
	var err error
	ta := New(ctx).(*tokenAnalytics)
	ionPrice := 1.15
	ta.ionPriceUSD.Store(&ionPrice)
	now := wintrtime.Now()
	t.Run("writes_trade_to_questdb", func(t *testing.T) {
		tx := &txEvent{
			TransactionHash: "0xtest_trade_hash_123",
			BlockTimestamp:  now,
		}

		pairBytes := [32]byte{}
		copy(pairBytes[:], []byte("test_pair_id_123"))

		inputAmt := new(big.Int)
		inputAmt.SetString("1000000000000000000", 10) // 1 ION
		outputAmt := new(big.Int)
		outputAmt.SetString("10000000000000000000", 10) // 10 tokens

		ev := &bondingcurve.LogTokenSwapped{
			Address:      common.HexToAddress("0xc80e0ff82452cc7c8c4174f9fbc3ffed"),
			Swapper:      common.HexToAddress("0xbe725e59f41de3890fda809744ed6ec2"),
			Pair:         common.BytesToHash(pairBytes[:]),
			Direction:    false, // buy
			InputAmount:  inputAmt,
			OutputAmount: outputAmt,
		}

		ionConnectAddr := "30023:testcreator:article1"
		err = ta.registerTrade(ctx, tx, ev, ionConnectAddr)

		require.NoError(t, err, "registerTrade should not return error")
		t.Log("registerTrade completed successfully - ILP write accepted")
		type readTrade struct {
			Timestamp                time.Time `db:"timestamp"`
			PairAddress              string    `db:"pair_address"`
			ContractAddress          string    `db:"contract_address"`
			ContentIONConnectAddress string    `db:"ion_connect_address"`
			BasePriceInUsd           float64   `db:"base_price_in_usd"`
			BaseAmount               uint64    `db:"base_amount"`
			Amount                   uint64    `db:"amount"`
			PriceInUsd               float64   `db:"price_in_usd"`
			Type                     TradeType `db:"trade_type"`
			TraderAddress            string    `db:"trader_address"`
			TransactionHash          string    `db:"transaction_hash"`
		}
		time.Sleep(100 * time.Millisecond)
		tradeItem, err := questdb.Select[readTrade](ctx, ta.questDB, "SELECT * FROM trades WHERE ion_connect_address = $1;", ionConnectAddr)
		require.NoError(t, err)
		require.Len(t, tradeItem, 1)
		expectedPrice, _ := new(big.Float).Mul(new(big.Float).SetFloat64(ionPrice), new(big.Float).SetFloat64(0.1)).Float64()
		actualPrice := tradeItem[0].PriceInUsd
		tradeItem[0].PriceInUsd = 0
		require.Equal(t, &readTrade{
			Timestamp:                now.Time.Truncate(time.Microsecond),
			PairAddress:              hex.EncodeToString(pairBytes[:]),
			ContractAddress:          ev.Address.Hex(),
			ContentIONConnectAddress: ionConnectAddr,
			BasePriceInUsd:           ionPrice,
			BaseAmount:               inputAmt.Uint64(),
			Amount:                   outputAmt.Uint64(),
			PriceInUsd:               0,
			Type:                     tradeTypeBuy,
			TraderAddress:            ev.Swapper.Hex(),
			TransactionHash:          tx.TransactionHash,
		}, tradeItem[0])
		require.InDelta(t, expectedPrice, actualPrice, 0.000001)
	})
	price := float64(0.0)
	t.Run("handles_sell_trade", func(t *testing.T) {
		tx := &txEvent{
			TransactionHash: "0xtest_sell_trade_456",
			BlockTimestamp:  now,
		}

		pairBytes := [32]byte{}
		copy(pairBytes[:], []byte("sell_pair_id"))

		ev := &bondingcurve.LogTokenSwapped{
			Address:      common.HexToAddress("0x09342c724b6db0929446ef7c137c7823"),
			Swapper:      common.HexToAddress("0x42ea3c177a936a01cb02f93f43d0afc0"),
			Pair:         common.BytesToHash(pairBytes[:]),
			Direction:    true,                            // sell
			InputAmount:  big.NewInt(5000000000000000000), // 5 tokens
			OutputAmount: big.NewInt(500000000000000000),  // 0.5 ION
		}

		ionConnectAddr := "30023:sellercreator:article2"
		err = ta.registerTrade(ctx, tx, ev, ionConnectAddr)
		require.NoError(t, err)
		t.Log("registerTrade for sell completed successfully")

		type readTrade struct {
			Timestamp                time.Time `db:"timestamp"`
			PairAddress              string    `db:"pair_address"`
			ContractAddress          string    `db:"contract_address"`
			ContentIONConnectAddress string    `db:"ion_connect_address"`
			BasePriceInUsd           float64   `db:"base_price_in_usd"`
			BaseAmount               uint64    `db:"base_amount"`
			Amount                   uint64    `db:"amount"`
			PriceInUsd               float64   `db:"price_in_usd"`
			Type                     TradeType `db:"trade_type"`
			TraderAddress            string    `db:"trader_address"`
			TransactionHash          string    `db:"transaction_hash"`
		}
		time.Sleep(100 * time.Millisecond)
		tradeItem, err := questdb.Select[readTrade](ctx, ta.questDB, "SELECT * FROM trades WHERE ion_connect_address = $1;", ionConnectAddr)
		require.NoError(t, err)
		require.Len(t, tradeItem, 1)
		expectedPrice, _ := new(big.Float).Mul(new(big.Float).SetFloat64(ionPrice), new(big.Float).SetFloat64(0.1)).Float64()
		actualPrice := tradeItem[0].PriceInUsd
		tradeItem[0].PriceInUsd = 0
		require.Equal(t, &readTrade{
			Timestamp:                now.Time.Truncate(time.Microsecond),
			PairAddress:              hex.EncodeToString(pairBytes[:]),
			ContractAddress:          ev.Address.Hex(),
			ContentIONConnectAddress: ionConnectAddr,
			BasePriceInUsd:           ionPrice,
			BaseAmount:               ev.OutputAmount.Uint64(),
			Amount:                   ev.InputAmount.Uint64(),
			PriceInUsd:               0,
			Type:                     tradeTypeSell,
			TraderAddress:            ev.Swapper.Hex(),
			TransactionHash:          tx.TransactionHash,
		}, tradeItem[0])
		require.InDelta(t, expectedPrice, actualPrice, 0.000001)
		price = actualPrice
	})
	t.Run("recent ohlcv", func(t *testing.T) {
		ohlcv, err := ta.GetOHLVCRecent(ctx, now.Add(1*time.Second), "30023:sellercreator:article2", Interval("1m"))
		require.NoError(t, err)
		require.NotNil(t, ohlcv)
		require.Equal(t, &OHLCV{
			Timestamp: uint64(now.Truncate(1 * time.Minute).UnixNano()),
			Open:      price,
			High:      price,
			Low:       price,
			Close:     price,
			Volume:    price,
		}, ohlcv)
	})
}

func newAtomicPointer[T any](val *T) *atomic.Pointer[T] {
	ptr := &atomic.Pointer[T]{}
	ptr.Store(val)

	return ptr
}
