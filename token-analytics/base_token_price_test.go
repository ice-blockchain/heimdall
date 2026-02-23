// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"math/big"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func TestSaveBaseTokenPriceToDatabase(t *testing.T) {
	t.Parallel()

	db, release := helperCreateDB(t)
	defer release()

	ctx := t.Context()

	t.Run("first insert creates records in both tables", func(t *testing.T) {
		tokenAddress := "0xTEST1111111111111111111111111111111111"
		symbol := "TEST1"
		price := 1.234

		err := saveBaseTokenPriceToDatabase(ctx, db, symbol, tokenAddress, price, big.NewInt(1))
		require.NoError(t, err)

		type priceRow struct {
			TokenAddress string  `db:"token_address"`
			TokenSymbol  string  `db:"token_symbol"`
			PriceUSD     float64 `db:"price_usd"`
		}
		prices, err := storage.Select[priceRow](ctx, db, "SELECT token_address, token_symbol, price_usd FROM base_token_prices WHERE token_address = $1", tokenAddress)
		require.NoError(t, err)
		require.Len(t, prices, 1)
		require.Equal(t, tokenAddress, prices[0].TokenAddress)
		require.Equal(t, symbol, prices[0].TokenSymbol)
		require.InDelta(t, price, prices[0].PriceUSD, 0.0001)

		type historyRow struct {
			TokenAddress string  `db:"token_address"`
			PriceUSD     float64 `db:"price_usd"`
		}
		history, err := storage.Select[historyRow](ctx, db, "SELECT token_address, price_usd FROM base_token_price_history WHERE token_address = $1", tokenAddress)
		require.NoError(t, err)
		require.Len(t, history, 1)
		require.Equal(t, tokenAddress, history[0].TokenAddress)
		require.InDelta(t, price, history[0].PriceUSD, 0.0001)
	})

	t.Run("update with same price does not create history record", func(t *testing.T) {
		tokenAddress := "0xTEST2222222222222222222222222222222222"
		symbol := "TEST2"
		price := 2.345

		err := saveBaseTokenPriceToDatabase(ctx, db, symbol, tokenAddress, price, big.NewInt(1))
		require.NoError(t, err)

		// Update with same price
		err = saveBaseTokenPriceToDatabase(ctx, db, symbol, tokenAddress, price, big.NewInt(1))
		require.NoError(t, err)

		type historyRow struct {
			TokenAddress string  `db:"token_address"`
			PriceUSD     float64 `db:"price_usd"`
		}
		history, err := storage.Select[historyRow](ctx, db, "SELECT token_address, price_usd FROM base_token_price_history WHERE token_address = $1", tokenAddress)
		require.NoError(t, err)
		require.Len(t, history, 1, "should not create duplicate history when price hasn't changed")
	})

	t.Run("update with new price creates history record", func(t *testing.T) {
		tokenAddress := "0xTEST3333333333333333333333333333333333"
		symbol := "TEST3"
		initialPrice := 3.456
		newPrice := 4.567

		err := saveBaseTokenPriceToDatabase(ctx, db, symbol, tokenAddress, initialPrice, big.NewInt(1))
		require.NoError(t, err)

		err = saveBaseTokenPriceToDatabase(ctx, db, symbol, tokenAddress, newPrice, big.NewInt(1))
		require.NoError(t, err)

		type priceRow struct {
			PriceUSD float64 `db:"price_usd"`
		}
		prices, err := storage.Select[priceRow](ctx, db, "SELECT price_usd FROM base_token_prices WHERE token_address = $1", tokenAddress)
		require.NoError(t, err)
		require.Len(t, prices, 1)
		require.InDelta(t, newPrice, prices[0].PriceUSD, 0.0001)

		type historyRow struct {
			PriceUSD float64 `db:"price_usd"`
		}
		history, err := storage.Select[historyRow](ctx, db, "SELECT price_usd FROM base_token_price_history WHERE token_address = $1 ORDER BY created_at ASC", tokenAddress)
		require.NoError(t, err)
		require.Len(t, history, 2, "should create new history record when price changes")
		require.InDelta(t, initialPrice, history[0].PriceUSD, 0.0001)
		require.InDelta(t, newPrice, history[1].PriceUSD, 0.0001)
	})

	t.Run("concurrent inserts with same timestamp do not fail (ON CONFLICT DO NOTHING)", func(t *testing.T) {
		tokenAddress := "0xTEST4444444444444444444444444444444444"
		symbol := "TEST4"
		price := 5.678

		err := saveBaseTokenPriceToDatabase(ctx, db, symbol, tokenAddress, price, big.NewInt(1))
		require.NoError(t, err)

		var wg sync.WaitGroup
		errors := make(chan error, 10)

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(iteration int) {
				defer wg.Done()
				newPrice := price + float64(iteration)*0.1
				err := saveBaseTokenPriceToDatabase(ctx, db, symbol, tokenAddress, newPrice, big.NewInt(1))
				if err != nil {
					errors <- err
				}
			}(i)
		}

		wg.Wait()
		close(errors)

		for err := range errors {
			require.NoError(t, err, "concurrent inserts should not fail due to ON CONFLICT DO NOTHING")
		}

		type priceRow struct {
			TokenAddress string  `db:"token_address"`
			PriceUSD     float64 `db:"price_usd"`
		}
		prices, err := storage.Select[priceRow](ctx, db, "SELECT token_address, price_usd FROM base_token_prices WHERE token_address = $1", tokenAddress)
		require.NoError(t, err)
		require.Len(t, prices, 1)
		require.Equal(t, tokenAddress, prices[0].TokenAddress)

		type historyRow struct {
			TokenAddress string `db:"token_address"`
		}
		history, err := storage.Select[historyRow](ctx, db, "SELECT token_address FROM base_token_price_history WHERE token_address = $1", tokenAddress)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(history), 1, "should have at least initial history record")
	})

	t.Run("multiple price changes create complete history", func(t *testing.T) {
		tokenAddress := "0xTEST5555555555555555555555555555555555"
		symbol := "TEST5"
		prices := []float64{1.0, 2.0, 3.0, 2.5, 4.0}

		for i, price := range prices {
			err := saveBaseTokenPriceToDatabase(ctx, db, symbol, tokenAddress, price, big.NewInt(1))
			require.NoError(t, err, "insert %d should succeed", i)
		}

		type priceRow struct {
			PriceUSD float64 `db:"price_usd"`
		}
		currentPrices, err := storage.Select[priceRow](ctx, db, "SELECT price_usd FROM base_token_prices WHERE token_address = $1", tokenAddress)
		require.NoError(t, err)
		require.Len(t, currentPrices, 1)
		require.InDelta(t, prices[len(prices)-1], currentPrices[0].PriceUSD, 0.0001)

		type historyRow struct {
			PriceUSD float64 `db:"price_usd"`
		}
		history, err := storage.Select[historyRow](ctx, db, "SELECT price_usd FROM base_token_price_history WHERE token_address = $1 ORDER BY created_at ASC", tokenAddress)
		require.NoError(t, err)
		require.Len(t, history, len(prices), "should have complete price history")

		for i, expectedPrice := range prices {
			require.InDelta(t, expectedPrice, history[i].PriceUSD, 0.0001, "history[%d] should match prices[%d]", i, i)
		}
	})

	t.Run("updates symbol when changed", func(t *testing.T) {
		tokenAddress := "0xTEST6666666666666666666666666666666666"
		oldSymbol := "OLD"
		newSymbol := "NEW"
		price := 10.0

		err := saveBaseTokenPriceToDatabase(ctx, db, oldSymbol, tokenAddress, price, big.NewInt(1))
		require.NoError(t, err)

		err = saveBaseTokenPriceToDatabase(ctx, db, newSymbol, tokenAddress, price, big.NewInt(1))
		require.NoError(t, err)

		type priceRow struct {
			TokenSymbol string `db:"token_symbol"`
		}
		prices, err := storage.Select[priceRow](ctx, db, "SELECT token_symbol FROM base_token_prices WHERE token_address = $1", tokenAddress)
		require.NoError(t, err)
		require.Len(t, prices, 1)
		require.Equal(t, newSymbol, prices[0].TokenSymbol)
	})
}
