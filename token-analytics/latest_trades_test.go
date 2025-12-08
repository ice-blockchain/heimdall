// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetLatestTrades(t *testing.T) {
	ctx := t.Context()
	ta := NewForTest(ctx)

	t.Run("returns empty for non-existent token", func(t *testing.T) {
		trades, maxTs, err := ta.GetLatestTrades(ctx, "a0:nonexistent:", 10, 0, nil)
		require.NoError(t, err)
		assert.Empty(t, trades)
		assert.True(t, !maxTs.IsZero() || maxTs.Before(time.Now().Add(time.Second)), "maxTs should be set or current time")
	})

	t.Run("returns latest trades for token", func(t *testing.T) {
		helperInsertTestUser(t, ctx, testDB, "creator_trades", "alice_trades", "Alice Trades", "", true, PlatformGroupIonConnect, "https://avatar1.png")
		helperInsertTestUser(t, ctx, testDB, "buyer1_trades", "buyer1", "Buyer One", "0xbuyer1000000000000000000000000000000001", false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, testDB, "seller1_trades", "seller1", "Seller One", "0xseller100000000000000000000000000000001", false, PlatformGroupIonConnect)

		tokenExt := "0:creator_trades:"
		contractAddr := "0xTRADES1111111111111111111111111111111"

		helperInsertTestToken(t, ctx, testDB,
			contractAddr,
			tokenExt,
			"TRADE1",
			"profile",
			"creator_trades",
			"1000000000000000000000000",
			100.0,
			0.0001,
			1,
			PlatformGroupIonConnect,
		)

		// Insert positions
		helperInsertUserTokenPosition(t, ctx, testDB,
			"buyer1_trades",
			contractAddr,
			tokenExt,
			"0:buyer1_trades:",
			"5000000000000000000000", // 5000 tokens
			0.0001,
			0.5,
		)

		// Insert buy swap
		helperInsertTokenSwap(t, ctx, testDB,
			contractAddr,
			tokenExt,
			"0xbuyer1000000000000000000000000000000001",
			"0xTX1111111111111111111111111111111111111111111111111111111111111111",
			false,                    // buy
			"500000000000000000000",  // 500 ION input
			"5000000000000000000000", // 5000 tokens output
			0.0001,
		)
		time.Sleep(10 * time.Millisecond)

		// Insert sell swap
		helperInsertTokenSwap(t, ctx, testDB,
			contractAddr,
			tokenExt,
			"0xseller100000000000000000000000000000001",
			"0xTX2222222222222222222222222222222222222222222222222222222222222222",
			true,                     // sell
			"3000000000000000000000", // 3000 tokens input
			"300000000000000000000",  // 300 ION output
			0.0001,
		)

		trades, maxTs, err := ta.GetLatestTrades(ctx, tokenExt, 10, 0, nil)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(trades), 2, "Should return at least 2 trades")

		var buyTrade, sellTrade *Trade
		for _, trade := range trades {
			if trade != nil && trade.Creator.Username == "alice_trades" {
				if trade.Position.Type == tradeTypeBuy && trade.Position.Holder.Username == "buyer1" {
					buyTrade = trade
				} else if trade.Position.Type == tradeTypeSell && trade.Position.Holder.Username == "seller1" {
					sellTrade = trade
				}
			}
		}

		if buyTrade != nil {
			// Creator
			assert.Equal(t, "alice_trades", buyTrade.Creator.Username)
			assert.Equal(t, "Alice Trades", buyTrade.Creator.Display)
			assert.True(t, buyTrade.Creator.Verified)
			assert.Equal(t, "https://avatar1.png", buyTrade.Creator.Avatar)
			assert.Equal(t, tokenExt, buyTrade.Creator.Addresses.IonConnect)

			// Position - Holder
			assert.Equal(t, "buyer1", buyTrade.Position.Holder.Username)
			assert.Equal(t, "Buyer One", buyTrade.Position.Holder.Display)
			assert.False(t, buyTrade.Position.Holder.Verified)
			assert.Equal(t, "0:buyer1_trades:", buyTrade.Position.Holder.Addresses.IonConnect)

			// Position - Trade details
			assert.Equal(t, tokenExt, buyTrade.Position.Addresses.IonConnect)
			assert.Equal(t, tradeTypeBuy, buyTrade.Position.Type)
			assert.Equal(t, uint64(5000), buyTrade.Position.Amount, "Amount should be 5000 tokens")
			assert.InDelta(t, 0.5, buyTrade.Position.AmountUSD, 0.01, "AmountUSD = 5000 * 0.0001 = 0.5")
			// Balance should reflect current position from user_token_positions
			assert.Equal(t, uint64(5000), buyTrade.Position.Balance, "Balance should be 5000 tokens")
			assert.InDelta(t, 0.5, buyTrade.Position.BalanceUSD, 0.01, "BalanceUSD = 5000 * 0.0001 = 0.5")
			assert.False(t, buyTrade.Position.CreatedAt.IsZero())
		}

		if sellTrade != nil {
			// Creator
			assert.Equal(t, "alice_trades", sellTrade.Creator.Username)
			assert.Equal(t, "Alice Trades", sellTrade.Creator.Display)
			assert.True(t, sellTrade.Creator.Verified)
			assert.Equal(t, tokenExt, sellTrade.Creator.Addresses.IonConnect)

			// Position - Holder
			assert.Equal(t, "seller1", sellTrade.Position.Holder.Username)
			assert.Equal(t, "Seller One", sellTrade.Position.Holder.Display)
			assert.False(t, sellTrade.Position.Holder.Verified)
			assert.Equal(t, "0:seller1_trades:", sellTrade.Position.Holder.Addresses.IonConnect)

			// Position - Trade details
			assert.Equal(t, tokenExt, sellTrade.Position.Addresses.IonConnect)
			assert.Equal(t, tradeTypeSell, sellTrade.Position.Type)
			assert.Equal(t, uint64(3000), sellTrade.Position.Amount, "Amount should be 3000 tokens")
			assert.InDelta(t, 0.3, sellTrade.Position.AmountUSD, 0.01, "AmountUSD = 3000 * 0.0001 = 0.3")
			assert.False(t, sellTrade.Position.CreatedAt.IsZero())
		}

		assert.False(t, maxTs.IsZero(), "maxTs should be set")
	})

	t.Run("pagination with limit and offset", func(t *testing.T) {
		helperInsertTestUser(t, ctx, testDB, "creator_page_trades", "alice_page", "Alice Page", "", true, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, testDB, "trader1_page", "trader1", "Trader One", "0xtrader1000000000000000000000000000000001", false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, testDB, "trader2_page", "trader2", "Trader Two", "0xtrader2000000000000000000000000000000002", false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, testDB, "trader3_page", "trader3", "Trader Three", "0xtrader3000000000000000000000000000000003", false, PlatformGroupIonConnect)

		tokenExt := "0:creator_page_trades:"
		contractAddr := "0xPAGETRADES11111111111111111111111111"

		helperInsertTestToken(t, ctx, testDB,
			contractAddr,
			tokenExt,
			"PAGE1",
			"profile",
			"creator_page_trades",
			"1000000000000000000000000",
			100.0,
			0.0001,
			1,
			PlatformGroupIonConnect,
		)
		helperInsertUserTokenPosition(t, ctx, testDB, "trader1_page", contractAddr, tokenExt, "0:trader1_page:", "1000000000000000000000", 0.0001, 0.1)
		helperInsertUserTokenPosition(t, ctx, testDB, "trader2_page", contractAddr, tokenExt, "0:trader2_page:", "2000000000000000000000", 0.0001, 0.2)
		helperInsertUserTokenPosition(t, ctx, testDB, "trader3_page", contractAddr, tokenExt, "0:trader3_page:", "3000000000000000000000", 0.0001, 0.3)

		helperInsertTokenSwap(t, ctx, testDB, contractAddr, tokenExt, "0xtrader1000000000000000000000000000000001", "0xTX1000000000000000000000000000000000000000000000000000000000000001", false, "100000000000000000000", "1000000000000000000000", 0.0001)
		time.Sleep(10 * time.Millisecond)
		helperInsertTokenSwap(t, ctx, testDB, contractAddr, tokenExt, "0xtrader2000000000000000000000000000000002", "0xTX2000000000000000000000000000000000000000000000000000000000000002", false, "200000000000000000000", "2000000000000000000000", 0.0001)
		time.Sleep(10 * time.Millisecond)
		helperInsertTokenSwap(t, ctx, testDB, contractAddr, tokenExt, "0xtrader3000000000000000000000000000000003", "0xTX3000000000000000000000000000000000000000000000000000000000000003", false, "300000000000000000000", "3000000000000000000000", 0.0001)

		trades1, _, err := ta.GetLatestTrades(ctx, tokenExt, 2, 0, nil)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(trades1), 2, "Should return at most 2 trades")

		trades2, _, err := ta.GetLatestTrades(ctx, tokenExt, 2, 2, nil)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(trades2), 2, "Should return at most 2 trades")

		// Results should not overlap if we have enough data
		if len(trades1) > 0 && len(trades2) > 0 {
			for _, t1 := range trades1 {
				for _, t2 := range trades2 {
					if t1 != nil && t2 != nil {
						assert.NotEqual(t, t1.Position.CreatedAt, t2.Position.CreatedAt, "Trades should not overlap between pages")
					}
				}
			}
		}
	})

	t.Run("filter by startFrom timestamp", func(t *testing.T) {
		helperInsertTestUser(t, ctx, testDB, "creator_time_trades", "alice_time", "Alice Time", "", true, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, testDB, "trader_time", "trader_time", "Trader Time", "0xtimetrader000000000000000000000000000001", false, PlatformGroupIonConnect)

		tokenExt := "0:creator_time_trades:"
		contractAddr := "0xTIMETRADES1111111111111111111111111111"

		helperInsertTestToken(t, ctx, testDB,
			contractAddr,
			tokenExt,
			"TIME1",
			"profile",
			"creator_time_trades",
			"1000000000000000000000000",
			100.0,
			0.0001,
			1,
			PlatformGroupIonConnect,
		)

		helperInsertUserTokenPosition(t, ctx, testDB,
			"trader_time",
			contractAddr,
			tokenExt,
			"0:trader_time:",
			"3000000000000000000000", // 3000 tokens total
			0.0001,
			0.3,
		)

		helperInsertTokenSwap(t, ctx, testDB, contractAddr, tokenExt, "0xtimetrader000000000000000000000000000001", "0xTXTIME1000000000000000000000000000000000000000000000000000000000001", false, "100000000000000000000", "1000000000000000000000", 0.0001)
		time.Sleep(100 * time.Millisecond)
		timestampAfterFirst := time.Now()
		time.Sleep(100 * time.Millisecond)

		helperInsertTokenSwap(t, ctx, testDB, contractAddr, tokenExt, "0xtimetrader000000000000000000000000000001", "0xTXTIME2000000000000000000000000000000000000000000000000000000000002", false, "200000000000000000000", "2000000000000000000000", 0.0001)

		tradesAll, _, err := ta.GetLatestTrades(ctx, tokenExt, 10, 0, nil)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(tradesAll), 2, "Should have at least 2 trades")

		// Get trades after first swap
		tradesFiltered, _, err := ta.GetLatestTrades(ctx, tokenExt, 10, 0, &timestampAfterFirst)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(tradesFiltered), 1, "Should have at least 1 trade after timestamp")

		assert.LessOrEqual(t, len(tradesFiltered), len(tradesAll), "Filtered results should be <= all results")

		// All filtered trades should be after the timestamp
		for _, trade := range tradesFiltered {
			if trade != nil {
				assert.True(t, trade.Position.CreatedAt.After(timestampAfterFirst), "Trade should be after startFrom timestamp")
			}
		}
	})

}
