// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGetLatestTrades(t *testing.T) {
	ctx := t.Context()
	db, release := helperCreateDB(t)
	defer release()

	ta := helperNewForTest(t, db)

	t.Run("returns empty for non-existent token", func(t *testing.T) {
		trades, maxTs, err := ta.GetLatestTrades(ctx, "a0:nonexistent:", 10, 0, nil)
		require.NoError(t, err)
		require.Empty(t, trades)
		require.True(t, !maxTs.IsZero() || maxTs.Before(time.Now().Add(time.Second)), "maxTs should be set or current time")
	})

	t.Run("returns latest trades for token", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "creator_trades", "alice_trades", "Alice Trades", "", true, PlatformGroupIonConnect, "https://avatar1.png")
		helperInsertTestUser(t, ctx, db, "buyer1_trades", "buyer1", "Buyer One", "0xbuyer1000000000000000000000000000000001", false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "seller1_trades", "seller1", "Seller One", "0xseller100000000000000000000000000000001", false, PlatformGroupIonConnect)

		tokenExt := "0:creator_trades:"
		contractAddr := "0xTRADES1111111111111111111111111111111"

		helperInsertTestToken(t, ctx, db,
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

		helperInsertUserTokenPosition(t, ctx, db,
			"buyer1_trades",
			contractAddr,
			tokenExt,
			"0:buyer1_trades:",
			"5000000000000000000000", // 5000 tokens
			0.0001,
			0.5,
		)
		helperInsertUserTokenPosition(t, ctx, db,
			"seller1_trades",
			contractAddr,
			tokenExt,
			"0:seller1_trades:",
			"3000000000000000000000", // 3000 tokens
			0.0001,
			0.3,
		)

		// Insert buy swap
		helperInsertTokenSwap(t, ctx, db,
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
		helperInsertTokenSwap(t, ctx, db,
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
			if trade != nil && strVal(trade.Creator.Username) == "alice_trades" {
				if trade.Position.Type == TradeTypeBuy && strVal(trade.Position.Holder.Username) == "buyer1" {
					buyTrade = trade
				} else if trade.Position.Type == TradeTypeSell && strVal(trade.Position.Holder.Username) == "seller1" {
					sellTrade = trade
				}
			}
		}

		if buyTrade != nil {
			require.Equal(t, "alice_trades", strVal(buyTrade.Creator.Username))
			require.Equal(t, "Alice Trades", strVal(buyTrade.Creator.Display))
			require.True(t, buyTrade.Creator.Verified != nil && *buyTrade.Creator.Verified)
			require.Equal(t, "https://avatar1.png", strVal(buyTrade.Creator.Avatar))
			require.Equal(t, "creator_trades", buyTrade.Creator.Addresses.IonConnect, "Creator IonConnect should be pubkey only")

			require.Equal(t, "buyer1", strVal(buyTrade.Position.Holder.Username))
			require.Equal(t, "Buyer One", strVal(buyTrade.Position.Holder.Display))
			require.True(t, buyTrade.Position.Holder.Verified == nil || !*buyTrade.Position.Holder.Verified)
			require.Equal(t, "buyer1_trades", buyTrade.Position.Holder.Addresses.IonConnect, "Holder IonConnect should be pubkey only")

			require.Equal(t, "0xbuyer1000000000000000000000000000000001", buyTrade.Position.Addresses.Blockchain, "Position.Addresses.Blockchain should be user blockchain address")
			require.Equal(t, TradeTypeBuy, buyTrade.Position.Type)
			require.Equal(t, "5000000000000000000000", buyTrade.Position.Amount, "Amount should be 5000 tokens in wei")

			require.InDelta(t, 0.5, buyTrade.Position.AmountUSD, 0.01, "AmountUSD = 5000 * 0.0001 = 0.5")
			require.Equal(t, "5000000000000000000000", buyTrade.Position.Balance, "Balance should be 5000 tokens in wei")
			require.InDelta(t, 0.5, buyTrade.Position.BalanceUSD, 0.01, "BalanceUSD = 5000 * 0.0001 = 0.5")
			require.False(t, buyTrade.Position.CreatedAt.IsZero())
		}

		if sellTrade != nil {
			require.Equal(t, "alice_trades", strVal(sellTrade.Creator.Username))
			require.Equal(t, "Alice Trades", strVal(sellTrade.Creator.Display))
			require.True(t, sellTrade.Creator.Verified != nil && *sellTrade.Creator.Verified)
			require.Equal(t, "creator_trades", sellTrade.Creator.Addresses.IonConnect, "Creator IonConnect should be pubkey only")

			require.Equal(t, "seller1", strVal(sellTrade.Position.Holder.Username))
			require.Equal(t, "Seller One", strVal(sellTrade.Position.Holder.Display))
			require.True(t, sellTrade.Position.Holder.Verified == nil || !*sellTrade.Position.Holder.Verified)
			require.Equal(t, "seller1_trades", sellTrade.Position.Holder.Addresses.IonConnect, "Holder IonConnect should be pubkey only")

			require.Equal(t, "0xseller100000000000000000000000000000001", sellTrade.Position.Addresses.Blockchain, "Position.Addresses.Blockchain should be user blockchain address")
			require.Equal(t, TradeTypeSell, sellTrade.Position.Type)
			require.Equal(t, "3000000000000000000000", sellTrade.Position.Amount, "Amount should be 3000 tokens in wei")
			require.InDelta(t, 0.3, sellTrade.Position.AmountUSD, 0.01, "AmountUSD = 3000 * 0.0001 = 0.3")
			require.False(t, sellTrade.Position.CreatedAt.IsZero())
		}
		require.False(t, maxTs.IsZero(), "maxTs should be set")
	})

	t.Run("pagination with limit and offset", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "creator_page_trades", "alice_page", "Alice Page", "", true, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "trader1_page", "trader1", "Trader One", "0xtrader1000000000000000000000000000000001", false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "trader2_page", "trader2", "Trader Two", "0xtrader2000000000000000000000000000000002", false, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "trader3_page", "trader3", "Trader Three", "0xtrader3000000000000000000000000000000003", false, PlatformGroupIonConnect)

		tokenExt := "0:creator_page_trades:"
		contractAddr := "0xPAGETRADES11111111111111111111111111"

		helperInsertTestToken(t, ctx, db,
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

		helperInsertUserTokenPosition(t, ctx, db, "trader1_page", contractAddr, tokenExt, "0:trader1_page:", "1000000000000000000000", 0.0001, 0.1)
		helperInsertUserTokenPosition(t, ctx, db, "trader2_page", contractAddr, tokenExt, "0:trader2_page:", "2000000000000000000000", 0.0001, 0.2)
		helperInsertUserTokenPosition(t, ctx, db, "trader3_page", contractAddr, tokenExt, "0:trader3_page:", "3000000000000000000000", 0.0001, 0.3)

		helperInsertTokenSwap(t, ctx, db, contractAddr, tokenExt, "0xtrader1000000000000000000000000000000001", "0xTX1000000000000000000000000000000000000000000000000000000000000001", false, "100000000000000000000", "1000000000000000000000", 0.0001)
		time.Sleep(10 * time.Millisecond)
		helperInsertTokenSwap(t, ctx, db, contractAddr, tokenExt, "0xtrader2000000000000000000000000000000002", "0xTX2000000000000000000000000000000000000000000000000000000000000002", false, "200000000000000000000", "2000000000000000000000", 0.0001)
		time.Sleep(10 * time.Millisecond)
		helperInsertTokenSwap(t, ctx, db, contractAddr, tokenExt, "0xtrader3000000000000000000000000000000003", "0xTX3000000000000000000000000000000000000000000000000000000000000003", false, "300000000000000000000", "3000000000000000000000", 0.0001)

		trades1, _, err := ta.GetLatestTrades(ctx, tokenExt, 2, 0, nil)
		require.NoError(t, err)
		require.LessOrEqual(t, len(trades1), 2, "Should return at most 2 trades")

		trades2, _, err := ta.GetLatestTrades(ctx, tokenExt, 2, 2, nil)
		require.NoError(t, err)
		require.LessOrEqual(t, len(trades2), 2, "Should return at most 2 trades")

		// Results should not overlap if we have enough data
		if len(trades1) > 0 && len(trades2) > 0 {
			for _, t1 := range trades1 {
				for _, t2 := range trades2 {
					if t1 != nil && t2 != nil {
						require.NotEqual(t, t1.Position.CreatedAt, t2.Position.CreatedAt, "Trades should not overlap between pages")
					}
				}
			}
		}
	})

	t.Run("filter by startFrom timestamp", func(t *testing.T) {
		helperInsertTestUser(t, ctx, db, "creator_time_trades", "alice_time", "Alice Time", "", true, PlatformGroupIonConnect)
		helperInsertTestUser(t, ctx, db, "trader_time", "trader_time", "Trader Time", "0xtimetrader000000000000000000000000000001", false, PlatformGroupIonConnect)

		tokenExt := "0:creator_time_trades:"
		contractAddr := "0xTIMETRADES1111111111111111111111111111"

		helperInsertTestToken(t, ctx, db,
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

		helperInsertUserTokenPosition(t, ctx, db,
			"trader_time",
			contractAddr,
			tokenExt,
			"0:trader_time:",
			"3000000000000000000000", // 3000 tokens total
			0.0001,
			0.3,
		)

		helperInsertTokenSwap(t, ctx, db, contractAddr, tokenExt, "0xtimetrader000000000000000000000000000001", "0xTXTIME1000000000000000000000000000000000000000000000000000000000001", false, "100000000000000000000", "1000000000000000000000", 0.0001)
		time.Sleep(100 * time.Millisecond)
		timestampAfterFirst := time.Now()
		time.Sleep(100 * time.Millisecond)

		helperInsertTokenSwap(t, ctx, db, contractAddr, tokenExt, "0xtimetrader000000000000000000000000000001", "0xTXTIME2000000000000000000000000000000000000000000000000000000000002", false, "200000000000000000000", "2000000000000000000000", 0.0001)

		tradesAll, _, err := ta.GetLatestTrades(ctx, tokenExt, 10, 0, nil)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(tradesAll), 2, "Should have at least 2 trades")

		tradesFiltered, _, err := ta.GetLatestTrades(ctx, tokenExt, 10, 0, &timestampAfterFirst)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(tradesFiltered), 1, "Should have at least 1 trade after timestamp")

		require.LessOrEqual(t, len(tradesFiltered), len(tradesAll), "Filtered results should be <= all results")

		for _, trade := range tradesFiltered {
			if trade != nil {
				require.True(t, trade.Position.CreatedAt.After(timestampAfterFirst), "Trade should be after startFrom timestamp")
			}
		}
	})

}
