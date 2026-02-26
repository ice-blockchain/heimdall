// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"sync"
	"testing"
	stdlibtime "time"

	"github.com/stretchr/testify/require"
)

func TestNotifySwap(t *testing.T) {
	t.Run("single subscriber receives all notifications", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*stdlibtime.Second)
		defer cancel()

		subs := newSubscriptions(ctx)

		externalAddress := "0:test_notify_single:"
		userID := "test-user-1"

		receivedTrades := make([]*Trade, 0)
		var mu sync.Mutex

		swapsChan := subs.SubscribeOnSwaps(ctx, externalAddress, userID)

		go func() {
			for trade := range swapsChan {
				mu.Lock()
				receivedTrades = append(receivedTrades, trade)
				mu.Unlock()
			}
		}()
		for i := 0; i < 5; i++ {
			subs.NotifySwap(&Trade{
				TokenExternalAddress: externalAddress,
			})
		}

		require.Eventually(t, func() bool {
			mu.Lock()
			defer mu.Unlock()
			return len(receivedTrades) == 5
		}, 2*stdlibtime.Second, 10*stdlibtime.Millisecond, "should receive exactly 5 trades")
	})

	t.Run("multiple subscribers receive same notifications", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*stdlibtime.Second)
		defer cancel()

		subs := newSubscriptions(ctx)

		externalAddress := "0:test_notify_multiple:"

		receivedTrades1 := make([]*Trade, 0)
		receivedTrades2 := make([]*Trade, 0)
		var mu1, mu2 sync.Mutex

		swapsChan1 := subs.SubscribeOnSwaps(ctx, externalAddress, "user-1")
		swapsChan2 := subs.SubscribeOnSwaps(ctx, externalAddress, "user-2")

		go func() {
			for trade := range swapsChan1 {
				mu1.Lock()
				receivedTrades1 = append(receivedTrades1, trade)
				mu1.Unlock()
			}
		}()

		go func() {
			for trade := range swapsChan2 {
				mu2.Lock()
				receivedTrades2 = append(receivedTrades2, trade)
				mu2.Unlock()
			}
		}()

		for i := 0; i < 3; i++ {
			subs.NotifySwap(&Trade{
				TokenExternalAddress: externalAddress,
			})
		}

		require.Eventually(t, func() bool {
			mu1.Lock()
			defer mu1.Unlock()
			mu2.Lock()
			defer mu2.Unlock()
			return len(receivedTrades1) == 3 && len(receivedTrades2) == 3
		}, 2*stdlibtime.Second, 10*stdlibtime.Millisecond, "both users should receive exactly 3 trades")
	})

	t.Run("duplicate NotifySwap calls send duplicate events", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*stdlibtime.Second)
		defer cancel()

		subs := newSubscriptions(ctx)

		externalAddress := "0:test_notify_duplicates:"
		userID := "test-user-dup"

		receivedTrades := make([]*Trade, 0)
		var mu sync.Mutex

		swapsChan := subs.SubscribeOnSwaps(ctx, externalAddress, userID)

		go func() {
			for trade := range swapsChan {
				mu.Lock()
				receivedTrades = append(receivedTrades, trade)
				mu.Unlock()
			}
		}()

		// Send same trade 3 times (simulating duplicate NotifySwap calls)
		sameTrade := &Trade{
			TokenExternalAddress: externalAddress,
		}

		for i := 0; i < 3; i++ {
			subs.NotifySwap(sameTrade)
		}

		require.Eventually(t, func() bool {
			mu.Lock()
			defer mu.Unlock()
			return len(receivedTrades) == 3
		}, 2*stdlibtime.Second, 10*stdlibtime.Millisecond, "should receive 3 duplicate events (this is the BUG we need to fix)")
	})

	t.Run("subscriber for different token does not receive notifications", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*stdlibtime.Second)
		defer cancel()

		subs := newSubscriptions(ctx)

		externalAddress1 := "0:test_notify_token1:"
		externalAddress2 := "0:test_notify_token2:"

		receivedTrades1 := make([]*Trade, 0)
		receivedTrades2 := make([]*Trade, 0)
		var mu1, mu2 sync.Mutex

		swapsChan1 := subs.SubscribeOnSwaps(ctx, externalAddress1, "user-1")
		swapsChan2 := subs.SubscribeOnSwaps(ctx, externalAddress2, "user-2")

		go func() {
			for trade := range swapsChan1 {
				mu1.Lock()
				receivedTrades1 = append(receivedTrades1, trade)
				mu1.Unlock()
			}
		}()

		go func() {
			for trade := range swapsChan2 {
				mu2.Lock()
				receivedTrades2 = append(receivedTrades2, trade)
				mu2.Unlock()
			}
		}()

		// Send trades only for token1
		for i := 0; i < 3; i++ {
			subs.NotifySwap(&Trade{
				TokenExternalAddress: externalAddress1,
			})
		}

		require.Eventually(t, func() bool {
			mu1.Lock()
			defer mu1.Unlock()
			return len(receivedTrades1) == 3
		}, 2*stdlibtime.Second, 10*stdlibtime.Millisecond, "user-1 subscribed to token1 should receive 3 trades")

		mu2.Lock()
		count2 := len(receivedTrades2)
		mu2.Unlock()

		require.Equal(t, 0, count2, "user-2 subscribed to token2 should receive 0 trades")
	})

	t.Run("unsubscribe stops receiving notifications", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*stdlibtime.Second)
		defer cancel()

		subs := newSubscriptions(ctx)

		externalAddress := "0:test_notify_unsub:"

		receivedTrades := make([]*Trade, 0)
		var mu sync.Mutex

		subCtx, subCancel := context.WithCancel(ctx)
		swapsChan := subs.SubscribeOnSwaps(subCtx, externalAddress, "user-unsub")

		go func() {
			for trade := range swapsChan {
				mu.Lock()
				receivedTrades = append(receivedTrades, trade)
				mu.Unlock()
			}
		}()

		for i := 0; i < 2; i++ {
			subs.NotifySwap(&Trade{
				TokenExternalAddress: externalAddress,
			})
		}

		require.Eventually(t, func() bool {
			mu.Lock()
			defer mu.Unlock()
			return len(receivedTrades) == 2
		}, 2*stdlibtime.Second, 10*stdlibtime.Millisecond, "should receive 2 trades before unsubscribe")

		subCancel()

		for i := 0; i < 2; i++ {
			subs.NotifySwap(&Trade{
				TokenExternalAddress: externalAddress,
			})
		}

		require.Never(t, func() bool {
			mu.Lock()
			defer mu.Unlock()
			return len(receivedTrades) > 2
		}, 500*stdlibtime.Millisecond, 10*stdlibtime.Millisecond, "should not receive any trades after unsubscribe")

		mu.Lock()
		countAfter := len(receivedTrades)
		mu.Unlock()

		require.Equal(t, 2, countAfter, "should still have only 2 trades after unsubscribe")
	})
}
