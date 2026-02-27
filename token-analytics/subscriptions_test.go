// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	stdlibtime "time"

	"github.com/stretchr/testify/require"
)

func TestNotifySwap(t *testing.T) {
	t.Run("single_subscriber_receives_all_notifications", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*stdlibtime.Second)
		defer cancel()

		subs := newSubscriptions(ctx)
		externalAddress := "0:test_notify_single:"

		var received int32
		ch := subs.SubscribeOnSwaps(ctx, externalAddress, "test-user-1")
		go func() {
			for range ch {
				atomic.AddInt32(&received, 1)
			}
		}()

		for i := 0; i < 5; i++ {
			subs.NotifySwap(&Trade{TokenExternalAddress: externalAddress})
		}

		require.Eventually(t, func() bool {
			return atomic.LoadInt32(&received) == 5
		}, 2*stdlibtime.Second, 10*stdlibtime.Millisecond, "should receive exactly 5 trades")
	})

	t.Run("multiple_subscribers_receive_same_notifications", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*stdlibtime.Second)
		defer cancel()

		subs := newSubscriptions(ctx)
		externalAddress := "0:test_notify_multiple:"

		var received1, received2 int32

		ch1 := subs.SubscribeOnSwaps(ctx, externalAddress, "user-1")
		ch2 := subs.SubscribeOnSwaps(ctx, externalAddress, "user-2")

		go func() {
			for range ch1 {
				atomic.AddInt32(&received1, 1)
			}
		}()
		go func() {
			for range ch2 {
				atomic.AddInt32(&received2, 1)
			}
		}()

		for i := 0; i < 3; i++ {
			subs.NotifySwap(&Trade{TokenExternalAddress: externalAddress})
		}

		require.Eventually(t, func() bool {
			return atomic.LoadInt32(&received1) == 3 && atomic.LoadInt32(&received2) == 3
		}, 2*stdlibtime.Second, 10*stdlibtime.Millisecond, "both users should receive exactly 3 trades")
	})

	t.Run("subscriber_for_different_token_does_not_receive", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*stdlibtime.Second)
		defer cancel()

		subs := newSubscriptions(ctx)
		addr1 := "0:test_notify_token1:"
		addr2 := "0:test_notify_token2:"

		var received1, received2 int32

		ch1 := subs.SubscribeOnSwaps(ctx, addr1, "user-1")
		ch2 := subs.SubscribeOnSwaps(ctx, addr2, "user-2")

		go func() {
			for range ch1 {
				atomic.AddInt32(&received1, 1)
			}
		}()
		go func() {
			for range ch2 {
				atomic.AddInt32(&received2, 1)
			}
		}()

		for i := 0; i < 3; i++ {
			subs.NotifySwap(&Trade{TokenExternalAddress: addr1})
		}

		require.Eventually(t, func() bool {
			return atomic.LoadInt32(&received1) == 3
		}, 2*stdlibtime.Second, 10*stdlibtime.Millisecond, "user-1 subscribed to token1 should receive 3 trades")

		require.Equal(t, int32(0), atomic.LoadInt32(&received2), "user-2 subscribed to token2 should receive 0 trades")
	})

	t.Run("same_userID_both_channels_receive_with_fanout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*stdlibtime.Second)
		defer cancel()

		subs := newSubscriptions(ctx)
		externalAddress := "30175:test_content_token:uuid1"
		deviceKey := "same-device-pubkey"

		var received1 int32
		ch1 := subs.SubscribeOnSwaps(ctx, externalAddress, deviceKey)
		go func() {
			for range ch1 {
				atomic.AddInt32(&received1, 1)
			}
		}()

		subs.NotifySwap(&Trade{TokenExternalAddress: externalAddress})
		require.Eventually(t, func() bool {
			return atomic.LoadInt32(&received1) == 1
		}, 1*stdlibtime.Second, 10*stdlibtime.Millisecond, "latest-trades should receive first notification")

		var received2 int32
		ch2 := subs.SubscribeOnSwaps(ctx, externalAddress, deviceKey)
		go func() {
			for range ch2 {
				atomic.AddInt32(&received2, 1)
			}
		}()

		subs.NotifySwap(&Trade{TokenExternalAddress: externalAddress})

		require.Eventually(t, func() bool {
			return atomic.LoadInt32(&received1) == 2
		}, 1*stdlibtime.Second, 10*stdlibtime.Millisecond,
			"latest-trades must still receive after second SubscribeOnSwaps")

		require.Eventually(t, func() bool {
			return atomic.LoadInt32(&received2) == 1
		}, 1*stdlibtime.Second, 10*stdlibtime.Millisecond,
			"trading-stats must also receive the notification")
	})

	t.Run("unsubscribe_stops_receiving_notifications", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*stdlibtime.Second)
		defer cancel()

		subs := newSubscriptions(ctx)
		externalAddress := "0:test_notify_unsub:"

		var received int32
		var closed int32

		subCtx, subCancel := context.WithCancel(ctx)
		ch := subs.SubscribeOnSwaps(subCtx, externalAddress, "user-unsub")
		go func() {
			for range ch {
				atomic.AddInt32(&received, 1)
			}
			atomic.StoreInt32(&closed, 1)
		}()

		for i := 0; i < 2; i++ {
			subs.NotifySwap(&Trade{TokenExternalAddress: externalAddress})
		}

		require.Eventually(t, func() bool {
			return atomic.LoadInt32(&received) == 2
		}, 2*stdlibtime.Second, 10*stdlibtime.Millisecond, "should receive 2 trades before unsubscribe")

		subCancel()

		require.Eventually(t, func() bool {
			return atomic.LoadInt32(&closed) == 1
		}, 1*stdlibtime.Second, 10*stdlibtime.Millisecond, "channel must be closed after ctx cancel")

		for i := 0; i < 2; i++ {
			subs.NotifySwap(&Trade{TokenExternalAddress: externalAddress})
		}

		require.Never(t, func() bool {
			return atomic.LoadInt32(&received) > 2
		}, 500*stdlibtime.Millisecond, 10*stdlibtime.Millisecond, "should not receive any trades after unsubscribe")

		require.Equal(t, int32(2), atomic.LoadInt32(&received), "should still have only 2 trades after unsubscribe")
	})

	t.Run("multi_user_multi_endpoint_all_receive", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*stdlibtime.Second)
		defer cancel()

		subs := newSubscriptions(ctx)
		tokenX := "0:multi_user_fanout_token:"

		var counters [6]int32

		consume := func(ch <-chan *Trade, idx int) {
			for range ch {
				atomic.AddInt32(&counters[idx], 1)
			}
		}

		go consume(subs.SubscribeOnSwaps(ctx, tokenX, "device-key-A"), 0)
		go consume(subs.SubscribeOnSwaps(ctx, tokenX, "device-key-A"), 1)
		go consume(subs.SubscribeOnSwaps(ctx, tokenX, "device-key-A"), 2)
		go consume(subs.SubscribeOnSwaps(ctx, tokenX, "device-key-B"), 3)
		go consume(subs.SubscribeOnSwaps(ctx, tokenX, "device-key-B"), 4)
		go consume(subs.SubscribeOnSwaps(ctx, tokenX, "device-key-B"), 5)

		subs.NotifySwap(&Trade{TokenExternalAddress: tokenX})

		for i := range counters {
			idx := i
			require.Eventually(t, func() bool {
				return atomic.LoadInt32(&counters[idx]) == 1
			}, 2*stdlibtime.Second, 10*stdlibtime.Millisecond,
				"listener %d must receive 1 event from single NotifySwap", idx)
		}
	})

	t.Run("listener_cleanup_on_ctx_cancel", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*stdlibtime.Second)
		defer cancel()

		subs := newSubscriptions(ctx)
		internal := subs.(*subscriptions)
		token := "0:cleanup_test_token:"

		ctxA, cancelA := context.WithCancel(ctx)
		ctxB, cancelB := context.WithCancel(ctx)
		ctxC, cancelC := context.WithCancel(ctx)

		chA := subs.SubscribeOnSwaps(ctxA, token, "userA")
		chB := subs.SubscribeOnSwaps(ctxB, token, "userB")
		chC := subs.SubscribeOnSwaps(ctxC, token, "userC")

		var closedA, closedB, closedC int32
		var receivedB, receivedC int32

		go func() {
			for range chA {
			}
			atomic.StoreInt32(&closedA, 1)
		}()
		go func() {
			for range chB {
				atomic.AddInt32(&receivedB, 1)
			}
			atomic.StoreInt32(&closedB, 1)
		}()
		go func() {
			for range chC {
				atomic.AddInt32(&receivedC, 1)
			}
			atomic.StoreInt32(&closedC, 1)
		}()

		require.Eventually(t, func() bool {
			_, exists := internal.swapSubs.Load(token)
			return exists
		}, 1*stdlibtime.Second, 10*stdlibtime.Millisecond, "subscription entry must exist while listeners are active")

		cancelA()
		require.Eventually(t, func() bool {
			return atomic.LoadInt32(&closedA) == 1
		}, 1*stdlibtime.Second, 10*stdlibtime.Millisecond, "channel A must be closed after ctx cancel")

		subs.NotifySwap(&Trade{TokenExternalAddress: token})

		require.Eventually(t, func() bool {
			return atomic.LoadInt32(&receivedB) >= 1
		}, 2*stdlibtime.Second, 10*stdlibtime.Millisecond, "B must still receive after A cancelled")
		require.Eventually(t, func() bool {
			return atomic.LoadInt32(&receivedC) >= 1
		}, 2*stdlibtime.Second, 10*stdlibtime.Millisecond, "C must still receive after A cancelled")

		require.Eventually(t, func() bool {
			_, exists := internal.swapSubs.Load(token)
			return exists
		}, 1*stdlibtime.Second, 10*stdlibtime.Millisecond, "subscription entry must still exist (B and C are active)")

		cancelB()
		require.Eventually(t, func() bool {
			return atomic.LoadInt32(&closedB) == 1
		}, 1*stdlibtime.Second, 10*stdlibtime.Millisecond, "channel B must be closed after ctx cancel")

		cancelC()
		require.Eventually(t, func() bool {
			return atomic.LoadInt32(&closedC) == 1
		}, 1*stdlibtime.Second, 10*stdlibtime.Millisecond, "channel C must be closed after ctx cancel")

		require.Eventually(t, func() bool {
			_, e := internal.swapSubs.Load(token)
			return !e
		}, 1*stdlibtime.Second, 10*stdlibtime.Millisecond,
			"subscription entry must be removed after last listener leaves")

		var resubReceived int32
		resubCh := subs.SubscribeOnSwaps(ctx, token, "new-user-after-cleanup")
		go func() {
			for range resubCh {
				atomic.AddInt32(&resubReceived, 1)
			}
		}()

		subs.NotifySwap(&Trade{TokenExternalAddress: token})
		require.Eventually(t, func() bool {
			return atomic.LoadInt32(&resubReceived) == 1
		}, 2*stdlibtime.Second, 10*stdlibtime.Millisecond,
			"re-subscribe after full cleanup must work")
	})

	t.Run("global_shutdown_closes_all_channels", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		subs := newSubscriptions(ctx)

		token1 := "0:shutdown_token1:"
		token2 := "0:shutdown_token2:"

		var closed [4]int32

		drain := func(ch <-chan *Trade, idx int) {
			for range ch {
			}
			atomic.StoreInt32(&closed[idx], 1)
		}

		go drain(subs.SubscribeOnSwaps(ctx, token1, "u1"), 0)
		go drain(subs.SubscribeOnSwaps(ctx, token1, "u2"), 1)
		go drain(subs.SubscribeOnSwaps(ctx, token2, "u3"), 2)
		go drain(subs.SubscribeOnSwaps(ctx, token2, "u4"), 3)

		cancel()

		for i := 0; i < 4; i++ {
			idx := i
			require.Eventually(t, func() bool {
				return atomic.LoadInt32(&closed[idx]) == 1
			}, 2*stdlibtime.Second, 10*stdlibtime.Millisecond,
				"channel %d must be closed on global shutdown", idx)
		}
	})

	t.Run("partial_unsubscribe_does_not_affect_others", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*stdlibtime.Second)
		defer cancel()

		subs := newSubscriptions(ctx)
		token := "0:partial_unsub_token:"
		deviceKey := "same-device"

		ctx1, cancel1 := context.WithCancel(ctx)
		ctx2, cancel2 := context.WithCancel(ctx)
		ctx3, cancel3 := context.WithCancel(ctx)
		_ = cancel1
		_ = cancel3

		ch1 := subs.SubscribeOnSwaps(ctx1, token, deviceKey)
		ch2 := subs.SubscribeOnSwaps(ctx2, token, deviceKey)
		ch3 := subs.SubscribeOnSwaps(ctx3, token, deviceKey)

		var received1, received3 int32
		var closed2 int32

		go func() {
			for range ch1 {
				atomic.AddInt32(&received1, 1)
			}
		}()
		go func() {
			for range ch2 {
			}
			atomic.StoreInt32(&closed2, 1)
		}()
		go func() {
			for range ch3 {
				atomic.AddInt32(&received3, 1)
			}
		}()

		cancel2()

		require.Eventually(t, func() bool {
			return atomic.LoadInt32(&closed2) == 1
		}, 1*stdlibtime.Second, 10*stdlibtime.Millisecond, "channel 2 must be closed")

		subs.NotifySwap(&Trade{TokenExternalAddress: token})

		require.Eventually(t, func() bool {
			return atomic.LoadInt32(&received1) == 1
		}, 2*stdlibtime.Second, 10*stdlibtime.Millisecond,
			"channel 1 must still receive after channel 2 cancelled")

		require.Eventually(t, func() bool {
			return atomic.LoadInt32(&received3) == 1
		}, 2*stdlibtime.Second, 10*stdlibtime.Millisecond,
			"channel 3 must still receive after channel 2 cancelled")
	})

	t.Run("concurrent_subscribe_unsubscribe_no_panic", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*stdlibtime.Second)
		defer cancel()

		subs := newSubscriptions(ctx)
		token := "0:stress_test_token:"

		var wg sync.WaitGroup
		done := make(chan struct{})

		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-done:
						return
					default:
					}
					subCtx, subCancel := context.WithCancel(ctx)
					ch := subs.SubscribeOnSwaps(subCtx, token, "stress-user")
					go func() {
						for range ch {
						}
					}()
					stdlibtime.Sleep(stdlibtime.Duration(1+stdlibtime.Now().UnixNano()%5) * stdlibtime.Millisecond)
					subCancel()
				}
			}()
		}

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-done:
						return
					default:
					}
					subs.NotifySwap(&Trade{TokenExternalAddress: token})
					stdlibtime.Sleep(1 * stdlibtime.Millisecond)
				}
			}()
		}

		stdlibtime.Sleep(2 * stdlibtime.Second)
		close(done)
		wg.Wait()
	})
}
