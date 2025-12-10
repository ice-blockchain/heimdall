// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"time"

	"github.com/puzpuzpuz/xsync/v4"
)

func newSubscriptions(ctx context.Context) interface {
	Subscriptions
	Notifier
} {
	s := &subscriptions{
		swaps:    make(chan string),
		swapSubs: xsync.NewMap[string, chan struct{}](),
	}

	go s.routeSwapsToSubscribers(ctx)

	return s
}

func (s *subscriptions) routeSwapsToSubscribers(ctx context.Context) {
	go func() {
		<-ctx.Done()
		close(s.swaps)
		s.swapSubs.Range(func(key string, value chan struct{}) bool {
			close(value)
			return true
		})
	}()
	for newSwapAddr := range s.swaps {
		dest, ok := s.swapSubs.Load(newSwapAddr)
		if ok {
			dest <- struct{}{}
		}
	}
}

func (s *subscriptions) SubscribeOnSwaps(externalAddress string) <-chan struct{} {
	swaps, _ := s.swapSubs.LoadOrCompute(externalAddress, func() (newValue chan struct{}, cancel bool) {
		return make(chan struct{}), false
	})
	return swaps
}

func (s *subscriptions) NotifySwap(externalAddress string) {
	select {
	case s.swaps <- externalAddress:
	case <-time.After(10 * time.Millisecond): // Just in case if reader get stuck, TODO: remove when we'll have proper subs/notify flow
	}
}
