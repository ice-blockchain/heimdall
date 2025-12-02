// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/puzpuzpuz/xsync/v4"

	bondingcurve "github.com/ice-blockchain/heimdall/token-analytics/internal/bonding_curve"
	"github.com/ice-blockchain/wintr/log"
)

func newSubscriptions(ctx context.Context) interface {
	Subscriptions
	Notifier
} {
	s := &subscriptions{
		swaps:    make(chan *bondingcurve.LogTokenSwapped),
		swapSubs: xsync.NewMap[string, chan *bondingcurve.LogTokenSwapped](),
	}

	go s.routeSwapsToSubscribers(ctx)

	return s
}

func (s *subscriptions) routeSwapsToSubscribers(ctx context.Context) {
	go func() {
		<-ctx.Done()
		close(s.swaps)
		s.swapSubs.Range(func(key string, value chan *bondingcurve.LogTokenSwapped) bool {
			close(value)
			return true
		})
	}()
	for newSwap := range s.swaps {
		ionAddrOfNewSwap, err := detectExternalAddressFromSwap(newSwap)
		if err != nil {
			log.Error(errors.Wrapf(err, "failed to detect ion connect address from swap"))
			continue
		}
		dest, ok := s.swapSubs.Load(ionAddrOfNewSwap)
		if ok {
			dest <- newSwap
		}
	}
}

func (s *subscriptions) SubscribeOnSwaps(externalAddress string) <-chan *bondingcurve.LogTokenSwapped {
	swaps, _ := s.swapSubs.LoadOrCompute(externalAddress, func() (newValue chan *bondingcurve.LogTokenSwapped, cancel bool) {
		return make(chan *bondingcurve.LogTokenSwapped), false
	})
	return swaps
}

func (s *subscriptions) NotifySwap(ev *bondingcurve.LogTokenSwapped) {
	select {
	case s.swaps <- ev:
	case <-time.After(10 * time.Millisecond): // Just in case if reader get stuck, TODO: remove when we'll have proper subs/notify flow
	}
}
