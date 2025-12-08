// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"time"

	"github.com/puzpuzpuz/xsync/v4"
)

type (
	Subscriptions interface {
		SubscribeOnSwaps(externalAddress string) <-chan struct{}
		SubscribeOnBondingCurveProgress(externalAddress string) <-chan *BondingCurveProgress
	}
	Notifier interface {
		NotifySwap(externalAddress string)
		NotifyBondingCurveProgress(externalAddress string, progress *BondingCurveProgress)
	}

	subscriptions struct {
		swaps                           chan swapExternalAddress // externalAddresses, think if we need some interface unifing uniswap and curve swaps
		bondingCurveProgressUpdates     chan bondingCurveProgressUpdate
		swapSubs                        *xsync.Map[string, chan struct{}]
		bondingCurveProgressUpdatesSubs *xsync.Map[string, chan *BondingCurveProgress]
	}
	bondingCurveProgressUpdate struct {
		externalAddress string
		progress        *BondingCurveProgress
	}
	swapExternalAddress string
)

func (b bondingCurveProgressUpdate) ExternalAddress() string      { return b.externalAddress }
func (b bondingCurveProgressUpdate) Value() *BondingCurveProgress { return b.progress }
func (s swapExternalAddress) ExternalAddress() string             { return string(s) }
func (s swapExternalAddress) Value() struct{}                     { return struct{}{} }

func newSubscriptions(ctx context.Context, cfg *config) interface {
	Subscriptions
	Notifier
} {
	s := &subscriptions{
		swaps:                           make(chan swapExternalAddress),
		bondingCurveProgressUpdates:     make(chan bondingCurveProgressUpdate, cfg.ConcurrentBondingCurveUpdates),
		swapSubs:                        xsync.NewMap[string, chan struct{}](),
		bondingCurveProgressUpdatesSubs: xsync.NewMap[string, chan *BondingCurveProgress](),
	}

	go routeToSubscribers[struct{}, swapExternalAddress](ctx, s.swapSubs, s.swaps)
	go routeToSubscribers[*BondingCurveProgress, bondingCurveProgressUpdate](ctx, s.bondingCurveProgressUpdatesSubs, s.bondingCurveProgressUpdates)
	return s
}

func routeToSubscribers[T any, N interface {
	ExternalAddress() string
	Value() T
}](ctx context.Context, subs *xsync.Map[string, chan T], notifyChan chan N) {
	go func() {
		<-ctx.Done()
		close(notifyChan)
		subs.Range(func(key string, value chan T) bool {
			close(value)
			return true
		})
	}()
	for newEventTokenExternalAddr := range notifyChan {
		addr := newEventTokenExternalAddr.ExternalAddress()
		dest, ok := subs.Load(addr)
		if ok {
			dest <- newEventTokenExternalAddr.Value()
		}
	}
}

func (s *subscriptions) SubscribeOnSwaps(externalAddress string) <-chan struct{} {
	swaps, _ := s.swapSubs.LoadOrCompute(externalAddress, func() (newValue chan struct{}, cancel bool) {
		return make(chan struct{}), false
	})
	return swaps
}
func (s *subscriptions) SubscribeOnBondingCurveProgress(externalAddress string) <-chan *BondingCurveProgress {
	progress, _ := s.bondingCurveProgressUpdatesSubs.LoadOrCompute(externalAddress, func() (newValue chan *BondingCurveProgress, cancel bool) {
		return make(chan *BondingCurveProgress), false
	})
	return progress
}

func (s *subscriptions) NotifySwap(externalAddress string) {
	select {
	case s.swaps <- swapExternalAddress(externalAddress):
	case <-time.After(10 * time.Millisecond): // Just in case if reader get stuck, TODO: remove when we'll have proper subs/notify flow
	}
}

func (s *subscriptions) NotifyBondingCurveProgress(externalAddress string, progress *BondingCurveProgress) {
	select {
	case s.bondingCurveProgressUpdates <- bondingCurveProgressUpdate{externalAddress, progress}:
	case <-time.After(10 * time.Millisecond): // Just in case if reader get stuck, TODO: remove when we'll have proper subs/notify flow
	}
}
