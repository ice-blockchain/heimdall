// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/puzpuzpuz/xsync/v4"
)

type (
	Subscriptions interface {
		SubscribeOnSwaps(ctx context.Context, externalAddress string) (notifyEvents <-chan *Trade, atLeastOneSubExists bool, lastSubClosed <-chan struct{})
		SubscribeOnBondingCurveProgress(ctx context.Context, externalAddress string) (notify <-chan *BondingCurveProgress, atLeastOneSubExists bool, lastSubClosed <-chan struct{})
	}
	Notifier interface {
		NotifySwap(trade *Trade)
		NotifyBondingCurveProgress(externalAddress string, progress *BondingCurveProgress)
	}

	subscriptions struct {
		swaps                           chan *Trade
		bondingCurveProgressUpdates     chan bondingCurveProgressUpdate
		swapSubs                        *xsync.Map[string, *subscription[*Trade]]
		bondingCurveProgressUpdatesSubs *xsync.Map[string, *subscription[*BondingCurveProgress]]
		shutdown                        <-chan struct{}
	}
	subscription[T any] struct {
		subscriptions *atomic.Int64
		notifyClients chan T
		lastClosed    chan struct{}
	}
	bondingCurveProgressUpdate struct {
		externalAddress string
		progress        *BondingCurveProgress
	}
	swapExternalAddress string
)

func (b bondingCurveProgressUpdate) ExternalAddress() string      { return b.externalAddress }
func (b bondingCurveProgressUpdate) Value() *BondingCurveProgress { return b.progress }
func (t *Trade) ExternalAddress() string {
	return t.TokenExternalAddress
}
func (t *Trade) Value() *Trade { return t }

func newSubscriptions(ctx context.Context) interface {
	Subscriptions
	Notifier
} {
	s := &subscriptions{
		swaps:                           make(chan *Trade),
		bondingCurveProgressUpdates:     make(chan bondingCurveProgressUpdate),
		swapSubs:                        xsync.NewMap[string, *subscription[*Trade]](),
		bondingCurveProgressUpdatesSubs: xsync.NewMap[string, *subscription[*BondingCurveProgress]](),
		shutdown:                        ctx.Done(),
	}

	go routeToSubscribers[*Trade, *Trade](ctx, s, s.swapSubs, s.swaps)
	go routeToSubscribers[*BondingCurveProgress, bondingCurveProgressUpdate](ctx, s, s.bondingCurveProgressUpdatesSubs, s.bondingCurveProgressUpdates)
	return s
}

func routeToSubscribers[T any, N interface {
	ExternalAddress() string
	Value() T
}](ctx context.Context, s *subscriptions, subs *xsync.Map[string, *subscription[T]], notifyChan chan N) {
	go func() {
		<-ctx.Done()
		close(notifyChan)
		subs.Range(func(key string, value *subscription[T]) bool {
			close(value.notifyClients)
			return true
		})
	}()
	for newEventTokenExternalAddr := range notifyChan {
		addr := newEventTokenExternalAddr.ExternalAddress()
		dest, ok := subs.Load(addr)
		if ok {
			select {
			case dest.notifyClients <- newEventTokenExternalAddr.Value():
			case <-s.shutdown:
			}

		}
	}
}

func (s *subscriptions) SubscribeOnSwaps(ctx context.Context, externalAddress string) (<-chan *Trade, bool, <-chan struct{}) {
	return subscribe[*Trade](ctx, externalAddress, s.swapSubs)
}
func (s *subscriptions) SubscribeOnBondingCurveProgress(ctx context.Context, externalAddress string) (<-chan *BondingCurveProgress, bool, <-chan struct{}) {
	return subscribe[*BondingCurveProgress](ctx, externalAddress, s.bondingCurveProgressUpdatesSubs)
}

func subscribe[T any](ctx context.Context, externalAddress string, subs *xsync.Map[string, *subscription[T]]) (nofifyClients <-chan T, hasAtLeastOneSub bool, lastSubClosed <-chan struct{}) {
	go func() {
		<-ctx.Done()

		sub, ok := subs.Load(externalAddress)
		if ok {
			if last := sub.subscriptions.Add(-1) <= 0; last {
				subs.Delete(externalAddress)
				close(sub.notifyClients)
				close(sub.lastClosed)
			}
		}
	}()
	progress, loaded := subs.LoadOrCompute(externalAddress, func() (newValue *subscription[T], cancel bool) {
		return &subscription[T]{subscriptions: new(atomic.Int64), notifyClients: make(chan T), lastClosed: make(chan struct{})}, false
	})
	progress.subscriptions.Add(1)
	return progress.notifyClients, loaded, progress.lastClosed
}

func (s *subscriptions) NotifySwap(tr *Trade) {
	select {
	case s.swaps <- tr:
	case <-time.After(10 * time.Millisecond): // Just in case if reader get stuck, TODO: remove when we'll have proper subs/notify flow
	case <-s.shutdown:
	}
}

func (s *subscriptions) NotifyBondingCurveProgress(externalAddress string, progress *BondingCurveProgress) {
	select {
	case s.bondingCurveProgressUpdates <- bondingCurveProgressUpdate{externalAddress, progress}:
	case <-time.After(10 * time.Millisecond): // Just in case if reader get stuck, TODO: remove when we'll have proper subs/notify flow
	case <-s.shutdown:
	}
}
