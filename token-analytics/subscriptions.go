// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/puzpuzpuz/xsync/v4"
)

type (
	Subscriptions interface {
		SubscribeOnSwaps(ctx context.Context, externalAddress, userID string) (notifyEvents <-chan *Trade)
		SubscribeOnBondingCurveProgress(ctx context.Context, externalAddress, userID string) (notify <-chan *BondingCurveProgress)
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
		listeners *xsync.Map[uint64, *safeChan[T]]
		nextID    atomic.Uint64
		closeOnce sync.Once
	}
	safeChan[T any] struct {
		ch     chan T
		mu     sync.RWMutex
		closed bool
	}
	bondingCurveProgressUpdate struct {
		externalAddress string
		progress        *BondingCurveProgress
	}
)

func newSafeChan[T any](cap int) *safeChan[T] {
	return &safeChan[T]{ch: make(chan T, cap)}
}

func (s *safeChan[T]) C() <-chan T { return s.ch }

func (s *safeChan[T]) Send(val T, timeout time.Duration, shutdown <-chan struct{}) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return
	}
	select {
	case s.ch <- val:
	case <-time.After(timeout):
	case <-shutdown:
	}
}

func (s *safeChan[T]) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.ch)
	}
}

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
		swaps:                           make(chan *Trade, 1000),
		bondingCurveProgressUpdates:     make(chan bondingCurveProgressUpdate, 1000),
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
			value.closeOnce.Do(func() {
				value.listeners.DeleteMatching(func(_ uint64, sc *safeChan[T]) (bool, bool) {
					sc.Close()
					return true, false
				})
			})
			return true
		})
	}()
	for newEventTokenExternalAddr := range notifyChan {
		addr := newEventTokenExternalAddr.ExternalAddress()
		dest, ok := subs.Load(addr)
		if ok {
			dest.listeners.Range(func(_ uint64, sc *safeChan[T]) bool {
				go sc.Send(newEventTokenExternalAddr.Value(), 10*time.Millisecond, s.shutdown)
				return true
			})
		}
	}
}

func (s *subscriptions) SubscribeOnSwaps(ctx context.Context, externalAddress, userID string) <-chan *Trade {
	return subscribe[*Trade](ctx, externalAddress, userID, s.swapSubs)
}
func (s *subscriptions) SubscribeOnBondingCurveProgress(ctx context.Context, externalAddress, userID string) <-chan *BondingCurveProgress {
	return subscribe[*BondingCurveProgress](ctx, externalAddress, userID, s.bondingCurveProgressUpdatesSubs)
}

func subscribe[T any](ctx context.Context, externalAddress, userID string, subs *xsync.Map[string, *subscription[T]]) <-chan T {
	sc := newSafeChan[T](100)

	sub, _ := subs.LoadOrCompute(externalAddress, func() (*subscription[T], bool) {
		return &subscription[T]{
			listeners: xsync.NewMap[uint64, *safeChan[T]](),
		}, false
	})

	listenerID := sub.nextID.Add(1)
	sub.listeners.Store(listenerID, sc)

	go func() {
		<-ctx.Done()
		if removed, ok := sub.listeners.LoadAndDelete(listenerID); ok {
			removed.Close()
			if sub.listeners.Size() == 0 {
				subs.Delete(externalAddress)
			}
		}
	}()

	return sc.C()
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
