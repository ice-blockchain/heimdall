// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"sync"
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
		notifyClients *xsync.Map[string, chan T]
		closeOnce     sync.Once
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
			value.closeOnce.Do(func() {
				value.notifyClients.DeleteMatching(func(userKey string, clientNotifyChannel chan T) (bool, bool) {
					close(clientNotifyChannel)
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
			dest.notifyClients.Range(func(userID string, clientNotifyChannel chan T) bool {
				go func(ch chan T, val T) {
					select {
					case ch <- val:
					case <-time.After(10 * time.Millisecond):
					case <-s.shutdown:
					}
				}(clientNotifyChannel, newEventTokenExternalAddr.Value())
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

func subscribe[T any](ctx context.Context, externalAddress, userID string, subs *xsync.Map[string, *subscription[T]]) (nofifyClients <-chan T) {
	go func() {
		<-ctx.Done()

		sub, ok := subs.Load(externalAddress)
		if ok {
			if nofity, deleted := sub.notifyClients.LoadAndDelete(userID); deleted {
				close(nofity)
				last := sub.notifyClients.Size() == 0
				if last {
					subs.Delete(externalAddress)
				}
			}
		}
	}()
	progress, loaded := subs.LoadOrCompute(externalAddress, func() (newValue *subscription[T], cancel bool) {
		notif := xsync.NewMap[string, chan T]()
		nofifyClient := make(chan T, 100)
		notif.Store(userID, nofifyClient)
		nofifyClients = nofifyClient
		return &subscription[T]{notifyClients: notif}, false
	})
	if loaded {
		nofifyClients = progress.addClientSub(userID)
	}
	return nofifyClients
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

func (s *subscription[T]) addClientSub(userID string) chan T {
	clientSub := make(chan T, 100)
	prev, hasPrev := s.notifyClients.LoadAndStore(userID, clientSub)
	if hasPrev {
		close(prev)
	}
	return clientSub
}
