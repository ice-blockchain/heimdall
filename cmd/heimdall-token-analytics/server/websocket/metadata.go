// SPDX-License-Identifier: ice License 1.0

package websocket

import (
	"iter"
	"sync"
)

type (
	metadataHander struct {
		m sync.Map
	}
)

func (m *metadataHander) Set(key string, value any) {
	m.m.Store(key, value)
}

func (m *metadataHander) Get(key string) (any, bool) {
	return m.m.Load(key)
}

func (m *metadataHander) Range() iter.Seq2[string, any] {
	return func(yield func(string, any) bool) {
		m.m.Range(func(key, value any) bool {
			return yield(key.(string), value)
		})
	}
}

func (m *metadataHander) Delete(key string) (any, bool) {
	return m.m.LoadAndDelete(key)
}

func (m *metadataHander) Clear() {
	m.m.Clear()
}
