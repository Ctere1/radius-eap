package eap

import (
	"sync"
	"time"

	"github.com/Ctere1/radius-eap/protocol"
)

// MemoryStateManager is a ready-to-use, concurrency-safe protocol.StateManager
// backed by an in-memory map with time-based eviction. It exists so consumers do
// not have to re-implement the same map+mutex+TTL boilerplate (and so they avoid
// the unbounded-growth bug of a naive map that never evicts abandoned EAP
// sessions).
//
// A single MemoryStateManager serves one EAP configuration (protocol.Settings).
// Construct it once at startup and share it across requests.
type MemoryStateManager struct {
	settings protocol.Settings
	ttl      time.Duration

	mu     sync.RWMutex
	states map[string]*stateEntry

	stopOnce sync.Once
	stop     chan struct{}
}

type stateEntry struct {
	state    *protocol.State
	lastSeen time.Time
}

// NewMemoryStateManager returns a MemoryStateManager for the given settings. If
// ttl > 0 a background goroutine evicts sessions whose last access is older than
// ttl; ttl <= 0 disables eviction (sessions live until the process exits). Call
// Close to stop the eviction goroutine when the manager is no longer needed.
func NewMemoryStateManager(settings protocol.Settings, ttl time.Duration) *MemoryStateManager {
	m := &MemoryStateManager{
		settings: settings,
		ttl:      ttl,
		states:   make(map[string]*stateEntry),
		stop:     make(chan struct{}),
	}
	if ttl > 0 {
		go m.evictLoop()
	}
	return m
}

func (m *MemoryStateManager) GetEAPSettings() protocol.Settings {
	return m.settings
}

func (m *MemoryStateManager) GetEAPState(key string) *protocol.State {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.states[key]
	if entry == nil {
		return nil
	}
	entry.lastSeen = time.Now()
	return entry.state
}

func (m *MemoryStateManager) SetEAPState(key string, state *protocol.State) {
	if key == "" || state == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.states[key] = &stateEntry{state: state, lastSeen: time.Now()}
}

// Delete removes a session immediately, e.g. once authentication has resolved.
func (m *MemoryStateManager) Delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.states, key)
}

// Len reports the number of live sessions. Primarily useful for tests/metrics.
func (m *MemoryStateManager) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.states)
}

// Close stops the background eviction goroutine. It is safe to call more than
// once.
func (m *MemoryStateManager) Close() {
	m.stopOnce.Do(func() { close(m.stop) })
}

func (m *MemoryStateManager) evictLoop() {
	ticker := time.NewTicker(m.ttl / 2)
	defer ticker.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			m.evictExpired(time.Now())
		}
	}
}

func (m *MemoryStateManager) evictExpired(now time.Time) {
	cutoff := now.Add(-m.ttl)
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, entry := range m.states {
		if entry.lastSeen.Before(cutoff) {
			delete(m.states, key)
		}
	}
}
