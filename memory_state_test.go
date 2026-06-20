package eap

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Ctere1/radius-eap/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryStateManagerStoreAndGet(t *testing.T) {
	m := NewMemoryStateManager(protocol.Settings{}, 0)
	defer m.Close()

	assert.Nil(t, m.GetEAPState("missing"))

	st := protocol.BlankState(protocol.Settings{})
	m.SetEAPState("k", st)
	assert.Same(t, st, m.GetEAPState("k"))
	assert.Equal(t, 1, m.Len())

	m.Delete("k")
	assert.Nil(t, m.GetEAPState("k"))
	assert.Zero(t, m.Len())
}

func TestMemoryStateManagerIgnoresEmptyKeyOrNil(t *testing.T) {
	m := NewMemoryStateManager(protocol.Settings{}, 0)
	defer m.Close()

	m.SetEAPState("", protocol.BlankState(protocol.Settings{}))
	m.SetEAPState("k", nil)
	assert.Zero(t, m.Len())
}

func TestMemoryStateManagerEvictsExpired(t *testing.T) {
	m := NewMemoryStateManager(protocol.Settings{}, time.Hour)
	defer m.Close()

	m.SetEAPState("old", protocol.BlankState(protocol.Settings{}))
	m.SetEAPState("fresh", protocol.BlankState(protocol.Settings{}))

	// Force "old" to look stale, then run a manual eviction pass.
	m.mu.Lock()
	m.states["old"].lastSeen = time.Now().Add(-2 * time.Hour)
	m.mu.Unlock()

	m.evictExpired(time.Now())

	assert.Nil(t, m.GetEAPState("old"))
	assert.NotNil(t, m.GetEAPState("fresh"))
}

func TestMemoryStateManagerConcurrentAccess(t *testing.T) {
	m := NewMemoryStateManager(protocol.Settings{}, 0)
	defer m.Close()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := strconv.Itoa(i % 8)
			m.SetEAPState(key, protocol.BlankState(protocol.Settings{}))
			_ = m.GetEAPState(key)
			_ = m.Len()
		}(i)
	}
	wg.Wait()
	require.LessOrEqual(t, m.Len(), 8)
}
