package example

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// KeyState is the lifecycle position of a key in this toy domain.
type KeyState string

const (
	// KeyInactive is the initial state of every key.
	KeyInactive KeyState = "INACTIVE"
	// KeyActive is reached once the key (and, by cascade ordering, its parent)
	// has been activated.
	KeyActive KeyState = "ACTIVE"
	// KeyFailed marks a key whose activation job terminated in failure.
	KeyFailed KeyState = "FAILED"
)

// KeyStore is the domain state the handlers act on. In a real deployment the
// root and each agent would own separate stores; here a single in-memory store
// stands in for all of them so the example runs in one process.
type KeyStore struct {
	mu   sync.Mutex
	keys map[string]KeyState
}

// NewKeyStore returns a store seeded with the given key IDs, all inactive.
func NewKeyStore(keyIDs ...string) *KeyStore {
	keys := make(map[string]KeyState, len(keyIDs))
	for _, id := range keyIDs {
		keys[id] = KeyInactive
	}
	return &KeyStore{keys: keys}
}

// State returns the current state of a key and whether it is known.
func (s *KeyStore) State(keyID string) (KeyState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.keys[keyID]
	return state, ok
}

// setState updates a known key's state. It reports whether the key existed.
func (s *KeyStore) setState(keyID string, state KeyState) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.keys[keyID]; !ok {
		return false
	}
	s.keys[keyID] = state
	return true
}

// parentActive reports whether a key's parent is active. A root key (empty
// parentID) is always considered ready.
func (s *KeyStore) parentActive(parentID string) bool {
	if parentID == "" {
		return true
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.keys[parentID] == KeyActive
}

// String renders the store deterministically (sorted by key ID) for examples.
func (s *KeyStore) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	ids := make([]string, 0, len(s.keys))
	for id := range s.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("%s=%s", id, s.keys[id])
	}
	return strings.Join(parts, " ")
}
