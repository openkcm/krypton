package kmip

import (
	"context"
	"fmt"
	"sync"

	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/pkg/model"
)

// SeedDEK describes a single DEK to preload into a memKeyManager.
type SeedDEK struct {
	TenantID   string
	KeyID      string
	Material   []byte
	Algorithm  Algorithm
	LengthBits int32
	State      model.KeyLifeCycleState
}

// memKeyManager is an in-memory KeyManager for tests and reference/dev use.
// It stores material inside securemem.Data so the reference implementation
// exercises the same secure-memory path a real backend will.
type memKeyManager struct {
	mu      sync.RWMutex
	entries map[string]*memEntry
}

type memEntry struct {
	data       *securemem.Data
	algorithm  Algorithm
	lengthBits int32
	state      model.KeyLifeCycleState
}

// NewMemKeyManager returns a KeyManager seeded with the given DEKs. Each
// seed's Material is copied into a locked secure-memory region; the caller
// may zero its own copy after this call returns.
func NewMemKeyManager(seeds ...SeedDEK) (KeyManager, error) {
	m := &memKeyManager{entries: make(map[string]*memEntry, len(seeds))}
	for _, s := range seeds {
		if err := m.seed(s); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (m *memKeyManager) seed(s SeedDEK) error {
	if s.TenantID == "" || s.KeyID == "" {
		return fmt.Errorf("kmip: seed requires tenant_id and key_id")
	}
	if len(s.Material) == 0 {
		return fmt.Errorf("kmip: seed material for %s:%s is empty", s.TenantID, s.KeyID)
	}
	data, err := securemem.NewData(s.TenantID+":"+s.KeyID, len(s.Material))
	if err != nil {
		return fmt.Errorf("kmip: alloc secure memory: %w", err)
	}
	copy(data.SecureBytes(), s.Material)

	m.entries[memKey(s.TenantID, s.KeyID)] = &memEntry{
		data:       data,
		algorithm:  s.Algorithm,
		lengthBits: s.LengthBits,
		state:      s.State,
	}
	return nil
}

// Close destroys all secure memory regions held by this manager. Safe to
// call multiple times.
func (m *memKeyManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var firstErr error
	for k, e := range m.entries {
		if err := e.data.Destroy(); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(m.entries, k)
	}
	return firstErr
}

func (m *memKeyManager) GetDEK(ctx context.Context, tenantID, keyID string) (*DEK, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	e, ok := m.entries[memKey(tenantID, keyID)]
	if !ok || e.state == model.KeyLifeCycleDestroyed {
		return nil, ErrKeyNotFound
	}
	if e.state != model.KeyLifeCycleActive {
		return nil, ErrKeyNotActive
	}
	return &DEK{
		Material:   e.data,
		Algorithm:  e.algorithm,
		LengthBits: e.lengthBits,
		State:      e.state,
	}, nil
}

func (m *memKeyManager) GetKeyInfo(ctx context.Context, tenantID, keyID string) (*KeyInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	e, ok := m.entries[memKey(tenantID, keyID)]
	if !ok || e.state == model.KeyLifeCycleDestroyed {
		return nil, ErrKeyNotFound
	}
	if e.state != model.KeyLifeCycleActive {
		return nil, ErrKeyNotActive
	}
	return &KeyInfo{
		Algorithm:  e.algorithm,
		LengthBits: e.lengthBits,
		State:      e.state,
	}, nil
}

func memKey(tenantID, keyID string) string {
	return tenantID + "\x00" + keyID
}
