package kmip

import (
	"context"
	"errors"

	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/pkg/model"
)

// Sentinel errors returned by KeyManager implementations. The KMIP handler
// maps these into KMIP result reasons; keeping them as sentinels lets callers
// remain framework-agnostic.
var (
	// ErrKeyNotFound signals that no key exists for the given tenant/keyID
	// (or that the key has been destroyed).
	ErrKeyNotFound = errors.New("kmip: key not found")
	// ErrKeyNotActive signals that a key exists but is not in the Active
	// lifecycle state.
	ErrKeyNotActive = errors.New("kmip: key not active")
)

// KeyManager abstracts the retrieval of DEK material and metadata. This
// ticket ships an in-memory fake implementation; a follow-up will provide a
// real adapter backed by the SQL key store and the unwrap path.
type KeyManager interface {
	// GetDEK returns the unwrapped DEK material and metadata for the given
	// tenant/keyID. The material is held in secure memory and the caller is
	// responsible for copying only what it needs.
	GetDEK(ctx context.Context, tenantID, keyID string) (*DEK, error)

	// GetKeyInfo returns metadata without material. Used for GetAttributes.
	GetKeyInfo(ctx context.Context, tenantID, keyID string) (*KeyInfo, error)
}

// DEK is an unwrapped data encryption key plus enough metadata to build a
// KMIP SymmetricKey response.
type DEK struct {
	Material   *securemem.Data
	Algorithm  Algorithm
	LengthBits int32
	State      model.KeyLifeCycleState
}

// KeyInfo is DEK metadata without material.
type KeyInfo struct {
	Algorithm  Algorithm
	LengthBits int32
	State      model.KeyLifeCycleState
}

// Algorithm is a Krypton-side enum for the symmetric algorithm of a DEK. The
// KMIP handler translates it into the wire-format constants from kmip-go.
// Kept small on purpose — only what we serve today.
type Algorithm int

const (
	AlgorithmUnknown Algorithm = iota
	AlgorithmAES
)
