package model

import (
	"errors"
	"fmt"
)

var (
	// ErrKeyHierarchyNameEmpty is returned when a KeyHierarchy has an empty name.
	ErrKeyHierarchyNameEmpty = errors.New("hierarchy name cannot be empty")
	// ErrKeyHierarchyKeysListEmpty is returned when a KeyHierarchy has a nil or empty keys list.
	ErrKeyHierarchyKeysListEmpty = errors.New("keys list cannot be empty")
	// ErrKeyHierarchyFirstKeyNotRoot is returned when the first key in a KeyHierarchy does not have role 'root'.
	ErrKeyHierarchyFirstKeyNotRoot = errors.New("first key must have role 'root'")
	// ErrKeyHierarchyDuplicateKind is returned when two or more keys in a KeyHierarchy share the same kind.
	ErrKeyHierarchyDuplicateKind = errors.New("duplicate key kind found in hierarchy")
	// ErrKeyHierarchyDuplicateRoot is returned when more than one key in a KeyHierarchy has role 'root'.
	ErrKeyHierarchyDuplicateRoot = errors.New("only one key can have role 'root'")
	// ErrKeyHierarchyLastKeyNotDek is returned when the last key in a multi-key KeyHierarchy does not have role 'dek'.
	ErrKeyHierarchyLastKeyNotDek = errors.New("last key must have role 'dek'")
	// ErrKeyHierarchyInvalidIntermediateKey is returned when an intermediate key in a KeyHierarchy does not have role 'kek' or 'tek'.
	ErrKeyHierarchyInvalidIntermediateKey = errors.New("intermediate keys must have role 'kek' or 'tek'")
)

// KeyHierarchy defines an ordered arrangement of cryptographic keys and their roles.
type KeyHierarchy struct {
	Name     string
	KeySpecs []KeySpec
}

// Validate checks the KeyHierarchy for structural correctness. It returns an error if the name is
// empty, the keys list is empty or nil, the first key does not have role 'root', the last key in a
// multi-key hierarchy does not have role 'dek', intermediate keys must have role 'kek' or 'tek',
// there are multiple keys with role 'root', there are duplicate key kinds, or any KeySpec fails its
// own validation.
func (h KeyHierarchy) Validate() error {
	if h.Name == "" {
		return ErrKeyHierarchyNameEmpty
	}

	keyLen := len(h.KeySpecs)
	if keyLen == 0 {
		return ErrKeyHierarchyKeysListEmpty
	}

	seenKind := make(map[KeyKind]struct{}, keyLen)
	for i, k := range h.KeySpecs {
		if err := k.Validate(); err != nil {
			return fmt.Errorf("key at index %d: %w", i, err)
		}

		switch i {
		case 0:
			// For single-key hierarchies (keyLen == 1), this is the only case
			// that executes. A root-only hierarchy is valid; the last-key-must-be-dek
			// rule applies only to multi-key hierarchies.
			if k.Role != KeyRoleRoot {
				return ErrKeyHierarchyFirstKeyNotRoot
			}
		case (keyLen - 1):
			if k.Role != KeyRoleDek {
				return ErrKeyHierarchyLastKeyNotDek
			}
		default:
			switch k.Role {
			case KeyRoleRoot:
				return ErrKeyHierarchyDuplicateRoot
			case KeyRoleDek:
				return ErrKeyHierarchyInvalidIntermediateKey
			}
		}

		if _, ok := seenKind[k.Kind]; ok {
			return ErrKeyHierarchyDuplicateKind
		}

		seenKind[k.Kind] = struct{}{}
	}

	return nil
}

// FindKeySpec searches the KeySpecs in the hierarchy for a key with the specified kind.
// It returns the KeySpec and true if found, or an empty KeySpec and false if not found.
func (h KeyHierarchy) FindKeySpec(kind KeyKind) (KeySpec, bool) {
	for _, k := range h.KeySpecs {
		if k.Kind == kind {
			return k, true
		}
	}
	return KeySpec{}, false
}
