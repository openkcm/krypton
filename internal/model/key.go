package model

import (
	"errors"
	"sync"
)

const (
	// KeyRoleRoot represents the top-level key.
	KeyRoleRoot KeyRole = "root"
	// KeyRoleKek represents a key encryption key, used to encrypt other keys.
	KeyRoleKek KeyRole = "kek"
	// KeyRoleDek represents a data encryption key, used to encrypt data directly.
	KeyRoleDek KeyRole = "dek"
	// KeyRoleTek represents a traffic encryption key.
	KeyRoleTek KeyRole = "tek"
)

// KeyAlgorithmAES256 represents the AES-256 encryption algorithm.
const KeyAlgorithmAES256 KeyAlgorithm = "AES256"

const (
	// KeyUsageEncrypt allows the key to be used for encryption operations.
	KeyUsageEncrypt KeyUsage = 1 << iota
	// KeyUsageDecrypt allows the key to be used for decryption operations.
	KeyUsageDecrypt
	// KeyUsageWrap allows the key to be used for wrapping (encrypting) other keys.
	KeyUsageWrap
	// KeyUsageUnwrap allows the key to be used for unwrapping (decrypting) other keys.
	KeyUsageUnwrap
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
	// ErrKeySpecKindEmpty is returned when a KeySpec has an empty kind.
	ErrKeySpecKindEmpty = errors.New("key kind cannot be empty")
	// ErrKeySpecRoleInvalid is returned when a KeySpec has a role other than 'root', 'kek', 'tek', or 'dek'.
	ErrKeySpecRoleInvalid = errors.New("invalid role: must be 'root', 'kek', 'tek', or 'dek'")
	// ErrKeySpecAlgorithmInvalid is returned when a KeySpec has an algorithm other than 'AES256'.
	ErrKeySpecAlgorithmInvalid = errors.New("invalid algorithm: must be 'AES256'")
	// ErrKeyHierarchyInvalidIntermediateKey is returned when an intermediate key in a KeyHierarchy does not have role 'kek' or 'tek'.
	ErrKeyHierarchyInvalidIntermediateKey = errors.New("intermediate keys must have role 'kek' or 'tek'")

	validKeyRoles = map[KeyRole]struct{}{
		KeyRoleRoot: {},
		KeyRoleKek:  {},
		KeyRoleDek:  {},
		KeyRoleTek:  {},
	}
)

// KeyHierarchy defines an ordered arrangement of cryptographic keys and their roles.
type KeyHierarchy struct {
	Name         string
	Keys         []KeySpec
	keyKindUsage map[KeyKind]KeyUsage
	mu           sync.RWMutex
}

// KeySpec defines the properties of a key within a hierarchy, including its kind, role, and algorithm.
type KeySpec struct {
	Kind      KeyKind
	Role      KeyRole
	Algorithm KeyAlgorithm
}

type (
	// KeyKind identifies the type or purpose of a key within a hierarchy.
	KeyKind string
	// KeyRole identifies the role of a key within a hierarchy.
	KeyRole string
	// KeyAlgorithm identifies the encryption algorithm used by a key.
	KeyAlgorithm string
	// KeyUsage is a bitmask describing the permitted operations for a key.
	KeyUsage uint
)

// Validate checks the KeyHierarchy for structural correctness. It returns an error if the name is
// empty, the keys list is empty or nil, the first key does not have role 'root', the last key in a
// multi-key hierarchy does not have role 'dek', intermediate keys must have role 'kek' or 'tek',
// there are multiple keys with role 'root', there are duplicate key kinds, or any KeySpec fails its
// own validation.
func (h *KeyHierarchy) Validate() error {
	if h.Name == "" {
		return ErrKeyHierarchyNameEmpty
	}

	keyLen := len(h.Keys)
	if keyLen == 0 {
		return ErrKeyHierarchyKeysListEmpty
	}

	seenKind := make(map[KeyKind]struct{}, keyLen)
	for i, k := range h.Keys {
		if err := k.Validate(); err != nil {
			return err
		}

		switch i {
		case 0:
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

// Usage returns the KeyUsage for the key with the given kind.
// Returns false if no key with the given kind exists in the hierarchy.
func (h *KeyHierarchy) Usage(kind KeyKind) (KeyUsage, bool) {
	h.mu.RLock()
	if h.keyKindUsage != nil {
		usage, ok := h.keyKindUsage[kind]
		h.mu.RUnlock()
		return usage, ok
	}
	h.mu.RUnlock()

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.keyKindUsage == nil {
		keyLen := len(h.Keys)
		h.keyKindUsage = make(map[KeyKind]KeyUsage, keyLen)

		for _, k := range h.Keys {
			var usage KeyUsage
			switch k.Role {
			case KeyRoleRoot:
				if keyLen == 1 {
					usage = KeyUsageEncrypt | KeyUsageDecrypt
				} else {
					usage = KeyUsageWrap | KeyUsageUnwrap
				}
			case KeyRoleKek, KeyRoleTek:
				usage = KeyUsageWrap | KeyUsageUnwrap
			case KeyRoleDek:
				usage = KeyUsageEncrypt | KeyUsageDecrypt
			}
			h.keyKindUsage[k.Kind] = usage
		}
	}

	usage, ok := h.keyKindUsage[kind]
	return usage, ok
}

// Has reports whether all of the flags in usage are set in ku. Returns false if usage is zero.
func (ku KeyUsage) Has(usage KeyUsage) bool {
	if usage == 0 {
		return false
	}
	return ku&usage == usage
}

// Validate checks the KeySpec for correctness. It returns an error if the kind is empty,
// the role is not one of 'root', 'kek', 'tek', or 'dek', or the algorithm is not 'AES256'.
func (k KeySpec) Validate() error {
	if k.Kind == "" {
		return ErrKeySpecKindEmpty
	}

	_, ok := validKeyRoles[k.Role]
	if !ok {
		return ErrKeySpecRoleInvalid
	}

	if k.Algorithm != KeyAlgorithmAES256 {
		return ErrKeySpecAlgorithmInvalid
	}

	return nil
}
