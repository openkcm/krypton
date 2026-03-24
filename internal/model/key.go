package model

import (
	"errors"
)

const (
	// KeyRoleRoot represents the top-level key.
	KeyRoleRoot KeyRole = "root"
	// KeyRoleKek represents a key encryption key, used to encrypt other keys.
	KeyRoleKek KeyRole = "kek"
	// KeyRoleDek represents a data encryption key, used to encrypt data directly.
	KeyRoleDek KeyRole = "dek"
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

const validKeyUsageMask = KeyUsageEncrypt | KeyUsageDecrypt | KeyUsageWrap | KeyUsageUnwrap

var (
	ErrKeyHierarchyNameEmpty       = errors.New("hierarchy name cannot be empty")
	ErrKeyHierarchyKeysListEmpty   = errors.New("keys list cannot be empty")
	ErrKeyHierarchyFirstKeyNotRoot = errors.New("first key must have role 'root'")
	ErrKeyHierarchyDuplicateKind   = errors.New("duplicate key kind found in hierarchy")
	ErrKeyHierarchyDuplicateRoot   = errors.New("only one key can have role 'root'")
	ErrKeySpecKindEmpty            = errors.New("key kind cannot be empty")
	ErrKeySpecRoleInvalid          = errors.New("invalid role: must be 'root', 'kek', or 'dek'")
	ErrKeySpecAlgorithmInvalid     = errors.New("invalid algorithm: must be 'AES256'")
	ErrKeySpecUsageInvalid         = errors.New("invalid key usage")

	validKeyRoles = map[KeyRole]struct{}{
		KeyRoleRoot: {},
		KeyRoleKek:  {},
		KeyRoleDek:  {},
	}
)

// KeyHierarchy represents a structured arrangement of cryptographic keys, defining their relationships
// and roles within a system.
type KeyHierarchy struct {
	Name string
	Keys []KeySpec
}

// KeySpec defines the properties and constraints of an individual key within a hierarchy, including its
// type, role, algorithm, and allowed operations.
type KeySpec struct {
	Kind      string
	Role      KeyRole
	Algorithm KeyAlgorithm
	Usage     KeyUsage
}

type (
	KeyRole      string
	KeyAlgorithm string
	KeyUsage     uint
)

// Validate checks the integrity and correctness of the KeyHierarchy instance, ensuring that it adheres to the
// defined rules and constraints for hierarchy structure and key specifications.
func (h KeyHierarchy) Validate() error {
	if h.Name == "" {
		return ErrKeyHierarchyNameEmpty
	}
	if len(h.Keys) == 0 {
		return ErrKeyHierarchyKeysListEmpty
	}

	if h.Keys[0].Role != KeyRoleRoot {
		return ErrKeyHierarchyFirstKeyNotRoot
	}

	seen := make(map[string]struct{}, len(h.Keys))
	for i, k := range h.Keys {
		if i > 0 && k.Role == KeyRoleRoot {
			return ErrKeyHierarchyDuplicateRoot
		}

		err := k.Validate()
		if err != nil {
			return err
		}

		if _, ok := seen[k.Kind]; ok {
			return ErrKeyHierarchyDuplicateKind
		}
		seen[k.Kind] = struct{}{}
	}
	return nil
}

// Validate checks the validity of the KeySpec instance, ensuring that it meets the required criteria for key
// specifications, such as having a non-empty kind, a valid role, a supported algorithm, and appropriate usage flags.
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

	if k.Usage == 0 || (k.Usage & ^validKeyUsageMask != 0) {
		return ErrKeySpecUsageInvalid
	}

	return nil
}
