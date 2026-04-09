package spec

import (
	"errors"
)

type (
	// KeyKind identifies the type or purpose of a key within a hierarchy.
	KeyKind string
	// KeyRole identifies the role of a key within a hierarchy.
	KeyRole string
	// KeyAlgorithm identifies the encryption algorithm used by a key.
	KeyAlgorithm string
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

// validKeyAlgorithms defines the set of supported KeyAlgorithm values.
var validKeyAlgorithms = map[KeyAlgorithm]struct{}{
	KeyAlgorithmAES256: {},
}

var (
	// ErrKeySpecKindEmpty is returned when a KeySpec has an empty kind.
	ErrKeySpecKindEmpty = errors.New("key kind cannot be empty")
	// ErrKeySpecRoleInvalid is returned when a KeySpec has a role other than 'root', 'kek', 'tek', or 'dek'.
	ErrKeySpecRoleInvalid = errors.New("invalid role: must be 'root', 'kek', 'tek', or 'dek'")
	// ErrKeySpecAlgorithmInvalid is returned when a KeySpec has an algorithm other than 'AES256'.
	ErrKeySpecAlgorithmInvalid = errors.New("invalid algorithm: must be 'AES256'")

	validKeyRoles = map[KeyRole]struct{}{
		KeyRoleRoot: {},
		KeyRoleKek:  {},
		KeyRoleDek:  {},
		KeyRoleTek:  {},
	}
)

// KeySpec defines the properties of a key within a hierarchy, including its kind, role, and algorithm.
type KeySpec struct {
	Kind      KeyKind      `yaml:"kind"`
	Role      KeyRole      `yaml:"role"`
	Algorithm KeyAlgorithm `yaml:"algorithm"`
}

// Usage returns the KeyUsage associated with the KeySpec's role.
// It determines the allowed cryptographic operations for the key.
// For KeyRoleRoot, KeyRoleKek, and KeyRoleTek, it allows wrapping and unwrapping.
// For KeyRoleDek, it allows encryption and decryption.
// For any other role, it returns KeyUsageNone.
func (k KeySpec) Usage() KeyUsage {
	switch k.Role {
	case KeyRoleRoot, KeyRoleKek, KeyRoleTek:
		return KeyUsageWrap | KeyUsageUnwrap
	case KeyRoleDek:
		return KeyUsageEncrypt | KeyUsageDecrypt
	default:
		return KeyUsageNone
	}
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

	if !IsSupportedAlgorithm(k.Algorithm) {
		return ErrKeySpecAlgorithmInvalid
	}

	return nil
}

// IsSupportedAlgorithm checks if the provided KeyAlgorithm is supported by the system.
func IsSupportedAlgorithm(alg KeyAlgorithm) bool {
	_, ok := validKeyAlgorithms[alg]
	return ok
}
