package model

import (
	"errors"
	"slices"
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
	Role      string
	Algorithm string
	Usage     []string
}

var (
	ErrKeyHierarchyNameEmpty    = errors.New("hierarchy name cannot be empty")
	ErrHierarchyKeysListEmpty   = errors.New("keys list cannot be empty")
	ErrHierarchyFirstKeyNotRoot = errors.New("first key must have role 'root'")
	ErrHierarchyDuplicateKind   = errors.New("duplicate key kind found in hierarchy")
	ErrKeySpecNameEmpty         = errors.New("key kind cannot be empty")
	ErrKeySpecRoleInvalid       = errors.New("invalid role: must be 'root', 'kek', or 'dek'")
	ErrKeySpecAlgorithmEmpty    = errors.New("algorithm cannot be empty")
	ErrKeySpecUsageListEmpty    = errors.New("usage list cannot be empty")

	roles = map[string]struct{}{
		"root": {},
		"kek":  {},
		"dek":  {},
	}
)

// Validate checks the integrity and correctness of the KeyHierarchy instance, ensuring that it adheres to the
// defined rules and constraints for hierarchy structure and key specifications.
func (h KeyHierarchy) Validate() error {
	if h.Name == "" {
		return ErrKeyHierarchyNameEmpty
	}
	if len(h.Keys) == 0 {
		return ErrHierarchyKeysListEmpty
	}

	if h.Keys[0].Role != "root" {
		return ErrHierarchyFirstKeyNotRoot
	}

	isFound := make(map[string]struct{}, len(h.Keys))
	for _, k := range h.Keys {
		err := k.Validate()
		if err != nil {
			return err
		}

		if _, ok := isFound[k.Kind]; ok {
			return ErrHierarchyDuplicateKind
		}
		isFound[k.Kind] = struct{}{}
	}
	return nil
}

// Validate checks the properties of the KeySpec instance to ensure that it meets the required criteria for a valid
// key specification, such as having a non-empty kind, a valid role, a specified algorithm, and a non-empty usage
// list without empty strings.
func (k KeySpec) Validate() error {
	if k.Kind == "" {
		return ErrKeySpecNameEmpty
	}

	_, ok := roles[k.Role]
	if !ok {
		return ErrKeySpecRoleInvalid
	}

	if k.Algorithm == "" {
		return ErrKeySpecAlgorithmEmpty
	}

	if len(k.Usage) == 0 {
		return ErrKeySpecUsageListEmpty
	}

	if slices.Contains(k.Usage, "") {
		return ErrKeySpecUsageListEmpty
	}

	return nil
}
