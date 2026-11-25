package spec

import (
	"errors"
	"fmt"

	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/sealer/sealerprovider"
	"github.com/openkcm/krypton/internal/vault/vaultprovider"
)

var (
	ErrRootKeyNoProviders     = errors.New("root key must allow at least one provider")
	ErrRootKeyUnknownProvider = errors.New("root key allowed provider is not a known sealer type")
)

// RootKeySpec configures the root key: which sealer providers may be bound to it
// at runtime (via the root key service) and the vault that stores the bound
// provider specs. The root provider itself is created at runtime through the
// root key API, not statically in configuration.
type RootKeySpec struct {
	AllowedProviders []sealer.Type      `yaml:"allowed_providers"`
	Vault            vaultprovider.Spec `yaml:"vault"`
}

// Validate checks the RootKeySpec for structural correctness.
func (s *RootKeySpec) Validate() error {
	if len(s.AllowedProviders) == 0 {
		return ErrRootKeyNoProviders
	}
	for _, p := range s.AllowedProviders {
		if err := sealerprovider.ValidateType(p); err != nil {
			return fmt.Errorf("%w: %q: %w", ErrRootKeyUnknownProvider, p, err)
		}
	}
	if err := s.Vault.Validate(); err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	return nil
}
