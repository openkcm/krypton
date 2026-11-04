package spec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/sealer/staticsecret"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/internal/vault/sqlitevault"
	"github.com/openkcm/krypton/internal/vault/vaultprovider"
)

func TestRootKeySpec_Validate(t *testing.T) {
	validVault := vaultprovider.Spec{
		Name: "root-key-vault",
		Type: sqlitevault.TypeUnsafeMemory,
	}

	tests := []struct {
		name    string
		spec    spec.RootKeySpec
		errIs   error
		causeIs error
	}{
		{
			name: "should return error if allowed providers are nil",
			spec: spec.RootKeySpec{
				Vault: validVault,
			},
			errIs: spec.ErrRootKeyNoProviders,
		},
		{
			name: "should return error if allowed providers are empty",
			spec: spec.RootKeySpec{
				AllowedProviders: []sealer.Type{},
				Vault:            validVault,
			},
			errIs: spec.ErrRootKeyNoProviders,
		},
		{
			name: "should return error if an allowed provider is unknown",
			spec: spec.RootKeySpec{
				AllowedProviders: []sealer.Type{staticsecret.TypeStaticSecret, "unknown-provider"},
				Vault:            validVault,
			},
			errIs:   spec.ErrRootKeyUnknownProvider,
			causeIs: sealer.ErrUnknownType,
		},
		{
			name: "should return error if vault is invalid",
			spec: spec.RootKeySpec{
				AllowedProviders: []sealer.Type{staticsecret.TypeStaticSecret},
				Vault: vaultprovider.Spec{
					Type: sqlitevault.TypeUnsafeMemory,
				},
			},
			errIs: vaultprovider.ErrVaultNameEmpty,
		},
		{
			name: "should return nil for a valid spec",
			spec: spec.RootKeySpec{
				AllowedProviders: []sealer.Type{staticsecret.TypeStaticSecret},
				Vault:            validVault,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.spec.Validate()

			if tt.errIs == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tt.errIs)
			if tt.causeIs != nil {
				assert.ErrorIs(t, err, tt.causeIs)
			}
		})
	}
}
