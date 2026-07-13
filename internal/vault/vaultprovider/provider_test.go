package vaultprovider_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/internal/vault/openbaovault"
	"github.com/openkcm/krypton/internal/vault/sqlitevault"
	"github.com/openkcm/krypton/internal/vault/vaultprovider"
)

func TestSpec_Validate(t *testing.T) {
	tts := []struct {
		name   string
		spec   vaultprovider.Spec
		expErr bool
	}{
		{
			name: "should fail for empty name",
			spec: vaultprovider.Spec{
				Name:   "",
				Type:   sqlitevault.TypeUnsafeMemory,
				Config: &sqlitevault.InMemoryConfig{},
			},
			expErr: true,
		},
		{
			name: "should fail for empty type",
			spec: vaultprovider.Spec{
				Name: "my-vault",
				Type: "",
			},
			expErr: true,
		},
		{
			name: "should pass for valid in-memory spec",
			spec: vaultprovider.Spec{
				Name:   "my-vault",
				Type:   sqlitevault.TypeUnsafeMemory,
				Config: &sqlitevault.InMemoryConfig{},
			},
		},
		{
			name: "should pass for valid file spec",
			spec: vaultprovider.Spec{
				Name: "my-vault",
				Type: sqlitevault.TypeUnsafe,
				Config: &sqlitevault.FileConfig{
					Path: "/tmp/vault.db",
				},
			},
		},
		{
			name: "should fail when file config has empty path",
			spec: vaultprovider.Spec{
				Name: "my-vault",
				Type: sqlitevault.TypeUnsafe,
				Config: &sqlitevault.FileConfig{
					Path: "",
				},
			},
			expErr: true,
		},
		{
			name: "should pass for openbao spec",
			spec: vaultprovider.Spec{
				Name: "my-vault",
				Type: openbaovault.TypeOpenBao,
				Config: &openbaovault.Config{
					Address: "https://openbao.example.com",
				},
			},
		},
		{
			name: "should fail when openbao config has empty address",
			spec: vaultprovider.Spec{
				Name: "my-vault",
				Type: openbaovault.TypeOpenBao,
				Config: &openbaovault.Config{
					Address: "",
				},
			},
			expErr: true,
		},
		{
			name: "should fail for unsupported type",
			spec: vaultprovider.Spec{
				Name: "my-vault",
				Type: "unknown-type",
			},
			expErr: true,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			err := tt.spec.Validate()

			// then
			if tt.expErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestSpec_UnmarshalYAML(t *testing.T) {
	t.Run("should unmarshal in-memory spec", func(t *testing.T) {
		// given
		input := `
name: test-vault
type: unsafe-sqlite-memory
`
		// when
		var spec vaultprovider.Spec
		err := yaml.Unmarshal([]byte(input), &spec)

		// then
		require.NoError(t, err)
		assert.Equal(t, "test-vault", spec.Name)
		assert.Equal(t, sqlitevault.TypeUnsafeMemory, spec.Type)
		assert.IsType(t, &sqlitevault.InMemoryConfig{}, spec.Config)
	})

	t.Run("should unmarshal file spec with config", func(t *testing.T) {
		// given
		input := `
name: file-vault
type: unsafe-sqlite
config:
  path: /var/data/vault.db
`
		// when
		var spec vaultprovider.Spec
		err := yaml.Unmarshal([]byte(input), &spec)

		// then
		require.NoError(t, err)
		assert.Equal(t, "file-vault", spec.Name)
		assert.Equal(t, sqlitevault.TypeUnsafe, spec.Type)

		cfg, ok := spec.Config.(*sqlitevault.FileConfig)
		require.True(t, ok)
		assert.Equal(t, "/var/data/vault.db", cfg.Path)
	})
	t.Run("should unmarshal openbao spec with config", func(t *testing.T) {
		// given
		input := `
name: openbao-vault
type: openbao
config:
  address: http://openbao.example.com
`
		// when
		var spec vaultprovider.Spec
		err := yaml.Unmarshal([]byte(input), &spec)

		// then
		require.NoError(t, err)
		assert.Equal(t, "openbao-vault", spec.Name)
		assert.Equal(t, openbaovault.TypeOpenBao, spec.Type)

		cfg, ok := spec.Config.(*openbaovault.Config)
		require.True(t, ok)
		assert.Equal(t, "http://openbao.example.com", cfg.Address)
	})

	t.Run("should return error for unknown type", func(t *testing.T) {
		// given
		input := `
name: bad-vault
type: unknown-type
`
		// when
		var spec vaultprovider.Spec
		err := yaml.Unmarshal([]byte(input), &spec)

		// then
		assert.ErrorIs(t, err, vault.ErrUnknownType)
	})
}

func TestGetVault(t *testing.T) {
	t.Run("should create in-memory vault", func(t *testing.T) {
		// given
		ctx := t.Context()
		spec := vaultprovider.Spec{
			Name:   "mem-vault",
			Type:   sqlitevault.TypeUnsafeMemory,
			Config: &sqlitevault.InMemoryConfig{},
		}

		// when
		v, err := vaultprovider.GetVault(ctx, spec)

		// then
		require.NoError(t, err)
		assert.NotNil(t, v)

		info := v.Info()
		assert.Equal(t, "mem-vault", info.Name)
		assert.Equal(t, sqlitevault.TypeUnsafeMemory, info.Type)
	})

	t.Run("should create file-based vault", func(t *testing.T) {
		// given
		ctx := t.Context()
		dbPath := filepath.Join(t.TempDir(), "test.db")
		spec := vaultprovider.Spec{
			Name: "file-vault",
			Type: sqlitevault.TypeUnsafe,
			Config: &sqlitevault.FileConfig{
				Path: dbPath,
			},
		}

		// when
		v, err := vaultprovider.GetVault(ctx, spec)

		// then
		require.NoError(t, err)
		assert.NotNil(t, v)

		info := v.Info()
		assert.Equal(t, "file-vault", info.Name)
		assert.Equal(t, sqlitevault.TypeUnsafe, info.Type)
	})

	t.Run("should create openbao vault", func(t *testing.T) {
		// given
		ctx := t.Context()
		spec := vaultprovider.Spec{
			Name: "openbao-vault",
			Type: openbaovault.TypeOpenBao,
			Config: &openbaovault.Config{
				Address: "http://openbao.example.com",
			},
		}

		// when
		v, err := vaultprovider.GetVault(ctx, spec)

		// then
		require.NoError(t, err)
		assert.NotNil(t, v)

		info := v.Info()
		assert.Equal(t, "openbao-vault", info.Name)
		assert.Equal(t, openbaovault.TypeOpenBao, info.Type)
	})

	t.Run("should return error for unknown type", func(t *testing.T) {
		// given
		ctx := t.Context()
		spec := vaultprovider.Spec{
			Name: "bad",
			Type: "unknown",
		}

		// when
		v, err := vaultprovider.GetVault(ctx, spec)

		// then
		assert.ErrorIs(t, err, vault.ErrUnknownType)
		assert.Nil(t, v)
	})
}
