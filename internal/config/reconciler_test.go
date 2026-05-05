package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadReconcilerConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(path, []byte(`
reconciler:
  maxReconcileCount: 5
  targets:
    - name: agent-aws
      address: localhost:9091
`), 0o600)
	require.NoError(t, err)

	cfg, err := LoadReconcilerConfig(path)
	require.NoError(t, err)

	assert.Equal(t, uint64(5), cfg.MaxReconcileCount)
	require.Len(t, cfg.Targets, 1)
	assert.Equal(t, ReconcilerTarget{Name: "agent-aws", Address: "localhost:9091"}, cfg.Targets[0])
}

func TestRootConfigIncludesReconcilerConfig(t *testing.T) {
	cfg := validRootConfig()
	cfg.Reconciler = ReconcilerConfig{
		MaxReconcileCount: 12,
		Targets: []ReconcilerTarget{
			{Name: "agent-aws", Address: "localhost:9091"},
		},
	}

	require.NoError(t, cfg.Validate())

	assert.Equal(t, uint64(12), cfg.Reconciler.MaxReconcileCount)
	assert.Equal(t, []ReconcilerTarget{{Name: "agent-aws", Address: "localhost:9091"}}, cfg.Reconciler.Targets)
}

func TestRootConfigLeavesEmptyReconcilerConfigAlone(t *testing.T) {
	cfg := validRootConfig()

	require.NoError(t, cfg.Validate())

	assert.Equal(t, ReconcilerConfig{}, cfg.Reconciler)
}

func TestReconcilerConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*ReconcilerConfig)
		wantErr error
	}{
		{
			name:   "valid default config",
			modify: func(*ReconcilerConfig) {},
		},
		{
			name: "duplicate target",
			modify: func(c *ReconcilerConfig) {
				target := validReconcilerTarget("agent-aws")
				c.Targets = []ReconcilerTarget{target, target}
			},
			wantErr: ErrReconcilerTargetDuplicate,
		},
		{
			name: "target name required",
			modify: func(c *ReconcilerConfig) {
				c.Targets = []ReconcilerTarget{{Address: "localhost:9091"}}
			},
			wantErr: ErrReconcilerTargetNameEmpty,
		},
		{
			name: "target address required",
			modify: func(c *ReconcilerConfig) {
				c.Targets = []ReconcilerTarget{{Name: "agent-aws"}}
			},
			wantErr: ErrReconcilerTargetAddressEmpty,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := ReconcilerConfig{}
			tt.modify(&cfg)

			err := cfg.Validate()
			if tt.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tt.wantErr, "got %v, want %v", err, tt.wantErr)
		})
	}
}

func validReconcilerTarget(name string) ReconcilerTarget {
	return ReconcilerTarget{Name: name, Address: "localhost:9091"}
}
