package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/spec"
)

func TestKMIPConfigValidate(t *testing.T) {
	t.Parallel()
	valid := config.KMIP{
		Name:     "test-kmip",
		BindAddr: "0.0.0.0",
		Port:     5696,
		TLS: config.TLSServer{
			CertPath: "/etc/tls/server.pem",
			KeyPath:  "/etc/tls/server-key.pem",
			CAPath:   "/etc/tls/ca.pem",
		},
	}

	tests := []struct {
		name    string
		mutate  func(*config.KMIP)
		wantErr error
	}{
		{"valid", func(*config.KMIP) {}, nil},
		{"empty name", func(c *config.KMIP) { c.Name = "" }, config.ErrKMIPEmptyName},
		{"empty bind addr", func(c *config.KMIP) { c.BindAddr = "" }, config.ErrKMIPEmptyBindAddr},
		{"port too low", func(c *config.KMIP) { c.Port = 0 }, config.ErrKMIPInvalidPort},
		{"port too high", func(c *config.KMIP) { c.Port = 65536 }, config.ErrKMIPInvalidPort},
		{"empty server cert", func(c *config.KMIP) { c.TLS.CertPath = "" }, config.ErrInvalidTLSConfig},
		{"empty server key", func(c *config.KMIP) { c.TLS.KeyPath = "" }, config.ErrInvalidTLSConfig},
		{"empty client CA", func(c *config.KMIP) { c.TLS.CAPath = "" }, config.ErrInvalidTLSConfig},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := valid
			tt.mutate(&cfg)
			err := cfg.Validate()
			if tt.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestConfigListenAddress(t *testing.T) {
	t.Parallel()
	cfg := config.KMIP{BindAddr: "127.0.0.1", Port: 5696}
	require.Equal(t, "127.0.0.1:5696", cfg.ListenAddress())
}

func TestKMIPsValidate(t *testing.T) {
	t.Parallel()

	validKMIP := func(name string) config.KMIP {
		return config.KMIP{
			Name:     name,
			BindAddr: "0.0.0.0",
			Port:     5696,
			TLS: config.TLSServer{
				CertPath: "/etc/tls/server.pem",
				KeyPath:  "/etc/tls/server-key.pem",
				CAPath:   "/etc/tls/ca.pem",
			},
		}
	}

	// validSetup returns a RootConfig with a DEK kind "K3" and a topology
	// segment "agent-aws" whose EndKind is "K3", plus a matching KMIPs slice.
	validSetup := func() (*config.RootConfig, config.KMIPs) {
		cfg := &config.RootConfig{
			Hierarchy: spec.KeyHierarchy{
				KeySpecs: []spec.KeySpec{
					{Kind: "K0", Role: spec.KeyRoleRoot},
					{Kind: "K1", Role: spec.KeyRoleKek},
					{Kind: "K2", Role: spec.KeyRoleTek},
					{Kind: "K3", Role: spec.KeyRoleDek},
				},
			},
			Topology: spec.Topology{
				Segments: []spec.TopologySegment{
					{
						Name: "agent-aws",
						Segment: spec.HierarchySegment{
							StartKind: "K2",
							EndKind:   "K3",
						},
					},
				},
			},
		}
		kmips := config.KMIPs{validKMIP("agent-aws")}
		return cfg, kmips
	}

	tests := []struct {
		name    string
		mutate  func(*config.RootConfig, *config.KMIPs)
		wantErr error
	}{
		{
			name:    "valid single KMIP server",
			mutate:  func(_ *config.RootConfig, _ *config.KMIPs) {},
			wantErr: nil,
		},
		{
			name: "valid multiple KMIP servers",
			mutate: func(cfg *config.RootConfig, kmips *config.KMIPs) {
				cfg.Topology.Segments = append(cfg.Topology.Segments, spec.TopologySegment{
					Name: "agent-gcp",
					Segment: spec.HierarchySegment{
						StartKind: "K2",
						EndKind:   "K3",
					},
				})
				*kmips = append(*kmips, validKMIP("agent-gcp"))
			},
			wantErr: nil,
		},
		{
			name: "empty KMIPs slice is valid",
			mutate: func(_ *config.RootConfig, kmips *config.KMIPs) {
				*kmips = nil
			},
			wantErr: nil,
		},
		{
			name: "KMIP name not in topology",
			mutate: func(_ *config.RootConfig, kmips *config.KMIPs) {
				(*kmips)[0].Name = "unknown-agent"
			},
			wantErr: config.ErrKMIPInvalidConfig,
		},
		{
			name: "KMIP name matches segment but EndKind is not DEK",
			mutate: func(cfg *config.RootConfig, _ *config.KMIPs) {
				cfg.Topology.Segments[0].Segment.EndKind = "K2"
			},
			wantErr: config.ErrKMIPInvalidConfig,
		},
		{
			name: "duplicate KMIP server name",
			mutate: func(_ *config.RootConfig, kmips *config.KMIPs) {
				*kmips = append(*kmips, validKMIP("agent-aws"))
			},
			wantErr: config.ErrKMIPInvalidConfig,
		},
		{
			name: "no DEK kind in hierarchy",
			mutate: func(cfg *config.RootConfig, _ *config.KMIPs) {
				cfg.Hierarchy.KeySpecs = []spec.KeySpec{
					{Kind: "K0", Role: spec.KeyRoleRoot},
					{Kind: "K1", Role: spec.KeyRoleKek},
				}
			},
			wantErr: config.ErrKMIPInvalidConfig,
		},
		{
			name: "KMIP entry fails validation with invalid port",
			mutate: func(_ *config.RootConfig, kmips *config.KMIPs) {
				(*kmips)[0].Port = 0
			},
			wantErr: config.ErrKMIPInvalidPort,
		},
		{
			name: "KMIP entry fails validation with empty bind addr",
			mutate: func(_ *config.RootConfig, kmips *config.KMIPs) {
				(*kmips)[0].BindAddr = ""
			},
			wantErr: config.ErrKMIPEmptyBindAddr,
		},
		{
			name: "KMIP entry fails validation with empty TLS cert",
			mutate: func(_ *config.RootConfig, kmips *config.KMIPs) {
				(*kmips)[0].TLS.CertPath = ""
			},
			wantErr: config.ErrInvalidTLSConfig,
		},
		{
			name: "KMIP is nil",
			mutate: func(_ *config.RootConfig, kmips *config.KMIPs) {
				*kmips = nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// given
			cfg, kmips := validSetup()
			tt.mutate(cfg, &kmips)

			// when
			err := kmips.Validate(cfg)

			// then
			if tt.wantErr == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}

func TestKMIPsByName(t *testing.T) {
	t.Parallel()

	kmipAWS := config.KMIP{
		Name:     "agent-aws",
		BindAddr: "0.0.0.0",
		Port:     5696,
		TLS: config.TLSServer{
			CertPath: "/etc/tls/aws-server.pem",
			KeyPath:  "/etc/tls/aws-server-key.pem",
			CAPath:   "/etc/tls/aws-ca.pem",
		},
	}
	kmipGCP := config.KMIP{
		Name:     "agent-gcp",
		BindAddr: "0.0.0.0",
		Port:     5697,
		TLS: config.TLSServer{
			CertPath: "/etc/tls/gcp-server.pem",
			KeyPath:  "/etc/tls/gcp-server-key.pem",
			CAPath:   "/etc/tls/gcp-ca.pem",
		},
	}

	tests := []struct {
		name      string
		kmips     config.KMIPs
		lookup    string
		wantKMIP  config.KMIP
		wantFound bool
	}{
		{
			name:      "finds existing entry",
			kmips:     config.KMIPs{kmipAWS, kmipGCP},
			lookup:    "agent-aws",
			wantKMIP:  kmipAWS,
			wantFound: true,
		},
		{
			name:      "finds second entry",
			kmips:     config.KMIPs{kmipAWS, kmipGCP},
			lookup:    "agent-gcp",
			wantKMIP:  kmipGCP,
			wantFound: true,
		},
		{
			name:      "returns false for non-existent name",
			kmips:     config.KMIPs{kmipAWS, kmipGCP},
			lookup:    "agent-azure",
			wantKMIP:  config.KMIP{},
			wantFound: false,
		},
		{
			name:      "returns false for empty name",
			kmips:     config.KMIPs{kmipAWS},
			lookup:    "",
			wantKMIP:  config.KMIP{},
			wantFound: false,
		},
		{
			name:      "returns false on nil slice",
			kmips:     nil,
			lookup:    "agent-aws",
			wantKMIP:  config.KMIP{},
			wantFound: false,
		},
		{
			name:      "returns false on empty slice",
			kmips:     config.KMIPs{},
			lookup:    "agent-aws",
			wantKMIP:  config.KMIP{},
			wantFound: false,
		},
		{
			name:      "finds single entry",
			kmips:     config.KMIPs{kmipGCP},
			lookup:    "agent-gcp",
			wantKMIP:  kmipGCP,
			wantFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// given
			kmips := tt.kmips

			// when
			got, found := kmips.ByName(tt.lookup)

			// then
			assert.Equal(t, tt.wantFound, found)
			assert.Equal(t, tt.wantKMIP, got)
		})
	}
}
