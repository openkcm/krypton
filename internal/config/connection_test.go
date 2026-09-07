package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/spec"
)

func TestConnectionConfigs_Validate(t *testing.T) {
	// given
	tests := []struct {
		name    string
		subj    config.ConnectionConfigs
		rc      *config.RootConfig
		wantErr error
	}{
		{
			name: "valid ConnectionConfigs",
			subj: config.ConnectionConfigs{
				{
					Name: "root",
					Address: config.Address{
						Type: config.AddressTypeGRPC,
						URL:  "localhost:5050",
					},
				},
				{
					Name: "agent-1",
					Address: config.Address{
						Type: config.AddressTypeGRPC,
						URL:  "localhost:5051",
					},
				},
			},
			rc: &config.RootConfig{
				Name: "root",
				Topology: spec.Topology{
					Segments: []spec.TopologySegment{
						{
							Name: "agent-1",
						},
					},
				},
			},
		},
		{
			name: "valid ConnectionConfigs without agent",
			subj: config.ConnectionConfigs{
				{
					Name: "root",
					Address: config.Address{
						Type: config.AddressTypeGRPC,
						URL:  "localhost:5050",
					},
				},
			},
			rc: &config.RootConfig{
				Name: "root",
				Topology: spec.Topology{
					Segments: []spec.TopologySegment{},
				},
			},
		},
		{
			name: "empty name",
			subj: config.ConnectionConfigs{
				{
					Name: "root",
					Address: config.Address{
						Type: config.AddressTypeGRPC,
						URL:  "localhost:5050",
					},
				},
				{
					Name: "",
					Address: config.Address{
						Type: config.AddressTypeGRPC,
						URL:  "localhost:5051",
					},
				},
			},
			rc: &config.RootConfig{
				Name: "root",
				Topology: spec.Topology{
					Segments: []spec.TopologySegment{
						{
							Name: "agent-1",
						},
					},
				},
			},
			wantErr: config.ErrInvalidConnectionConfig,
		},
		{
			name: "missing agent ConnectionConfig",
			subj: config.ConnectionConfigs{},
			rc: &config.RootConfig{
				Name: "root",
				Topology: spec.Topology{
					Segments: []spec.TopologySegment{
						{
							Name: "agent-1",
						},
					},
				},
			},
			wantErr: config.ErrInvalidConnectionConfig,
		},
		{
			name: "duplicate names",
			subj: config.ConnectionConfigs{
				{
					Name: "agent-1",
					Address: config.Address{
						Type: config.AddressTypeGRPC,
						URL:  "localhost:5051",
					},
				},
				{
					Name: "agent-1",
					Address: config.Address{
						Type: config.AddressTypeGRPC,
						URL:  "localhost:5051",
					},
				},
			},
			rc: &config.RootConfig{
				Name: "root",
				Topology: spec.Topology{
					Segments: []spec.TopologySegment{
						{
							Name: "agent-1",
						},
					},
				},
			},
			wantErr: config.ErrInvalidConnectionConfig,
		},
		{
			name: "invalid address type",
			subj: config.ConnectionConfigs{
				{
					Name: "agent-1",
					Address: config.Address{
						Type: "invalid-type",
						URL:  "localhost:5051",
					},
				},
			},
			rc: &config.RootConfig{
				Name: "root",
				Topology: spec.Topology{
					Segments: []spec.TopologySegment{
						{
							Name: "agent-1",
						},
					},
				},
			},
			wantErr: config.ErrInvalidConnectionConfig,
		},
		{
			name:    "nil root config",
			subj:    config.ConnectionConfigs{},
			rc:      nil,
			wantErr: config.ErrInvalidConnectionConfig,
		},
		{
			name: "nil topology segments",
			subj: config.ConnectionConfigs{
				{
					Name: "root",
					Address: config.Address{
						Type: config.AddressTypeGRPC,
						URL:  "localhost:5050",
					},
				},
			},
			rc: &config.RootConfig{
				Name: "root",
				Topology: spec.Topology{
					Segments: nil,
				},
			},
			wantErr: nil,
		},
		{
			name: "empty address URL",
			subj: config.ConnectionConfigs{
				{
					Name: "root",
					Address: config.Address{
						Type: config.AddressTypeGRPC,
						URL:  "",
					},
				},
				{
					Name: "agent-1",
					Address: config.Address{
						Type: config.AddressTypeGRPC,
						URL:  "localhost:5051",
					},
				},
			},
			rc: &config.RootConfig{
				Name: "root",
				Topology: spec.Topology{
					Segments: []spec.TopologySegment{
						{
							Name: "agent-1",
						},
					},
				},
			},
			wantErr: config.ErrInvalidConnectionConfig,
		},
		{
			name: "nil ConnectionConfigs",
			subj: nil,
			rc: &config.RootConfig{
				Name: "root",
				Topology: spec.Topology{
					Segments: []spec.TopologySegment{
						{
							Name: "agent-1",
						},
					},
				},
			},
			wantErr: config.ErrInvalidConnectionConfig,
		},
		{
			name: "orphaned connection config without matching segment",
			subj: config.ConnectionConfigs{
				{
					Name: "root",
					Address: config.Address{
						Type: config.AddressTypeGRPC,
						URL:  "localhost:5050",
					},
				},
				{
					Name: "agent-1",
					Address: config.Address{
						Type: config.AddressTypeGRPC,
						URL:  "localhost:5051",
					},
				},
				{
					Name: "agent-orphan",
					Address: config.Address{
						Type: config.AddressTypeGRPC,
						URL:  "localhost:5052",
					},
				},
			},
			rc: &config.RootConfig{
				Name: "root",
				Topology: spec.Topology{
					Segments: []spec.TopologySegment{
						{
							Name: "agent-1",
						},
					},
				},
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			gotErr := tt.subj.Validate(tt.rc)

			// then
			assert.ErrorIs(t, gotErr, tt.wantErr)
		})
	}
}

func TestConnectionConfigs_ByNames(t *testing.T) {
	// given
	tests := []struct {
		name       string
		subj       config.ConnectionConfigs
		agentNames []string
		wantRes    config.ConnectionConfigs
		wantErr    error
	}{
		{
			name: "returns correct ConnectionConfig for agent",
			subj: config.ConnectionConfigs{
				{
					Name: "agent-name",
					Address: config.Address{
						Type: config.AddressTypeGRPC,
						URL:  "something",
					},
				},
			},
			agentNames: []string{"agent-name"},
			wantRes: config.ConnectionConfigs{
				{
					Name: "agent-name",
					Address: config.Address{
						Type: config.AddressTypeGRPC,
						URL:  "something",
					},
				},
			},
			wantErr: nil,
		},
		{
			name: "returns correct ConnectionConfig for multiple configs",
			subj: config.ConnectionConfigs{
				{
					Name: "agent-name-1",
					Address: config.Address{
						Type: config.AddressTypeGRPC,
						URL:  "something",
					},
				},
				{
					Name: "agent-name",
					Address: config.Address{
						Type: config.AddressTypeGRPC,
						URL:  "something",
					},
				},
				{
					Name: "agent-name-2",
					Address: config.Address{
						Type: config.AddressTypeGRPC,
						URL:  "something",
					},
				},
			},
			agentNames: []string{"agent-name", "agent-name-1"},
			wantRes: config.ConnectionConfigs{
				{
					Name: "agent-name-1",
					Address: config.Address{
						Type: config.AddressTypeGRPC,
						URL:  "something",
					},
				},
				{
					Name: "agent-name",
					Address: config.Address{
						Type: config.AddressTypeGRPC,
						URL:  "something",
					},
				},
			},
			wantErr: nil,
		},
		{
			name: "returns error when multiple agent names provided and one is missing",
			subj: config.ConnectionConfigs{
				{
					Name: "agent-name",
					Address: config.Address{
						Type: config.AddressTypeGRPC,
						URL:  "something",
					},
				},
			},
			agentNames: []string{"agent-name", "unknown-agent"},
			wantRes:    nil,
			wantErr:    config.ErrNoConnectionConfig,
		},
		{
			name: "returns error when agent not in ConnectionConfigs",
			subj: config.ConnectionConfigs{
				{
					Name: "agent-name",
					Address: config.Address{
						Type: config.AddressTypeGRPC,
						URL:  "something",
					},
				},
			},
			agentNames: []string{"unknown-agent"},
			wantRes:    nil,
			wantErr:    config.ErrNoConnectionConfig,
		},
		{
			name:       "nil ConnectionConfigs",
			subj:       nil,
			agentNames: []string{"unknown-agent"},
			wantRes:    nil,
			wantErr:    config.ErrNoConnectionConfig,
		},
		{
			name:       "empty ConnectionConfigs",
			subj:       config.ConnectionConfigs{},
			agentNames: []string{"unknown-agent"},
			wantRes:    nil,
			wantErr:    config.ErrNoConnectionConfig,
		},
		{
			name:       "nil input agent names",
			subj:       config.ConnectionConfigs{},
			agentNames: nil,
			wantRes:    nil,
			wantErr:    config.ErrNoConnectionConfig,
		},
		{
			name: "duplicate agent names in input",
			subj: config.ConnectionConfigs{
				{
					Name: "agent-name",
					Address: config.Address{
						Type: config.AddressTypeGRPC,
						URL:  "something",
					},
				},
				{
					Name: "agent-name-1",
					Address: config.Address{
						Type: config.AddressTypeGRPC,
						URL:  "something",
					},
				},
			},
			agentNames: []string{"agent-name", "agent-name"},
			wantRes: config.ConnectionConfigs{
				{
					Name: "agent-name",
					Address: config.Address{
						Type: config.AddressTypeGRPC,
						URL:  "something",
					},
				},
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			res, err := tt.subj.ByNames(tt.agentNames...)

			// then
			assert.ErrorIs(t, err, tt.wantErr)
			assert.ElementsMatch(t, tt.wantRes, res)
		})
	}
}
