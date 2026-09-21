package grpcconn_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/grpcconn"
)

func insecureOpts() []grpc.DialOption {
	return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
}

func newConfig(name, url string) config.ConnectionConfig {
	return config.ConnectionConfig{
		Name: name,
		Address: config.Address{
			Type: config.AddressTypeGRPC,
			URL:  url,
		},
	}
}

func TestNewRegistry_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfgs    []config.ConnectionConfig
		wantErr error
	}{
		{
			name: "duplicate name",
			cfgs: []config.ConnectionConfig{
				newConfig("dup", "passthrough:///127.0.0.1:1"),
				newConfig("dup", "passthrough:///127.0.0.1:2"),
			},
			wantErr: grpcconn.ErrDuplicateName,
		},
		{
			name: "unsupported address type",
			cfgs: []config.ConnectionConfig{
				{Name: "http", Address: config.Address{Type: "http", URL: "http://x"}},
			},
			wantErr: grpcconn.ErrUnsupportedAddressType,
		},
		{
			name: "unsupported type after valid entry rolls back",
			cfgs: []config.ConnectionConfig{
				newConfig("ok", "passthrough:///127.0.0.1:1"),
				{Name: "bad", Address: config.Address{Type: "http", URL: "http://x"}},
			},
			wantErr: grpcconn.ErrUnsupportedAddressType,
		},
		{
			name: "empty address type",
			cfgs: []config.ConnectionConfig{
				{Name: "empty-type", Address: config.Address{Type: "", URL: "passthrough:///x"}},
			},
			wantErr: grpcconn.ErrUnsupportedAddressType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			reg, err := grpcconn.NewRegistry(tt.cfgs, insecureOpts()...)
			require.Error(t, err)
			assert.ErrorIs(t, err, tt.wantErr)
			assert.Nil(t, reg)
		})
	}
}

func TestNewRegistry_Empty(t *testing.T) {
	t.Parallel()

	reg, err := grpcconn.NewRegistry(nil, insecureOpts()...)
	require.NoError(t, err)

	conn, ok := reg.Get("anything")
	assert.False(t, ok)
	assert.Nil(t, conn)

	assert.NoError(t, reg.Close())
}

func TestGet(t *testing.T) {
	t.Parallel()

	cfgs := []config.ConnectionConfig{
		newConfig("root", "passthrough:///127.0.0.1:1"),
		newConfig("segment-a", "passthrough:///127.0.0.1:2"),
	}
	reg, err := grpcconn.NewRegistry(cfgs, insecureOpts()...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reg.Close() })

	tests := []struct {
		name   string
		lookup string
		wantOK bool
	}{
		{"known root", "root", true},
		{"known segment", "segment-a", true},
		{"unknown name", "nope", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			conn, ok := reg.Get(tt.lookup)
			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.NotNil(t, conn)
			} else {
				assert.Nil(t, conn)
			}
		})
	}

	t.Run("returns same conn on repeated lookups", func(t *testing.T) {
		t.Parallel()
		a, okA := reg.Get("root")
		b, okB := reg.Get("root")
		require.True(t, okA)
		require.True(t, okB)
		assert.Same(t, a, b)
	})
}

func TestClose_ShutsDownAllConns(t *testing.T) {
	t.Parallel()

	cfgs := []config.ConnectionConfig{
		newConfig("a", "passthrough:///127.0.0.1:1"),
		newConfig("b", "passthrough:///127.0.0.1:2"),
	}
	reg, err := grpcconn.NewRegistry(cfgs, insecureOpts()...)
	require.NoError(t, err)

	connA, okA := reg.Get("a")
	require.True(t, okA)
	connB, okB := reg.Get("b")
	require.True(t, okB)

	require.NoError(t, reg.Close())

	assert.Equal(t, connectivity.Shutdown, connA.GetState())
	assert.Equal(t, connectivity.Shutdown, connB.GetState())

	conn, ok := reg.Get("a")
	assert.False(t, ok)
	assert.Nil(t, conn)
}

func TestClose_Idempotent(t *testing.T) {
	t.Parallel()

	cfgs := []config.ConnectionConfig{
		newConfig("root", "passthrough:///127.0.0.1:1"),
	}
	reg, err := grpcconn.NewRegistry(cfgs, insecureOpts()...)
	require.NoError(t, err)

	assert.NoError(t, reg.Close())
	assert.NoError(t, reg.Close())
}
