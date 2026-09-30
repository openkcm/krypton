package agentclient_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/agentclient"
	"github.com/openkcm/krypton/internal/config"
)

func testConnections() config.ConnectionConfigs {
	return config.ConnectionConfigs{
		{Name: "agent-1", Address: config.Address{Type: config.AddressTypeGRPC, URL: "dns:///agent-1.internal:9443"}},
		{Name: "root", Address: config.Address{Type: config.AddressTypeGRPC, URL: "dns:///root.internal:9443"}},
	}
}

func TestRegistry_ResolvesConfiguredAgent(t *testing.T) {
	reg, err := agentclient.New(testConnections(), nil)
	require.NoError(t, err)

	// grpc.NewClient is lazy, so a configured agent resolves without dialing.
	cli, err := reg.Client("agent-1")
	require.NoError(t, err)
	assert.NotNil(t, cli)
}

func TestRegistry_CachesClientPerAgent(t *testing.T) {
	reg, err := agentclient.New(testConnections(), nil)
	require.NoError(t, err)

	first, err := reg.Client("agent-1")
	require.NoError(t, err)
	second, err := reg.Client("agent-1")
	require.NoError(t, err)

	assert.Same(t, first, second, "the same agent must reuse one cached client")
}

func TestRegistry_UnknownAgent(t *testing.T) {
	reg, err := agentclient.New(testConnections(), nil)
	require.NoError(t, err)

	_, err = reg.Client("ghost")
	require.Error(t, err)
	assert.ErrorIs(t, err, agentclient.ErrUnknownAgent, "want ErrUnknownAgent, got %v", err)
}
