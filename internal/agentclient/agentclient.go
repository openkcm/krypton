// Package agentclient provides root with mTLS gRPC clients to the agent-side
// key service, keyed by agent name. Root reaches agents over these clients to
// mirror keys (UpsertKey) and activate agent-managed keys (ActivateKey) as part
// of cascading key activation.
//
// Addresses are resolved from the root config's connections
// ([config.ConnectionConfigs]), which are validated to cover every topology
// segment plus root. The mTLS dial mirrors keyprocessor.NewRPCManager.
package agentclient

import (
	"errors"
	"fmt"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/openkcm/krypton/internal/config"
	keys "github.com/openkcm/krypton/pkg/api/v1/proto/agents/keys"
)

// ErrUnknownAgent is returned when no connection is configured for the
// requested agent name.
var ErrUnknownAgent = errors.New("no connection configured for agent")

// Provider hands out a key-service client for a named agent.
type Provider interface {
	Client(agentName string) (keys.KeyServiceClient, error)
}

// Registry is a [Provider] backed by the root connection config. Both the mTLS
// dial options and the per-agent clients are built lazily and cached on first
// use: grpc.NewClient does not dial until first use, and deferring the client
// TLS build means a startup that never reaches an agent (e.g. a root that only
// serves registration) does not require valid client credentials.
type Registry struct {
	connections config.ConnectionConfigs
	auth        config.AuthConfig

	mu       sync.Mutex
	dialOpts []grpc.DialOption
	optsErr  error
	optsDone bool
	clients  map[string]keys.KeyServiceClient
}

var _ Provider = (*Registry)(nil)

// New builds a Registry. When auth is non-nil the clients dial over mTLS built
// from the client credentials in auth; otherwise they dial insecurely (dev).
// The client credentials are not read until the first [Registry.Client] call.
func New(connections config.ConnectionConfigs, auth config.AuthConfig) (*Registry, error) {
	return &Registry{
		connections: connections,
		auth:        auth,
		clients:     make(map[string]keys.KeyServiceClient),
	}, nil
}

// dialOptions builds (once, cached) the dial options shared by all clients.
// Caller must hold r.mu.
func (r *Registry) dialOptions() ([]grpc.DialOption, error) {
	if r.optsDone {
		return r.dialOpts, r.optsErr
	}
	r.optsDone = true

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	if r.auth != nil {
		mtlsCfg, err := config.GetAuthConfig(r.auth)
		if err != nil {
			r.optsErr = err
			return nil, err
		}
		tlsCfg, err := mtlsCfg.Client.BuildTLSConfig()
		if err != nil {
			r.optsErr = err
			return nil, err
		}
		opts[0] = grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg))
	}

	r.dialOpts = opts
	return opts, nil
}

// Client returns the key-service client for agentName, building and caching it
// on first use. It returns ErrUnknownAgent if no connection is configured.
func (r *Registry) Client(agentName string) (keys.KeyServiceClient, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if cli, ok := r.clients[agentName]; ok {
		return cli, nil
	}

	conns, err := r.connections.ByNames(agentName)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrUnknownAgent, agentName, err)
	}

	dialOpts, err := r.dialOptions()
	if err != nil {
		return nil, err
	}

	conn, err := grpc.NewClient(conns[0].Address.URL, dialOpts...)
	if err != nil {
		return nil, err
	}

	cli := keys.NewKeyServiceClient(conn)
	r.clients[agentName] = cli
	return cli, nil
}
