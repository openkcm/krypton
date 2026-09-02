package agents_test

import (
	"context"
	"database/sql"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	_ "github.com/lib/pq"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/cryptor/aes256gcm"
	"github.com/openkcm/krypton/internal/cryptor/cryptorprovider"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents"
	"github.com/openkcm/krypton/pkg/store"
)

var pgConnStr string

func TestMain(m *testing.M) {
	pgCleanup, err := setupPostgres()
	if err != nil {
		os.Exit(1)
	}

	exitCode := m.Run()
	pgCleanup()
	os.Exit(exitCode)
}

func setupPostgres() (func(), error) {
	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx,
		"postgres:18-alpine",
		postgres.WithDatabase("postgres"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		return nil, err
	}
	cleanUp := func() { _ = pgContainer.Terminate(ctx) }

	pgConnStr, err = pgContainer.ConnectionString(ctx, "sslmode=disable")

	return cleanUp, err
}

func setupServerAndClient(t *testing.T, store store.Agent, cfg config.RootConfig) agents.ServiceClient {
	t.Helper()

	srv := grpc.NewServer()
	agentSvc := agents.NewAgentService(store, cfg)
	agents.RegisterServiceServer(srv, agentSvc)

	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)
	go func() {
		if err := srv.Serve(lis); err != nil {
			// Serve returns error on graceful stop; ignore it.
			assert.Fail(t, "agent service server error", err)
		}
	}()
	dialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}

	t.Cleanup(func() {
		srv.GracefulStop()
	})

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		conn.Close()
	})

	client := agents.NewServiceClient(conn)
	return client
}

func createDatabase(t *testing.T) *sql.DB {
	t.Helper()
	ctx := t.Context()

	db, err := sql.Open("postgres", pgConnStr)
	if err != nil {
		assert.FailNowf(t, "failed to connect to PostgreSQL", "error: %v", err)
	}

	dbName := "test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	_, err = db.ExecContext(ctx, "CREATE DATABASE "+dbName)
	if err != nil {
		db.Close()
		assert.FailNowf(t, "failed to create test database", "error: %v", err)
	}
	db.Close()

	pgConStr := strings.Replace(pgConnStr, "/postgres?", "/"+dbName+"?", 1)
	sqlDB, err := sql.Open("postgres", pgConStr)
	if err != nil {
		assert.FailNowf(t, "failed to connect to test database", "error: %v", err)
	}

	t.Cleanup(func() {
		sqlDB.Close()

		db, err := sql.Open("postgres", pgConnStr)
		if err == nil {
			_, _ = db.ExecContext(context.Background(), "DROP DATABASE "+dbName)
			db.Close()
		}
	})
	return sqlDB
}

// baseRootConfig builds a RootConfig with the shared hierarchy, topology, and
// the identity entries common to every test variant. Callers append extra
// identities via extraIdentities.
func baseRootConfig(agentName string, extraIdentities ...config.IdentityConfig) config.RootConfig {
	identities := config.IdentityConfigs{
		{
			Name: agentName,
			URI:  "kryptonid://acme-corp/service/agent-aws",
		},
	}
	identities = append(identities, extraIdentities...)
	identities = append(identities,
		config.IdentityConfig{
			Name: "child-agent-1",
			URI:  "kryptonid://acme-corp/service/child-agent-1",
		},
		config.IdentityConfig{
			Name: "child-agent-2",
			URI:  "kryptonid://acme-corp/service/child-agent-2",
		},
		config.IdentityConfig{
			Name: "child-agent-3",
			URI:  "kryptonid://acme-corp/service/child-agent-3",
		},
	)

	return config.RootConfig{
		Name: "root",
		Hierarchy: spec.KeyHierarchy{
			Name: "root-hierarchy",
			KeySpecs: []spec.KeySpec{
				{Kind: "K0"},
				{Kind: "K1"},
				{Kind: "K2"},
				{Kind: "K3"},
			},
		},
		Auth: &config.RootAuthConfig{
			IdentityConfigs: identities,
		},
		Topology: spec.Topology{
			Segments: []spec.TopologySegment{
				{
					Name: agentName,
					KeyBindings: map[string]spec.KeyBinding{
						"K1": {
							CryptorSpec: validCryptor(),
						},
					},
					SelectorLabels: spec.SelectorLabels{"region": "us-west"},
				},
				{
					Name: "child-agent-1",
					KeyBindings: map[string]spec.KeyBinding{
						"K2": {
							ParentKeyProvider: &spec.ParentKeyProviderRef{
								AgentName: agentName,
							},
						},
					},
				},
				{
					Name: "child-agent-2",
					KeyBindings: map[string]spec.KeyBinding{
						"K2": {
							ParentKeyProvider: &spec.ParentKeyProviderRef{
								AgentName: agentName,
							},
						},
					},
				},
				{
					Name: "child-agent-3",
					KeyBindings: map[string]spec.KeyBinding{
						"K3": {},
					},
				},
			},
		},
	}
}

// rootConfigMissingRootIdentity returns a RootConfig that is missing the
// root's own identity in Auth.IdentityConfigs, causing AgentIdentities to fail.
func rootConfigMissingRootIdentity(agentName string) config.RootConfig {
	return baseRootConfig(agentName)
}

func rootConfigWithNilAuth(agentName string) config.RootConfig {
	cfg := baseRootConfig(agentName)
	cfg.Auth = nil
	return cfg
}

func validRootConfig(agentName string) config.RootConfig {
	return baseRootConfig(agentName, config.IdentityConfig{
		Name: "root",
		URI:  "kryptonid://acme-corp/service/root",
	})
}

func assertErrorDetails(t *testing.T, expCode proto.Code, actErr error) {
	t.Helper()

	st := status.Convert(actErr)
	dts := st.Details()
	require.Len(t, dts, 1, "expected 1 error detail")

	dt, ok := dts[0].(*proto.ErrorDetails)
	require.True(t, ok, "expected error details of type proto.ErrorDetails")
	assert.Equal(t, expCode, dt.GetCode())
}

func validCryptor() *cryptorprovider.Spec {
	return &cryptorprovider.Spec{
		Name:   "test-crypto",
		Type:   aes256gcm.TypeAES256GCM,
		Config: &aes256gcm.Config{},
	}
}
