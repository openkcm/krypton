package integration

import (
	"context"
	"database/sql"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"google.golang.org/grpc"

	_ "github.com/lib/pq"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

// CLI test globals
var (
	binaryPath string
	coverDir   string
)

// Postgres test globals
var (
	pgConnStr string
)

func TestMain(m *testing.M) {
	var cleanups []func()

	cliCleanups, err := setupCLI()
	cleanups = append(cleanups, cliCleanups...)
	if err != nil {
		runCleanups(cleanups)
		os.Exit(1)
	}

	pgCleanups, err := setupPostgres()
	cleanups = append(cleanups, pgCleanups...)
	if err != nil {
		runCleanups(cleanups)
		os.Exit(1)
	}

	exitCode := m.Run()
	runCleanups(cleanups)
	os.Exit(exitCode)
}

func setupCLI() ([]func(), error) {
	ctx := context.Background()
	var cleanupFns []func()

	tmpDir, err := os.MkdirTemp("", "kr-integration-test-*")
	if err != nil {
		return nil, err
	}
	cleanupFn := func() { os.RemoveAll(tmpDir) }
	cleanupFns = append(cleanupFns, cleanupFn)

	binaryPath = filepath.Join(tmpDir, "kr")

	coverDir = os.Getenv("CLI_GOCOVERDIR")
	buildArgs := []string{"build", "-o", binaryPath}
	if coverDir != "" {
		buildArgs = append(buildArgs, "-cover", "-covermode=atomic")
	}
	buildArgs = append(buildArgs, "../cli")

	buildCmd := exec.CommandContext(ctx, "go", buildArgs...)
	buildCmd.Stderr = os.Stderr

	return cleanupFns, buildCmd.Run()
}

func setupPostgres() ([]func(), error) {
	ctx := context.Background()
	var cleanupFns []func()

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
	cleanupFns = append(cleanupFns, func() { _ = pgContainer.Terminate(ctx) })

	pgConnStr, err = pgContainer.ConnectionString(ctx, "sslmode=disable")

	return cleanupFns, err
}

func runCleanups(cleanups []func()) {
	for _, v := range slices.Backward(cleanups) {
		v()
	}
}

// newCLICommand creates a new exec.Command with the given arguments and sets up
// the environment variables including HOME and GOCOVERDIR (if coverage is enabled).
func newCLICommand(ctx context.Context, homeDir string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, binaryPath, args...)
	cmd.Env = []string{"HOME=" + homeDir}
	if coverDir != "" {
		cmd.Env = append(cmd.Env, "GOCOVERDIR="+coverDir)
	}
	return cmd
}

// newTenantStore creates a tenant store
func newTenantStore(t *testing.T, db *sql.DB) store.Tenant {
	t.Helper()
	if db == nil {
		db, _ = createDatabase(t)
	}
	return storesql.NewTenantStore(db)
}

// newKeyStore creates a key store.
func newKeyStore(t *testing.T, db *sql.DB) store.Key {
	t.Helper()
	if db == nil {
		db, _ = createDatabase(t)
	}
	return storesql.NewKeyStore(db)
}

// newKeyVersionStore creates a keyversion store.
func newKeyVersionStore(t *testing.T, db *sql.DB) store.KeyVersion {
	t.Helper()
	if db == nil {
		db, _ = createDatabase(t)
	}
	return storesql.NewKeyVersionStore(db)
}

// createDatabase creates a new PostgreSQL database for testing and returns a connection to it.
func createDatabase(t *testing.T) (*sql.DB, string) {
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

	// migrate
	require.NoError(t, storesql.Migrate(ctx, sqlDB))

	return sqlDB, pgConStr
}

// RegisterFunc is a function that registers services to a gRPC server.
type RegisterFunc func(*grpc.Server)

// startGRPCServer starts a gRPC server and returns the server address.
// The register function is called to register services to the server.
// The server is automatically stopped when the test completes.
func startGRPCServer(t *testing.T, registerFns ...RegisterFunc) string {
	t.Helper()

	lis, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	srv := grpc.NewServer()
	for _, registerFn := range registerFns {
		registerFn(srv)
	}

	go func() {
		if err := srv.Serve(lis); err != nil {
			t.Logf("server stopped: %v", err)
		}
	}()

	t.Cleanup(func() {
		srv.GracefulStop()
	})

	return lis.Addr().String()
}

// defaultTestHierarchy mirrors the K0(root) → K1(kek) → K2(tek) → K3(dek)
// hierarchy used by the existing fixture builders below.
func defaultTestHierarchy() spec.KeyHierarchy {
	return spec.KeyHierarchy{
		Name: "test-hierarchy",
		KeySpecs: []spec.KeySpec{
			{Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: cryptor.KeyAlgorithmAES256},
			{Kind: "K1", Role: spec.KeyRoleKek, Algorithm: cryptor.KeyAlgorithmAES256},
			{Kind: "K2", Role: spec.KeyRoleTek, Algorithm: cryptor.KeyAlgorithmAES256},
			{Kind: "K3", Role: spec.KeyRoleDek, Algorithm: cryptor.KeyAlgorithmAES256},
		},
	}
}

type noopJobPreparer struct{}

func (*noopJobPreparer) PrepareJob(_ context.Context, job orbital.Job) (orbital.Job, error) {
	if job.ID == uuid.Nil {
		job.ID = uuid.Must(uuid.NewUUID())
	}
	return job, nil
}
