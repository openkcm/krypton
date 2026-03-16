package integration

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	_ "github.com/lib/pq"

	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

// CLI test globals
var (
	binaryPath string
	coverDir   string
)

// Tenant test globals
var (
	tenantTestDB    *sql.DB
	tenantTestStore store.Store
)

func TestMain(m *testing.M) {
	var cleanups []func()

	cliCleanup, err := setupCLI()
	if err != nil {
		os.Exit(1)
	}
	cleanups = append(cleanups, cliCleanup)

	pgCleanups, err := setupPostgres()
	if err != nil {
		runCleanups(cleanups)
		os.Exit(1)
	}
	cleanups = append(cleanups, pgCleanups...)

	exitCode := m.Run()
	runCleanups(cleanups)
	os.Exit(exitCode)
}

func setupCLI() (func(), error) {
	ctx := context.Background()

	tmpDir, err := os.MkdirTemp("", "kr-integration-test-*")
	if err != nil {
		return nil, err
	}
	cleanupFn := func() { os.RemoveAll(tmpDir) }

	binaryPath = filepath.Join(tmpDir, "kr")

	coverDir = os.Getenv("GOCOVERDIR")
	buildArgs := []string{"build", "-o", binaryPath}
	if coverDir != "" {
		buildArgs = append(buildArgs, "-cover", "-covermode=atomic")
	}
	buildArgs = append(buildArgs, "../cli")

	buildCmd := exec.CommandContext(ctx, "go", buildArgs...)
	buildCmd.Stderr = os.Stderr

	return cleanupFn, buildCmd.Run()
}

func setupPostgres() ([]func(), error) {
	ctx := context.Background()
	var cleanupFns []func()

	pgContainer, err := postgres.Run(ctx,
		"postgres:18-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second)),
	)
	if err != nil {
		return nil, err
	}
	cleanupFns = append(cleanupFns, func() { _ = pgContainer.Terminate(ctx) })

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		runCleanups(cleanupFns)
		return nil, err
	}

	tenantTestDB, err = sql.Open("postgres", connStr)
	if err != nil {
		runCleanups(cleanupFns)
		return nil, err
	}
	cleanupFns = append(cleanupFns, func() { tenantTestDB.Close() })

	tenantTestStore, err = storesql.NewPostgreSQL(ctx, tenantTestDB)
	if err != nil {
		runCleanups(cleanupFns)
		return nil, err
	}

	return cleanupFns, nil
}

func runCleanups(cleanups []func()) {
	for i := len(cleanups) - 1; i >= 0; i-- {
		cleanups[i]()
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
