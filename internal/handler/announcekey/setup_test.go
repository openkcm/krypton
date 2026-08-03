package announcekey_test

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	_ "github.com/lib/pq"

	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
	"github.com/openkcm/krypton/pkg/validator"
)

var pgConnStr string

func TestMain(m *testing.M) {
	cleanup, err := setupPostgres()
	if err != nil {
		os.Exit(1)
	}
	exitCode := m.Run()
	cleanup()
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
	cleanup := func() { _ = pgContainer.Terminate(ctx) }

	pgConnStr, err = pgContainer.ConnectionString(ctx, "sslmode=disable")
	return cleanup, err
}

// newTestDB provisions an isolated test database, runs migrations, and seeds
// a tenant + key. It returns the open *sql.DB and the seeded key (with the
// tenant's ID inside).
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	ctx := t.Context()

	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err)

	dbName := "test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	_, err = db.ExecContext(ctx, "CREATE DATABASE "+dbName)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	connStr := strings.Replace(pgConnStr, "/postgres?", "/"+dbName+"?", 1)
	testDB, err := sql.Open("postgres", connStr)
	require.NoError(t, err)

	require.NoError(t, storesql.Migrate(ctx, testDB))

	t.Cleanup(func() {
		testDB.Close()

		root, err := sql.Open("postgres", pgConnStr)
		if err == nil {
			_, _ = root.ExecContext(context.Background(), "DROP DATABASE "+dbName)
			root.Close()
		}
	})
	return testDB
}

func seedTenantAndKey(t *testing.T, db *sql.DB) model.Key {
	t.Helper()
	ctx := t.Context()

	tenantStore := storesql.NewTenantStore(db)
	tenant := model.NewTenant("test-tenant-"+uuid.NewString(), nil)
	tenantRes, err := tenantStore.CreateTenant(ctx, store.CreateTenantQuery{Tenant: tenant})
	require.NoError(t, err)

	keyStore := storesql.NewKeyStore(db)
	key := model.NewKey(tenantRes.Tenant.ID, "test-key-"+uuid.NewString(), "K0", nil, "agent", nil)
	require.NoError(t, keyStore.CreateKey(ctx, key))
	return key
}

// stubProcessingStateUpdater wraps a real store.Key but overrides
// UpdateKeyProcessingState to return an injected error — used to exercise
// the unhappy paths without resorting to a fully fake store.
type stubProcessingStateUpdater struct {
	store.Key

	err error
}

func (s *stubProcessingStateUpdater) UpdateKeyProcessingState(_ context.Context, _ store.UpdateKeyProcessingStateQuery) error {
	return s.err
}

// stubValidator implements validator.KeyValidator for tests.
// If err is nil, ValidateKeyAnnounce returns nil (valid). Otherwise it
// returns the configured ValidationError.
type stubValidator struct {
	err *validator.ValidationError
}

func (s *stubValidator) ValidateKeyAnnounce(_ context.Context, _ validator.AnnounceInput) *validator.ValidationError {
	return s.err
}

func (s *stubValidator) ValidateKeyActivate(_ context.Context, _ validator.ActivateInput) *validator.ValidationError {
	return s.err
}

// passingValidator returns a stubValidator that accepts every input.
func passingValidator() *stubValidator {
	return &stubValidator{}
}
