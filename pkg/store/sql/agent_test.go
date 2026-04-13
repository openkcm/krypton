package sql_test

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	_ "github.com/lib/pq"

	"github.com/openkcm/krypton/internal/clock"
	"github.com/openkcm/krypton/internal/core"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
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

func TestRegister(t *testing.T) {
	// given
	ctx := t.Context()
	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err)

	t.Cleanup(func() {
		db.Close()
	})

	subj, err := storesql.NewAgentStore(ctx, db)
	require.NoError(t, err)

	t.Run("should insert new agent registration", func(t *testing.T) {
		// given
		registration := core.AgentRegistration{
			Name:       "test-agent",
			InstanceID: uuid.New().String(),
			Status:     core.AgentRegistrationStatusHealthy,
		}

		// when
		regResult, err := subj.Register(ctx, store.RegisterAgentQuery{
			Registration: registration,
		})

		// then
		assert.NoError(t, err)

		assert.Equal(t, registration.Name, regResult.Registration.Name)
		assert.Equal(t, registration.InstanceID, regResult.Registration.InstanceID)
		assert.Equal(t, registration.Status, regResult.Registration.Status)
		assert.Zero(t, regResult.Registration.LastHeartbeat)
		assert.NotZero(t, regResult.Registration.CreatedAt)
		assert.NotZero(t, regResult.Registration.UpdatedAt)
	})

	t.Run("should update existing agent registration", func(t *testing.T) {
		// given
		registration := core.AgentRegistration{
			Name:       "test-agent",
			InstanceID: uuid.New().String(),
			Status:     core.AgentRegistrationStatusHealthy,
		}

		regResult1, err := subj.Register(ctx, store.RegisterAgentQuery{
			Registration: registration,
		})
		require.NoError(t, err)

		registration.Status = core.AgentRegistrationStatusUnhealthy
		registration.LastHeartbeat = clock.Now()

		// when
		regResult2, err := subj.Register(ctx, store.RegisterAgentQuery{
			Registration: registration,
		})

		// then
		assert.NoError(t, err)

		assert.Equal(t, registration.Name, regResult2.Registration.Name)
		assert.Equal(t, registration.InstanceID, regResult2.Registration.InstanceID)
		assert.Equal(t, registration.Status, regResult2.Registration.Status)
		assert.Equal(t, registration.LastHeartbeat, regResult2.Registration.LastHeartbeat)
		assert.Equal(t, regResult1.Registration.CreatedAt, regResult2.Registration.CreatedAt)

		assert.NotZero(t, regResult2.Registration.UpdatedAt)
		assert.NotEqual(t, regResult1.Registration.UpdatedAt, regResult2.Registration.UpdatedAt)
		assert.Greater(t, regResult2.Registration.UpdatedAt, regResult1.Registration.UpdatedAt)
	})
}

func TestGet(t *testing.T) {
	ctx := t.Context()

	t.Run("should get existing agent registration", func(t *testing.T) {
		// given
		db, err := sql.Open("postgres", pgConnStr)
		require.NoError(t, err)

		t.Cleanup(func() {
			db.Close()
		})

		subj, err := storesql.NewAgentStore(ctx, db)
		require.NoError(t, err)

		registration := core.AgentRegistration{
			Name:       "test-agent",
			InstanceID: uuid.New().String(),
			Status:     core.AgentRegistrationStatusHealthy,
		}

		regResult, err := subj.Register(ctx, store.RegisterAgentQuery{
			Registration: registration,
		})
		require.NoError(t, err)

		// when
		getResult, err := subj.Get(ctx, store.GetAgentQuery{
			Name:       registration.Name,
			InstanceID: registration.InstanceID,
		})

		// then
		assert.NoError(t, err)

		assert.Equal(t, regResult.Registration.Name, getResult.Registration.Name)
		assert.Equal(t, regResult.Registration.InstanceID, getResult.Registration.InstanceID)
		assert.Equal(t, regResult.Registration.Status, getResult.Registration.Status)
		assert.Equal(t, regResult.Registration.LastHeartbeat, getResult.Registration.LastHeartbeat)
		assert.Equal(t, regResult.Registration.CreatedAt, getResult.Registration.CreatedAt)
		assert.Equal(t, regResult.Registration.UpdatedAt, getResult.Registration.UpdatedAt)
	})

	t.Run("should return error if agent registration not found", func(t *testing.T) {
		// given
		db, err := sql.Open("postgres", pgConnStr)
		require.NoError(t, err)

		t.Cleanup(func() {
			db.Close()
		})

		subj, err := storesql.NewAgentStore(ctx, db)
		require.NoError(t, err)

		// when
		getResult, err := subj.Get(ctx, store.GetAgentQuery{
			Name:       "non-existent-agent",
			InstanceID: uuid.New().String(),
		})

		// then
		assert.ErrorIs(t, err, store.ErrAgentRegistrationNotFound)
		assert.Zero(t, getResult.Registration)
	})
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
