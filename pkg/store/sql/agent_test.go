package sql_test

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"testing/synctest"
	"time"

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

func TestUpdateRegistrationStatus(t *testing.T) {
	// given
	ctx := t.Context()

	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err)

	t.Cleanup(func() {
		db.Close()
	})

	subj, err := storesql.NewAgentStore(ctx, db)
	require.NoError(t, err)

	t.Run("UpdateRegistrationStatus", func(t *testing.T) {
		tests := []struct {
			name                string
			sleepDuration       time.Duration
			expectStatusChanged bool
		}{
			{
				name:                "should update status when heartbeat threshold exceeded",
				sleepDuration:       21 * time.Second, // threshold + 1s
				expectStatusChanged: true,
			},
			{
				name:          "should not update status when heartbeat threshold not exceeded",
				sleepDuration: 10 * time.Second, // threshold - 10s

				expectStatusChanged: false,
			},
		}
		heartbeatThreshold := 15 * time.Second

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					// given
					registration := core.AgentRegistration{
						Name:          "test-agent",
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now(),
					}

					prevResult, err := subj.Register(ctx, store.RegisterAgentQuery{
						Registration: registration,
					})

					require.NoError(t, err)

					time.Sleep(tt.sleepDuration)
					synctest.Wait()

					updateQuery := store.UpdateRegistrationStatusQuery{
						Name:       registration.Name,
						InstanceID: registration.InstanceID,
						FromStatus: []core.AgentRegistrationStatus{
							core.AgentRegistrationStatusHealthy,
						},
						ToStatus:           core.AgentRegistrationStatusUnhealthy,
						HeartbeatThreshold: heartbeatThreshold,
					}

					// when
					err = subj.UpdateRegistrationStatus(ctx, updateQuery)

					// then
					assert.NoError(t, err)

					getResult, err := subj.Get(ctx, store.GetAgentQuery{
						Name:       registration.Name,
						InstanceID: registration.InstanceID,
					})
					require.NoError(t, err)

					assert.Equal(t, prevResult.Registration.Name, getResult.Registration.Name)
					assert.Equal(t, prevResult.Registration.InstanceID, getResult.Registration.InstanceID)
					assert.Equal(t, prevResult.Registration.LastHeartbeat, getResult.Registration.LastHeartbeat)
					assert.Equal(t, prevResult.Registration.CreatedAt, getResult.Registration.CreatedAt)
					if tt.expectStatusChanged {
						assert.Equal(t, updateQuery.ToStatus, getResult.Registration.Status)
						assert.NotEqual(t, prevResult.Registration.UpdatedAt, getResult.Registration.UpdatedAt)
						assert.Greater(t, getResult.Registration.UpdatedAt, prevResult.Registration.UpdatedAt)
					} else {
						assert.Equal(t, prevResult.Registration.Status, getResult.Registration.Status)
						assert.Equal(t, prevResult.Registration.UpdatedAt, getResult.Registration.UpdatedAt)
					}
				})
			})
		}
	})

	t.Run("should deregister without a LastHeartbeat threshold", func(t *testing.T) {
		tests := []struct {
			name       string
			fromStatus core.AgentRegistrationStatus
		}{
			{
				name:       "from healthy",
				fromStatus: core.AgentRegistrationStatusHealthy,
			},
			{
				name:       "from unhealthy",
				fromStatus: core.AgentRegistrationStatusUnhealthy,
			},
			{
				name:       "from registered",
				fromStatus: core.AgentRegistrationStatusRegistered,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				// given
				registration := core.AgentRegistration{
					Name:          "test-agent",
					InstanceID:    uuid.New().String(),
					Status:        tt.fromStatus,
					LastHeartbeat: clock.Now(),
				}

				prevResult, err := subj.Register(ctx, store.RegisterAgentQuery{
					Registration: registration,
				})
				require.NoError(t, err)

				updateQuery := store.UpdateRegistrationStatusQuery{
					Name:       registration.Name,
					InstanceID: registration.InstanceID,
					FromStatus: []core.AgentRegistrationStatus{
						tt.fromStatus,
					},
					ToStatus: core.AgentRegistrationStatusDeregistered,
				}

				// when
				err = subj.UpdateRegistrationStatus(ctx, updateQuery)

				// then
				assert.NoError(t, err)

				getResult, err := subj.Get(ctx, store.GetAgentQuery{
					Name:       registration.Name,
					InstanceID: registration.InstanceID,
				})
				require.NoError(t, err)

				assert.Equal(t, updateQuery.ToStatus, getResult.Registration.Status)
				assert.Greater(t, getResult.Registration.UpdatedAt, prevResult.Registration.UpdatedAt)

				assert.Equal(t, prevResult.Registration.Name, getResult.Registration.Name)
				assert.Equal(t, prevResult.Registration.InstanceID, getResult.Registration.InstanceID)
				assert.Equal(t, prevResult.Registration.LastHeartbeat, getResult.Registration.LastHeartbeat)
				assert.Equal(t, prevResult.Registration.CreatedAt, getResult.Registration.CreatedAt)
			})
		}
	})

	t.Run("should not update status if query does not match registration", func(t *testing.T) {
		// given
		registration := core.AgentRegistration{
			Name:          "test-agent",
			InstanceID:    uuid.New().String(),
			Status:        core.AgentRegistrationStatusHealthy,
			LastHeartbeat: clock.Now(),
		}

		prevResult, err := subj.Register(ctx, store.RegisterAgentQuery{
			Registration: registration,
		})

		require.NoError(t, err)

		tts := []struct {
			name        string
			updateQuery store.UpdateRegistrationStatusQuery
		}{
			{
				name: "non-existent name",
				updateQuery: store.UpdateRegistrationStatusQuery{
					Name:       "non-existent-agent",
					InstanceID: registration.InstanceID,
					FromStatus: []core.AgentRegistrationStatus{
						registration.Status,
					},
					ToStatus: core.AgentRegistrationStatusDeregistered,
				},
			},
			{
				name: "non-existent instance ID",
				updateQuery: store.UpdateRegistrationStatusQuery{
					Name:       registration.Name,
					InstanceID: uuid.New().String(),
					FromStatus: []core.AgentRegistrationStatus{
						registration.Status,
					},
					ToStatus: core.AgentRegistrationStatusDeregistered,
				},
			},
			{
				name: "from status does not match",
				updateQuery: store.UpdateRegistrationStatusQuery{
					Name:       registration.Name,
					InstanceID: registration.InstanceID,
					FromStatus: []core.AgentRegistrationStatus{
						core.AgentRegistrationStatusUnhealthy,
					},
					ToStatus: core.AgentRegistrationStatusDeregistered,
				},
			},
			{
				name: "heartbeat threshold not exceeded",
				updateQuery: store.UpdateRegistrationStatusQuery{
					Name:       registration.Name,
					InstanceID: registration.InstanceID,
					FromStatus: []core.AgentRegistrationStatus{
						registration.Status,
					},
					ToStatus:           core.AgentRegistrationStatusDeregistered,
					HeartbeatThreshold: 100 * time.Second,
				},
			},
		}
		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// when
				err = subj.UpdateRegistrationStatus(ctx, tt.updateQuery)

				// then
				assert.NoError(t, err)

				getResult, err := subj.Get(ctx, store.GetAgentQuery{
					Name:       registration.Name,
					InstanceID: registration.InstanceID,
				})

				require.NoError(t, err)

				assert.Equal(t, registration.Status, getResult.Registration.Status)
				assert.Equal(t, prevResult.Registration.Name, getResult.Registration.Name)
				assert.Equal(t, prevResult.Registration.InstanceID, getResult.Registration.InstanceID)
				assert.Equal(t, prevResult.Registration.LastHeartbeat, getResult.Registration.LastHeartbeat)
				assert.Equal(t, prevResult.Registration.CreatedAt, getResult.Registration.CreatedAt)
				assert.Equal(t, prevResult.Registration.UpdatedAt, getResult.Registration.UpdatedAt)
			})
		}
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
