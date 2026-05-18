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

	require.NoError(t, storesql.Migrate(ctx, db))
	subj := storesql.NewAgentStore(db)

	t.Run("should insert new agent registration", func(t *testing.T) {
		// given
		registration := core.AgentRegistration{
			Name:       agentName(),
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
			Name:       agentName(),
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
	// given
	ctx := t.Context()
	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err)

	t.Cleanup(func() {
		db.Close()
	})

	t.Run("should get existing agent registration", func(t *testing.T) {
		// given
		subj := storesql.NewAgentStore(db)

		registration := core.AgentRegistration{
			Name:       agentName(),
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
		subj := storesql.NewAgentStore(db)

		// when
		getResult, err := subj.Get(ctx, store.GetAgentQuery{
			Name:       "non-existent-agent",
			InstanceID: uuid.New().String(),
		})

		// then
		assert.ErrorIs(t, err, store.ErrAgentNotFound)
		assert.Zero(t, getResult.Registration)
	})
}

func TestUpdateStatus(t *testing.T) {
	// given
	ctx := t.Context()

	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err)

	t.Cleanup(func() {
		db.Close()
	})

	require.NoError(t, storesql.Migrate(ctx, db))
	subj := storesql.NewAgentStore(db)

	t.Run("should return error if the query does not have required fields", func(t *testing.T) {
		// given
		tests := []struct {
			name        string
			updateQuery store.UpdateAgentStatusQuery
		}{
			{
				name: "missing to status",
				updateQuery: store.UpdateAgentStatusQuery{
					Name:       agentName(),
					InstanceID: uuid.New().String(),
					FromStatus: []core.AgentRegistrationStatus{
						core.AgentRegistrationStatusHealthy,
					},
				},
			},
			{
				name: "missing from status",
				updateQuery: store.UpdateAgentStatusQuery{
					Name:       agentName(),
					InstanceID: uuid.New().String(),
					ToStatus:   core.AgentRegistrationStatusDeregistered,
				},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				// when
				err := subj.UpdateStatus(ctx, tt.updateQuery)

				// then
				assert.ErrorIs(t, err, store.ErrAgentQueryInvalid)
			})
		}
	})

	t.Run("UpdateStatus", func(t *testing.T) {
		// given
		tests := []struct {
			name          string
			inputs        func() (reg1 core.AgentRegistration, reg2 core.AgentRegistration, query store.UpdateAgentStatusQuery)
			isReg1Changed bool
			isReg2Changed bool
		}{
			{
				name: "should update status of both registration for the same name",
				inputs: func() (core.AgentRegistration, core.AgentRegistration, store.UpdateAgentStatusQuery) {
					reg1 := core.AgentRegistration{
						Name:          "test-agent",
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now(),
					}
					reg2 := core.AgentRegistration{
						Name:          "test-agent",
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now(),
					}

					return reg1, reg2, store.UpdateAgentStatusQuery{
						Name: "test-agent",
						FromStatus: []core.AgentRegistrationStatus{
							core.AgentRegistrationStatusHealthy,
						},
						ToStatus: core.AgentRegistrationStatusDeregistered,
					}
				},
				isReg1Changed: true,
				isReg2Changed: true,
			},

			{
				name: "should update status of only registration with matching name",
				inputs: func() (core.AgentRegistration, core.AgentRegistration, store.UpdateAgentStatusQuery) {
					reg1 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now(),
					}
					reg2 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now(),
					}

					return reg1, reg2, store.UpdateAgentStatusQuery{
						Name: reg2.Name,
						FromStatus: []core.AgentRegistrationStatus{
							core.AgentRegistrationStatusHealthy,
						},
						ToStatus: core.AgentRegistrationStatusDeregistered,
					}
				},
				isReg2Changed: true,
			},

			{
				name: "should not update status of any registration for an unknown name",
				inputs: func() (core.AgentRegistration, core.AgentRegistration, store.UpdateAgentStatusQuery) {
					reg1 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now(),
					}
					reg2 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now(),
					}

					return reg1, reg2, store.UpdateAgentStatusQuery{
						Name: "unknown-agent",
						FromStatus: []core.AgentRegistrationStatus{
							core.AgentRegistrationStatusHealthy,
						},
						ToStatus: core.AgentRegistrationStatusDeregistered,
					}
				},
			},

			{
				name: "should update status of only registration with a matching instanceID",
				inputs: func() (core.AgentRegistration, core.AgentRegistration, store.UpdateAgentStatusQuery) {
					reg1 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now(),
					}
					reg2 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now(),
					}

					return reg1, reg2, store.UpdateAgentStatusQuery{
						InstanceID: reg2.InstanceID,
						FromStatus: []core.AgentRegistrationStatus{
							core.AgentRegistrationStatusHealthy,
						},
						ToStatus: core.AgentRegistrationStatusDeregistered,
					}
				},
				isReg2Changed: true,
			},
			{
				name: "should not update status of any registration for an unknown instanceID",
				inputs: func() (core.AgentRegistration, core.AgentRegistration, store.UpdateAgentStatusQuery) {
					reg1 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now(),
					}
					reg2 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now(),
					}

					return reg1, reg2, store.UpdateAgentStatusQuery{
						InstanceID: uuid.New().String(),
						FromStatus: []core.AgentRegistrationStatus{
							core.AgentRegistrationStatusHealthy,
						},
						ToStatus: core.AgentRegistrationStatusDeregistered,
					}
				},
			},
			{
				name: "should update status of only registration with matching instanceID and name",
				inputs: func() (core.AgentRegistration, core.AgentRegistration, store.UpdateAgentStatusQuery) {
					reg1 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now(),
					}
					reg2 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now(),
					}

					return reg1, reg2, store.UpdateAgentStatusQuery{
						InstanceID: reg1.InstanceID,
						Name:       reg1.Name,
						FromStatus: []core.AgentRegistrationStatus{
							core.AgentRegistrationStatusHealthy,
						},
						ToStatus: core.AgentRegistrationStatusDeregistered,
					}
				},
				isReg1Changed: true,
			},
			{
				name: "should update status of only registration with heartbeat threshold exceeded",
				inputs: func() (core.AgentRegistration, core.AgentRegistration, store.UpdateAgentStatusQuery) {
					reg1 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.UnixNano(time.Now().Add(-1 * time.Minute).UnixNano()),
					}
					reg2 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now(),
					}

					return reg1, reg2, store.UpdateAgentStatusQuery{
						FromStatus: []core.AgentRegistrationStatus{
							core.AgentRegistrationStatusHealthy,
						},
						ToStatus:           core.AgentRegistrationStatusDeregistered,
						HeartbeatThreshold: 30 * time.Second,
					}
				},
				isReg1Changed: true,
			},
			{
				name: "should not update status of any registration when heartbeat threshold not exceeded",
				inputs: func() (core.AgentRegistration, core.AgentRegistration, store.UpdateAgentStatusQuery) {
					reg1 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now() - clock.UnixNano(time.Minute),
					}
					reg2 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now(),
					}

					return reg1, reg2, store.UpdateAgentStatusQuery{
						FromStatus: []core.AgentRegistrationStatus{
							core.AgentRegistrationStatusHealthy,
						},
						ToStatus:           core.AgentRegistrationStatusDeregistered,
						HeartbeatThreshold: 30 * time.Minute,
					}
				},
			},
			{
				name: "should update status of both registration when heartbeat threshold exceeded",
				inputs: func() (core.AgentRegistration, core.AgentRegistration, store.UpdateAgentStatusQuery) {
					reg1 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now() - clock.UnixNano(time.Minute),
					}
					reg2 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now() - clock.UnixNano(time.Minute),
					}

					return reg1, reg2, store.UpdateAgentStatusQuery{
						FromStatus: []core.AgentRegistrationStatus{
							core.AgentRegistrationStatusHealthy,
						},
						ToStatus:           core.AgentRegistrationStatusDeregistered,
						HeartbeatThreshold: 30 * time.Second,
					}
				},
				isReg1Changed: true,
				isReg2Changed: true,
			},
			{
				name: "should update status of only registration with heartbeat threshold exceeded and matching name",
				inputs: func() (core.AgentRegistration, core.AgentRegistration, store.UpdateAgentStatusQuery) {
					reg1 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now() - clock.UnixNano(time.Minute),
					}
					reg2 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now() - clock.UnixNano(time.Minute),
					}

					return reg1, reg2, store.UpdateAgentStatusQuery{
						FromStatus: []core.AgentRegistrationStatus{
							core.AgentRegistrationStatusHealthy,
						},
						ToStatus:           core.AgentRegistrationStatusDeregistered,
						Name:               reg2.Name,
						HeartbeatThreshold: 30 * time.Second,
					}
				},
				isReg2Changed: true,
			},
			{
				name: "should update status of only registration with heartbeat threshold exceeded and matching instanceID",
				inputs: func() (core.AgentRegistration, core.AgentRegistration, store.UpdateAgentStatusQuery) {
					reg1 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now() - clock.UnixNano(time.Minute),
					}
					reg2 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now() - clock.UnixNano(time.Minute),
					}

					return reg1, reg2, store.UpdateAgentStatusQuery{
						FromStatus: []core.AgentRegistrationStatus{
							core.AgentRegistrationStatusHealthy,
						},
						ToStatus:           core.AgentRegistrationStatusDeregistered,
						InstanceID:         reg1.InstanceID,
						HeartbeatThreshold: 30 * time.Second,
					}
				},
				isReg1Changed: true,
			},
			{
				name: "should update status of only registration with heartbeat threshold exceeded, matching instanceID and name",
				inputs: func() (core.AgentRegistration, core.AgentRegistration, store.UpdateAgentStatusQuery) {
					reg1 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now() - clock.UnixNano(time.Minute),
					}
					reg2 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now() - clock.UnixNano(time.Minute),
					}

					return reg1, reg2, store.UpdateAgentStatusQuery{
						FromStatus: []core.AgentRegistrationStatus{
							core.AgentRegistrationStatusHealthy,
						},
						ToStatus:           core.AgentRegistrationStatusDeregistered,
						InstanceID:         reg2.InstanceID,
						Name:               reg2.Name,
						HeartbeatThreshold: 30 * time.Second,
					}
				},
				isReg2Changed: true,
			},
			{
				name: "should update status of both registration for the same from status",
				inputs: func() (core.AgentRegistration, core.AgentRegistration, store.UpdateAgentStatusQuery) {
					reg1 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now(),
					}
					reg2 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now(),
					}

					return reg1, reg2, store.UpdateAgentStatusQuery{
						FromStatus: []core.AgentRegistrationStatus{
							core.AgentRegistrationStatusHealthy,
						},
						ToStatus: core.AgentRegistrationStatusDeregistered,
					}
				},
				isReg1Changed: true,
				isReg2Changed: true,
			},
			{
				name: "should not update the status of any registration when the from status does not match",
				inputs: func() (core.AgentRegistration, core.AgentRegistration, store.UpdateAgentStatusQuery) {
					reg1 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now(),
					}
					reg2 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now(),
					}

					return reg1, reg2, store.UpdateAgentStatusQuery{
						FromStatus: []core.AgentRegistrationStatus{
							core.AgentRegistrationStatusRegistered,
						},
						ToStatus: core.AgentRegistrationStatusDeregistered,
					}
				},
			},
			{
				name: "should update the status of one registration when the from status match",
				inputs: func() (core.AgentRegistration, core.AgentRegistration, store.UpdateAgentStatusQuery) {
					reg1 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusRegistered,
						LastHeartbeat: clock.Now(),
					}
					reg2 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now(),
					}

					return reg1, reg2, store.UpdateAgentStatusQuery{
						FromStatus: []core.AgentRegistrationStatus{
							core.AgentRegistrationStatusHealthy,
						},
						ToStatus: core.AgentRegistrationStatusDeregistered,
					}
				},
				isReg2Changed: true,
			},
			{
				name: "should update the status of all registration when the from status match",
				inputs: func() (core.AgentRegistration, core.AgentRegistration, store.UpdateAgentStatusQuery) {
					reg1 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusRegistered,
						LastHeartbeat: clock.Now(),
					}
					reg2 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now(),
					}

					return reg1, reg2, store.UpdateAgentStatusQuery{
						FromStatus: []core.AgentRegistrationStatus{
							core.AgentRegistrationStatusHealthy,
							core.AgentRegistrationStatusRegistered,
						},
						ToStatus: core.AgentRegistrationStatusDeregistered,
					}
				},
				isReg1Changed: true,
				isReg2Changed: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					// given
					reg1, reg2, query := tt.inputs()

					reg1Before, err := subj.Register(ctx, store.RegisterAgentQuery{
						Registration: reg1,
					})
					require.NoError(t, err)

					reg2Before, err := subj.Register(ctx, store.RegisterAgentQuery{
						Registration: reg2,
					})
					require.NoError(t, err)

					// when
					time.Sleep(1 * time.Second) // ensure the updatedAt timestamp will be different after update
					synctest.Wait()
					err = subj.UpdateStatus(ctx, query)

					// then
					assert.NoError(t, err)

					reg1After, err := subj.Get(ctx, store.GetAgentQuery{
						Name:       reg1.Name,
						InstanceID: reg1.InstanceID,
					})
					require.NoError(t, err)

					reg2After, err := subj.Get(ctx, store.GetAgentQuery{
						Name:       reg2.Name,
						InstanceID: reg2.InstanceID,
					})
					require.NoError(t, err)

					if tt.isReg1Changed {
						assert.Equal(t, query.ToStatus, reg1After.Registration.Status)
						assert.Greater(t, reg1After.Registration.UpdatedAt, reg1Before.Registration.UpdatedAt)
					} else {
						assert.Equal(t, reg1Before.Registration, reg1After.Registration)
					}

					if tt.isReg2Changed {
						assert.Equal(t, query.ToStatus, reg2After.Registration.Status)
						assert.Greater(t, reg2After.Registration.UpdatedAt, reg2Before.Registration.UpdatedAt)
					} else {
						assert.Equal(t, reg2Before.Registration, reg2After.Registration)
					}
				})
			})
		}
	})
}

func TestDelete(t *testing.T) {
	// given
	ctx := t.Context()

	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err)

	t.Cleanup(func() {
		db.Close()
	})
	require.NoError(t, storesql.Migrate(ctx, db))
	subj := storesql.NewAgentStore(db)

	t.Run("should return error if the query does not have required fields", func(t *testing.T) {
		// given
		tts := []struct {
			name        string
			deleteQuery store.DeleteAgentQuery
		}{
			{
				name: "missing status",
				deleteQuery: store.DeleteAgentQuery{
					HeartbeatThreshold: 30 * time.Second,
				},
			},
			{
				name: "missing heartbeat threshold",
				deleteQuery: store.DeleteAgentQuery{
					Status: core.AgentRegistrationStatusDeregistered,
				},
			},
			{
				name: "negative heartbeat threshold",
				deleteQuery: store.DeleteAgentQuery{
					Status:             core.AgentRegistrationStatusDeregistered,
					HeartbeatThreshold: -1 * time.Second,
				},
			},
		}

		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// when
				err = subj.Delete(ctx, tt.deleteQuery)

				// then
				assert.ErrorIs(t, err, store.ErrAgentQueryInvalid)
			})
		}
	})

	t.Run("Delete", func(t *testing.T) {
		// given
		tts := []struct {
			name          string
			inputs        func() (reg1 core.AgentRegistration, reg2 core.AgentRegistration, query store.DeleteAgentQuery)
			isReg1Deleted bool
			isReg2Deleted bool
		}{
			{
				name: "should delete both registration for the same status and heartbeat threshold exceeded",
				inputs: func() (core.AgentRegistration, core.AgentRegistration, store.DeleteAgentQuery) {
					reg1 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusDeregistered,
						LastHeartbeat: clock.Now() - clock.UnixNano(time.Minute),
					}
					reg2 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusDeregistered,
						LastHeartbeat: clock.Now() - clock.UnixNano(time.Minute),
					}
					return reg1, reg2, store.DeleteAgentQuery{
						Status:             core.AgentRegistrationStatusDeregistered,
						HeartbeatThreshold: 30 * time.Second,
					}
				},
				isReg1Deleted: true,
				isReg2Deleted: true,
			},
			{
				name: "should not delete any registration when status matches and the heartbeat threshold not exceeded",
				inputs: func() (core.AgentRegistration, core.AgentRegistration, store.DeleteAgentQuery) {
					reg1 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusDeregistered,
						LastHeartbeat: clock.Now() - clock.UnixNano(time.Minute),
					}
					reg2 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusDeregistered,
						LastHeartbeat: clock.Now(),
					}
					return reg1, reg2, store.DeleteAgentQuery{
						Status:             core.AgentRegistrationStatusDeregistered,
						HeartbeatThreshold: 30 * time.Minute,
					}
				},
				isReg1Deleted: false,
				isReg2Deleted: false,
			},
			{
				name: "should not delete any registration when the status does not match even if the heartbeat threshold exceeded",
				inputs: func() (core.AgentRegistration, core.AgentRegistration, store.DeleteAgentQuery) {
					reg1 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusDeregistered,
						LastHeartbeat: clock.Now() - clock.UnixNano(time.Minute),
					}
					reg2 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now() - clock.UnixNano(time.Minute),
					}
					return reg1, reg2, store.DeleteAgentQuery{
						Status:             core.AgentRegistrationStatusRegistered,
						HeartbeatThreshold: 30 * time.Second,
					}
				},
				isReg1Deleted: false,
				isReg2Deleted: false,
			},
			{
				name: "should delete only registration with matching status and heartbeat threshold exceeded",
				inputs: func() (core.AgentRegistration, core.AgentRegistration, store.DeleteAgentQuery) {
					reg1 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusDeregistered,
						LastHeartbeat: clock.Now() - clock.UnixNano(time.Minute),
					}
					reg2 := core.AgentRegistration{
						Name:          agentName(),
						InstanceID:    uuid.New().String(),
						Status:        core.AgentRegistrationStatusHealthy,
						LastHeartbeat: clock.Now() - clock.UnixNano(time.Minute),
					}
					return reg1, reg2, store.DeleteAgentQuery{
						Status:             core.AgentRegistrationStatusDeregistered,
						HeartbeatThreshold: 30 * time.Second,
					}
				},
				isReg1Deleted: true,
				isReg2Deleted: false,
			},
		}
		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// given
				reg1, reg2, query := tt.inputs()

				_, err = subj.Register(ctx, store.RegisterAgentQuery{
					Registration: reg1,
				})
				require.NoError(t, err)

				_, err = subj.Register(ctx, store.RegisterAgentQuery{
					Registration: reg2,
				})
				require.NoError(t, err)

				// when
				err = subj.Delete(ctx, query)

				// then
				assert.NoError(t, err)

				_, err = subj.Get(ctx, store.GetAgentQuery{
					Name:       reg1.Name,
					InstanceID: reg1.InstanceID,
				})

				if tt.isReg1Deleted {
					assert.ErrorIs(t, err, store.ErrAgentNotFound)
				} else {
					assert.NoError(t, err)
				}

				_, err = subj.Get(ctx, store.GetAgentQuery{
					Name:       reg2.Name,
					InstanceID: reg2.InstanceID,
				})
				if tt.isReg2Deleted {
					assert.ErrorIs(t, err, store.ErrAgentNotFound)
				} else {
					assert.NoError(t, err)
				}
			})
		}
	})
}

func TestList(t *testing.T) {
	// given
	ctx := t.Context()

	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err)

	t.Cleanup(func() {
		db.Close()
	})
	require.NoError(t, storesql.Migrate(ctx, db))
	subj := storesql.NewAgentStore(db)

	name1 := uuid.New().String()
	name2 := uuid.New().String()

	_, err = subj.Register(ctx, store.RegisterAgentQuery{
		Registration: core.AgentRegistration{
			Name:          name1,
			InstanceID:    uuid.New().String(),
			Status:        core.AgentRegistrationStatusDeregistered,
			LastHeartbeat: clock.Now() - clock.UnixNano(time.Minute),
		},
	})
	assert.NoError(t, err)

	_, err = subj.Register(ctx, store.RegisterAgentQuery{
		Registration: core.AgentRegistration{
			Name:          name2,
			InstanceID:    uuid.New().String(),
			Status:        core.AgentRegistrationStatusDeregistered,
			LastHeartbeat: clock.Now() - clock.UnixNano(time.Minute),
		},
	})
	assert.NoError(t, err)

	_, err = subj.Register(ctx, store.RegisterAgentQuery{
		Registration: core.AgentRegistration{
			Name:          name1,
			InstanceID:    uuid.New().String(),
			Status:        core.AgentRegistrationStatusDeregistered,
			LastHeartbeat: clock.Now() - clock.UnixNano(time.Minute),
		},
	})
	assert.NoError(t, err)

	t.Run("should filter agent registrations by name", func(t *testing.T) {
		// when
		listResult, err := subj.List(ctx, store.ListAgentQuery{
			Name: name1,
		})

		// then
		assert.NoError(t, err)
		assert.Len(t, listResult.Registrations, 2)

		for _, reg := range listResult.Registrations {
			assert.Equal(t, name1, reg.Name)
		}
	})
}

func agentName() string {
	return "test-agent-" + uuid.New().String()
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
