package agents_test

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/core"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

func TestSendHeartbeat(t *testing.T) {
	// given
	ctx := t.Context()
	expAgentName := "agent-aws"

	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err)

	t.Cleanup(func() {
		db.Close()
	})

	agentStore, err := storesql.NewAgentStore(ctx, db)
	require.NoError(t, err)

	t.Run("should update the status of the registered to healthy", func(t *testing.T) {
		// given
		expInstanceID := uuid.NewString()
		cli := setupServerAndClient(t, agentStore, validRootConfig(expAgentName))

		_, err := cli.Register(ctx, &agents.RegisterAgentRequest{
			AgentName:  expAgentName,
			InstanceId: expInstanceID,
		})
		assert.NoError(t, err)

		prevRes, err := agentStore.Get(ctx, store.GetAgentQuery{
			Name:       expAgentName,
			InstanceID: expInstanceID,
		})
		assert.NoError(t, err)
		assert.Equal(t, core.AgentRegistrationStatusRegistered, prevRes.Registration.Status, "expected initial status to be Registered")

		// when
		resp, err := cli.SendHeartbeat(ctx, &agents.SendHeartbeatRequest{
			AgentName:  expAgentName,
			InstanceId: expInstanceID,
		})

		// then
		assert.NoError(t, err)
		assert.NotNil(t, resp, "expected response to be not nil")

		newRes, err := agentStore.Get(ctx, store.GetAgentQuery{
			Name:       expAgentName,
			InstanceID: expInstanceID,
		})
		assert.NoError(t, err)

		assert.Equal(t, core.AgentRegistration{
			Name:          prevRes.Registration.Name,
			InstanceID:    prevRes.Registration.InstanceID,
			Status:        core.AgentRegistrationStatusHealthy,
			CreatedAt:     prevRes.Registration.CreatedAt,
			UpdatedAt:     newRes.Registration.UpdatedAt,
			LastHeartbeat: newRes.Registration.LastHeartbeat,
		}, newRes.Registration)
		assert.Less(t, prevRes.Registration.LastHeartbeat, newRes.Registration.LastHeartbeat, "expected LastHeartbeat to be updated")
		assert.Less(t, prevRes.Registration.UpdatedAt, newRes.Registration.UpdatedAt, "expected UpdatedAt to be updated")
	})

	t.Run("should re-register the agent if it is not found in the registry store", func(t *testing.T) {
		// given
		expInstanceID := uuid.NewString()
		cli := setupServerAndClient(t, agentStore, validRootConfig(expAgentName))

		_, err = agentStore.Get(ctx, store.GetAgentQuery{
			Name:       expAgentName,
			InstanceID: expInstanceID,
		})
		assert.Error(t, err, "expected error when getting agent registration before heartbeat")
		assert.Equal(t, store.ErrAgentNotFound, err, "expected error to be ErrAgentNotFound")

		// when
		resp, err := cli.SendHeartbeat(ctx, &agents.SendHeartbeatRequest{
			AgentName:  expAgentName,
			InstanceId: expInstanceID,
		})

		// then
		assert.NoError(t, err)
		assert.NotNil(t, resp, "expected response to be not nil")

		result, err := agentStore.Get(ctx, store.GetAgentQuery{
			Name:       expAgentName,
			InstanceID: expInstanceID,
		})
		assert.NoError(t, err)
		assert.Equal(t, core.AgentRegistration{
			Name:          expAgentName,
			InstanceID:    expInstanceID,
			Status:        core.AgentRegistrationStatusHealthy,
			LastHeartbeat: result.Registration.LastHeartbeat,
			CreatedAt:     result.Registration.CreatedAt,
			UpdatedAt:     result.Registration.UpdatedAt,
		}, result.Registration)
	})

	t.Run("should not return error if heartbeat is sent multiple times", func(t *testing.T) {
		// given
		expInstanceID := uuid.NewString()
		cli := setupServerAndClient(t, agentStore, validRootConfig(expAgentName))

		_, err := cli.Register(ctx, &agents.RegisterAgentRequest{
			AgentName:  expAgentName,
			InstanceId: expInstanceID,
		})
		assert.NoError(t, err)

		// when
		for range 3 {
			resp, err := cli.SendHeartbeat(ctx, &agents.SendHeartbeatRequest{
				AgentName:  expAgentName,
				InstanceId: expInstanceID,
			})

			// then
			assert.NoError(t, err)
			assert.NotNil(t, resp, "expected response to be not nil")
		}
	})

	t.Run("should return error if agent name is not found in topology", func(t *testing.T) {
		// given
		expInstanceID := uuid.NewString()
		cli := setupServerAndClient(t, agentStore, validRootConfig(expAgentName))

		// when
		resp, err := cli.SendHeartbeat(ctx, &agents.SendHeartbeatRequest{
			AgentName:  "unknown-agent",
			InstanceId: expInstanceID,
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.NotFound, status.Code(err), err.Error())
	})

	t.Run("should return internal error if there is an error in the registry store", func(t *testing.T) {
		// given
		expInstanceID := uuid.NewString()
		db := createDatabase(t)

		agentStore, err := storesql.NewAgentStore(ctx, db)
		require.NoError(t, err)

		// drop the table to cause an error in the agent store during heartbeat processing
		_, err = db.ExecContext(ctx, "DROP TABLE agent_registrations")
		require.NoError(t, err)

		cli := setupServerAndClient(t, agentStore, validRootConfig(expAgentName))

		// when
		resp, err := cli.SendHeartbeat(ctx, &agents.SendHeartbeatRequest{
			AgentName:  expAgentName,
			InstanceId: expInstanceID,
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.Internal, status.Code(err), err.Error())
	})

	t.Run("should return error if agent name is empty", func(t *testing.T) {
		// given
		cli := setupServerAndClient(t, agentStore, validRootConfig(expAgentName))

		// when
		_, err := cli.SendHeartbeat(ctx, &agents.SendHeartbeatRequest{
			InstanceId: uuid.NewString(),
		})

		// then
		assert.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err), err.Error())
	})

	t.Run("should return error if InstanceID is empty", func(t *testing.T) {
		// given
		cli := setupServerAndClient(t, agentStore, validRootConfig(expAgentName))

		// when
		_, err := cli.SendHeartbeat(ctx, &agents.SendHeartbeatRequest{
			AgentName: expAgentName,
		})

		// then
		assert.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err), err.Error())
	})
}
