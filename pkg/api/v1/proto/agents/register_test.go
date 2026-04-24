package agents_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/core"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

func TestRegister(t *testing.T) {
	// given
	ctx := t.Context()
	expAgentName := "agent-aws"

	db := createDatabase(t)

	agentStore, err := storesql.NewAgentStore(ctx, db)
	require.NoError(t, err)

	t.Run("should register agent successfully", func(t *testing.T) {
		// given
		expInstanceID := uuid.NewString()
		rootCfg := validRootConfig(expAgentName)
		cli := setupServerAndClient(t, agentStore, rootCfg)

		// when
		resp, err := cli.Register(ctx, &agents.RegisterAgentRequest{
			AgentName:  expAgentName,
			InstanceId: expInstanceID,
		})

		// then
		assert.NoError(t, err)

		actConfig, err := agents.UnmarshalAgentConfig(resp.GetConfig())
		require.NoError(t, err)
		actConfig.SubAgents = nil

		assert.Equal(t, spec.NewAgentConfig(rootCfg.Hierarchy, rootCfg.Topology.Segments[0]), *actConfig)

		result, err := agentStore.Get(ctx, store.GetAgentQuery{
			Name:       expAgentName,
			InstanceID: expInstanceID,
		})
		assert.NoError(t, err)

		assert.Equal(t, core.AgentRegistration{
			Name:          expAgentName,
			InstanceID:    expInstanceID,
			Status:        core.AgentRegistrationStatusRegistered,
			LastHeartbeat: result.Registration.LastHeartbeat,
			CreatedAt:     result.Registration.CreatedAt,
			UpdatedAt:     result.Registration.UpdatedAt,
		}, result.Registration)
	})

	t.Run("should update registration if agent registers two times", func(t *testing.T) {
		// given
		expInstanceID := uuid.NewString()
		cli := setupServerAndClient(t, agentStore, validRootConfig(expAgentName))

		// register first time
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

		// when - register second time
		_, err = cli.Register(ctx, &agents.RegisterAgentRequest{
			AgentName:  expAgentName,
			InstanceId: expInstanceID,
		})

		// then
		assert.NoError(t, err)

		newRes, err := agentStore.Get(ctx, store.GetAgentQuery{
			Name:       expAgentName,
			InstanceID: expInstanceID,
		})
		assert.NoError(t, err)

		assert.Equal(t, core.AgentRegistration{
			Name:          expAgentName,
			InstanceID:    expInstanceID,
			Status:        core.AgentRegistrationStatusRegistered,
			CreatedAt:     prevRes.Registration.CreatedAt,
			LastHeartbeat: newRes.Registration.LastHeartbeat,
			UpdatedAt:     newRes.Registration.UpdatedAt,
		}, newRes.Registration)

		assert.Less(t, prevRes.Registration.LastHeartbeat, newRes.Registration.LastHeartbeat, "expected LastHeartbeat to be updated")
		assert.Less(t, prevRes.Registration.UpdatedAt, newRes.Registration.UpdatedAt, "expected UpdatedAt to be updated")
	})

	t.Run("should return error if agent name is not found in topology", func(t *testing.T) {
		// given
		cli := setupServerAndClient(t, agentStore, validRootConfig(expAgentName))

		// when
		_, err := cli.Register(t.Context(), &agents.RegisterAgentRequest{
			AgentName:  "unknown-agent",
			InstanceId: uuid.NewString(),
		})

		// then
		assert.Error(t, err)
		assert.Equal(t, codes.NotFound, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should return internal error if there is an error in the registry store", func(t *testing.T) {
		// given
		expInstanceID := uuid.NewString()
		tmpDB := createDatabase(t)

		agentStore, err := storesql.NewAgentStore(ctx, tmpDB)
		require.NoError(t, err)

		// drop the table to cause an error in the agent store during register processing
		_, err = tmpDB.ExecContext(ctx, "DROP TABLE agent_registrations")
		require.NoError(t, err)

		cli := setupServerAndClient(t, agentStore, validRootConfig(expAgentName))

		// when
		resp, err := cli.Register(ctx, &agents.RegisterAgentRequest{
			AgentName:  expAgentName,
			InstanceId: expInstanceID,
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.Internal, status.Code(err), err.Error())

		assertErrorDetails(t, proto.Code_ERROR_CODE_RETRY, err)
	})

	t.Run("should return error if agent name is empty", func(t *testing.T) {
		// given
		cli := setupServerAndClient(t, agentStore, validRootConfig(expAgentName))

		// when
		_, err := cli.Register(ctx, &agents.RegisterAgentRequest{
			InstanceId: uuid.NewString(),
		})

		// then
		assert.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should return error if InstanceID is empty", func(t *testing.T) {
		// given
		cli := setupServerAndClient(t, agentStore, validRootConfig(expAgentName))

		// when
		_, err := cli.Register(ctx, &agents.RegisterAgentRequest{
			AgentName: expAgentName,
		})

		// then
		assert.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})
}
