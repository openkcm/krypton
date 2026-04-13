package agents_test

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/core"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/api"
	"github.com/openkcm/krypton/pkg/api/agents"
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

	t.Run("actual server", func(t *testing.T) {
		expSegment := spec.TopologySegment{
			Name:   expAgentName,
			Labels: map[string]string{"region": "us-west"},
			Segment: spec.HierarchySegment{
				StartKind: "K2",
				EndKind:   "K2",
			},
			KeyBindings: map[string]spec.KeyBinding{
				"binding1": {
					Vault:             spec.VaultSpec{},
					ParentKeyProvider: &spec.ParentKeyProviderRef{},
					Labels:            spec.Labels{},
				},
			},
		}
		topology := spec.Topology{
			Segments: []spec.TopologySegment{expSegment},
		}

		expHierarchy := spec.KeyHierarchy{
			Name: "some-hierarchy",
			KeySpecs: []spec.KeySpec{
				{
					Kind:      "K1",
					Role:      spec.KeyRoleRoot,
					Algorithm: "",
				},
				{
					Kind:      "K2",
					Role:      spec.KeyRoleDek,
					Algorithm: "",
				},
			},
		}

		// given
		handler := agents.NewServerMux(nil, agentStore, expHierarchy, topology)
		srv := httptest.NewServer(handler)
		t.Cleanup(srv.Close)

		t.Run("agent client should send a successful request to the server", func(t *testing.T) {
			// given
			expAgentID := uuid.NewString()
			subj, err := agents.NewClient(srv.URL, expAgentName, expAgentID)
			assert.NoError(t, err)

			// when
			resp, err := subj.SendHeartbeat(t.Context(), agents.SendHeartbeatRequest{})

			// then
			assert.NoError(t, err)
			assert.Equal(t, agents.SendHeartbeatResponse{}, resp)
		})

		t.Run("agent client should update the last heartbeat timestamp and status of the agent if it is already registered", func(t *testing.T) {
			// given
			expAgentID := uuid.NewString()

			subj, err := agents.NewClient(srv.URL, expAgentName, expAgentID)
			assert.NoError(t, err)

			_, err = subj.Register(t.Context(), agents.RegisterRequest{})
			assert.NoError(t, err)

			prevResult, err := agentStore.Get(t.Context(), store.GetAgentQuery{
				Name:       expAgentName,
				InstanceID: expAgentID,
			})
			assert.NoError(t, err)

			// when
			_, err = subj.SendHeartbeat(t.Context(), agents.SendHeartbeatRequest{})

			// then
			assert.NoError(t, err)

			newResult, err := agentStore.Get(t.Context(), store.GetAgentQuery{
				Name:       expAgentName,
				InstanceID: expAgentID,
			})

			assert.NoError(t, err)
			assert.Equal(t, core.AgentRegistration{
				Name:          prevResult.Registration.Name,
				InstanceID:    prevResult.Registration.InstanceID,
				CreatedAt:     prevResult.Registration.CreatedAt,
				Status:        core.AgentRegistrationStatusHealthy,
				LastHeartbeat: newResult.Registration.LastHeartbeat,
				UpdatedAt:     newResult.Registration.UpdatedAt,
			}, newResult.Registration)
			assert.NotEqual(t, prevResult.Registration.LastHeartbeat, newResult.Registration.LastHeartbeat)
			assert.NotEqual(t, prevResult.Registration.UpdatedAt, newResult.Registration.UpdatedAt)
		})

		t.Run("agent client should re-register the agent if it is not found in the registry store", func(t *testing.T) {
			// given
			expAgentID := uuid.NewString()

			subj, err := agents.NewClient(srv.URL, expAgentName, expAgentID)
			assert.NoError(t, err)

			// when
			_, err = subj.SendHeartbeat(t.Context(), agents.SendHeartbeatRequest{})

			// then
			assert.NoError(t, err)

			result, err := agentStore.Get(t.Context(), store.GetAgentQuery{
				Name:       expAgentName,
				InstanceID: expAgentID,
			})

			assert.NoError(t, err)
			assert.Equal(t, core.AgentRegistration{
				Name:          expAgentName,
				InstanceID:    expAgentID,
				Status:        core.AgentRegistrationStatusHealthy,
				LastHeartbeat: result.Registration.LastHeartbeat,
				CreatedAt:     result.Registration.CreatedAt,
				UpdatedAt:     result.Registration.UpdatedAt,
			}, result.Registration)
		})

		t.Run("agent client should return error if agent name is not found in topology", func(t *testing.T) {
			// given
			nonExistingAgentName := "non-existent-agent"
			expAgentID := uuid.NewString()

			subj, err := agents.NewClient(srv.URL, nonExistingAgentName, expAgentID)
			assert.NoError(t, err)

			// when
			resp, err := subj.SendHeartbeat(t.Context(), agents.SendHeartbeatRequest{})

			// then
			assert.Error(t, err)
			assert.ErrorIs(t, err, agents.ErrAgentTopologyNotFound)
			assert.Equal(t, agents.SendHeartbeatResponse{}, resp)

			_, err = agentStore.Get(t.Context(), store.GetAgentQuery{
				Name:       nonExistingAgentName,
				InstanceID: expAgentID,
			})

			assert.ErrorIs(t, err, store.ErrAgentRegistrationNotFound)
		})

		t.Run("server should return error if X-Agent-Name header is missing", func(t *testing.T) {
			// given
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+agents.PathHeartbeat, nil)
			req.Header.Set(agents.AgentIDHeader, uuid.NewString())
			assert.NoError(t, err)

			// when
			httpResp, err := http.DefaultClient.Do(req)
			assert.NoError(t, err)
			t.Cleanup(func() {
				httpResp.Body.Close()
			})

			// then
			assert.Equal(t, http.StatusBadRequest, httpResp.StatusCode)
		})

		t.Run("server should return error if X-Agent-ID header is missing", func(t *testing.T) {
			// given
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+agents.PathHeartbeat, nil)
			req.Header.Set(agents.AgentNameHeader, expAgentName)
			assert.NoError(t, err)

			// when
			httpResp, err := http.DefaultClient.Do(req)
			assert.NoError(t, err)
			t.Cleanup(func() {
				httpResp.Body.Close()
			})

			// then
			assert.Equal(t, http.StatusBadRequest, httpResp.StatusCode)
		})

		t.Run("server should return error if X-Agent-Name header is empty", func(t *testing.T) {
			// given
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+agents.PathHeartbeat, nil)
			req.Header.Set(agents.AgentNameHeader, "")
			req.Header.Set(agents.AgentIDHeader, uuid.NewString())
			assert.NoError(t, err)

			// when
			httpResp, err := http.DefaultClient.Do(req)
			assert.NoError(t, err)
			t.Cleanup(func() {
				httpResp.Body.Close()
			})

			// then
			assert.Equal(t, http.StatusBadRequest, httpResp.StatusCode)
		})

		t.Run("server should return error if X-Agent-ID header is empty", func(t *testing.T) {
			// given
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+agents.PathHeartbeat, nil)
			req.Header.Set(agents.AgentNameHeader, expAgentName)
			req.Header.Set(agents.AgentIDHeader, "")
			assert.NoError(t, err)

			// when
			httpResp, err := http.DefaultClient.Do(req)
			assert.NoError(t, err)

			t.Cleanup(func() {
				httpResp.Body.Close()
			})

			// then
			assert.Equal(t, http.StatusBadRequest, httpResp.StatusCode)
		})

		t.Run("server should return proper Content-Type", func(t *testing.T) {
			// given
			expAgentID := uuid.NewString()
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+agents.PathHeartbeat, nil)
			req.Header.Set(agents.AgentNameHeader, expAgentName)
			req.Header.Set(agents.AgentIDHeader, expAgentID)
			assert.NoError(t, err)

			// when
			httpResp, err := http.DefaultClient.Do(req)
			assert.NoError(t, err)

			t.Cleanup(func() {
				httpResp.Body.Close()
			})

			// then
			assert.Equal(t, http.StatusOK, httpResp.StatusCode)
			assert.Equal(t, "application/json", httpResp.Header.Get("Content-Type"))
		})
	})

	t.Run("faulty server", func(t *testing.T) {
		tts := []struct {
			name     string
			handler  http.HandlerFunc
			expError error
		}{
			{
				name: "agent client should return error if server returns 5xx status code",
				handler: func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				},
				expError: api.ErrUnexpectedStatusCode,
			},
			{
				name: "agent client should return error if server response cannot be decoded",
				handler: func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("invalid json"))
				},
				expError: api.ErrFailedToDecodeResponse,
			},
		}

		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				faultySrv := httptest.NewServer(tt.handler)
				t.Cleanup(faultySrv.Close)

				expAgentID := uuid.NewString()
				subj, err := agents.NewClient(faultySrv.URL, expAgentName, expAgentID)
				assert.NoError(t, err)

				resp, err := subj.SendHeartbeat(t.Context(), agents.SendHeartbeatRequest{})

				assert.ErrorIs(t, err, tt.expError)
				assert.Equal(t, agents.SendHeartbeatResponse{}, resp)
			})
		}
	})
}
