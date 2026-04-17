package agents_test

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/lib/pq"

	"github.com/openkcm/krypton/internal/core"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/api"
	"github.com/openkcm/krypton/pkg/api/agents"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

func TestClient(t *testing.T) {
	t.Run("agent client should return error if agent name is empty", func(t *testing.T) {
		// given when
		subj, err := agents.NewClient("some-url", "", "agent-id")

		// then
		assert.ErrorIs(t, err, agents.ErrAgentNameEmpty)
		assert.Nil(t, subj)
	})

	t.Run("agent client should return error if baseURL is empty", func(t *testing.T) {
		// given when
		subj, err := agents.NewClient("", "agent-aws", "agent-id")

		// then
		assert.ErrorIs(t, err, api.ErrBaseURLEmpty)
		assert.Nil(t, subj)
	})

	t.Run("agent client should return error if agent ID is empty", func(t *testing.T) {
		// given when
		subj, err := agents.NewClient("some-url", "agent-aws", "")

		// then
		assert.ErrorIs(t, err, agents.ErrAgentIDEmpty)
		assert.Nil(t, subj)
	})

	t.Run("agent client should return error if the context is canceled", func(t *testing.T) {
		// given
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		subj, err := agents.NewClient("http://example.com", "agent-aws", "agent-id")
		assert.NoError(t, err)

		// when
		cancel()
		resp, err := subj.Register(ctx, agents.RegisterRequest{})

		// then
		assert.ErrorIs(t, err, api.ErrFailedToSendRequest)
		assert.Equal(t, agents.RegisterResponse{}, resp)
	})
}

func TestAgentRegister(t *testing.T) {
	// given
	ctx := t.Context()
	expAgentName := "agent-aws"
	expAgentID := uuid.NewString()

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
			subj, err := agents.NewClient(srv.URL, expAgentName, expAgentID)
			assert.NoError(t, err)

			// when
			resp, err := subj.Register(t.Context(), agents.RegisterRequest{})

			// then
			assert.NoError(t, err)
			assert.Equal(t, agents.RegisterResponse{
				Config: spec.AgentConfig{
					Name:        expSegment.Name,
					KeyBindings: expSegment.KeyBindings,
					Segment:     expSegment.Segment,
					Labels:      expSegment.Labels,
					Role:        spec.DefaultRole,
					Hierarchy:   expHierarchy,
					KeepAlive:   30,
				},
			}, resp)
		})

		t.Run("agent client should send a successful request and the server should register the client in the registry store", func(t *testing.T) {
			// given
			subj, err := agents.NewClient(srv.URL, expAgentName, expAgentID)
			assert.NoError(t, err)

			// when
			_, err = subj.Register(t.Context(), agents.RegisterRequest{})

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
				Status:        core.AgentRegistrationStatusRegistered,
				LastHeartbeat: result.Registration.LastHeartbeat,
				CreatedAt:     result.Registration.CreatedAt,
				UpdatedAt:     result.Registration.UpdatedAt,
			}, result.Registration)
		})

		t.Run("agent client should return error if agent name is not found in topology", func(t *testing.T) {
			// given
			subj, err := agents.NewClient(srv.URL, "non-existent-agent", expAgentID)
			assert.NoError(t, err)

			// when
			resp, err := subj.Register(t.Context(), agents.RegisterRequest{})

			// then
			assert.ErrorIs(t, err, agents.ErrAgentTopologyNotFound)
			assert.Equal(t, agents.RegisterResponse{}, resp)
		})

		t.Run("server should return error if X-Agent-Name header is missing", func(t *testing.T) {
			// given
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+agents.PathRegister, nil)
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
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+agents.PathRegister, nil)
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
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+agents.PathRegister, nil)
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
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+agents.PathRegister, nil)
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
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+agents.PathRegister, nil)
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

				subj, err := agents.NewClient(faultySrv.URL, expAgentName, expAgentID)
				assert.NoError(t, err)

				resp, err := subj.Register(t.Context(), agents.RegisterRequest{})

				assert.ErrorIs(t, err, tt.expError)
				assert.Equal(t, agents.RegisterResponse{}, resp)
			})
		}
	})
}
