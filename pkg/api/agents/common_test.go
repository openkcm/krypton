package agents_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/model"
	"github.com/openkcm/krypton/internal/models"
	"github.com/openkcm/krypton/pkg/api"
	"github.com/openkcm/krypton/pkg/api/agents"
)

func TestClient(t *testing.T) {
	t.Run("agent client should return error if agent name is empty", func(t *testing.T) {
		// given when
		subj, err := agents.NewClient("some-url", "")

		// then
		assert.ErrorIs(t, err, agents.ErrAgentNameEmpty)
		assert.Nil(t, subj)
	})

	t.Run("agent client should return error if baseURL is empty", func(t *testing.T) {
		// given when
		subj, err := agents.NewClient("", "agent-aws")

		// then
		assert.ErrorIs(t, err, agents.ErrBaseURLEmpty)
		assert.Nil(t, subj)
	})

	t.Run("agent client should return error if the context is canceled", func(t *testing.T) {
		// given
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		subj, err := agents.NewClient("http://example.com", "agent-aws")
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
	expAgentName := "agent-aws"

	t.Run("actual server", func(t *testing.T) {
		expSegment := models.TopologySegment{
			Name:   expAgentName,
			Labels: map[string]string{"region": "us-west"},
			Segment: models.HierarchySegment{
				StartKind: "K2",
				EndKind:   "K2",
			},
			KeyBindings: map[string]models.KeyBinding{
				"binding1": {
					Vault:             models.VaultSpec{},
					ParentKeyProvider: &models.ParentKeyProviderRef{},
					Labels:            models.Labels{},
				},
			},
		}
		topology := models.Topology{
			Segments: []models.TopologySegment{expSegment},
		}

		expHierarchy := model.KeyHierarchy{
			Name: "some-hierarchy",
			KeySpecs: []model.KeySpec{
				{
					Kind:      "K1",
					Role:      model.KeyRoleRoot,
					Algorithm: "",
				},
				{
					Kind:      "K2",
					Role:      model.KeyRoleDek,
					Algorithm: "",
				},
			},
		}

		// given
		handler := agents.NewServerMux(nil, expHierarchy, topology)
		srv := httptest.NewServer(handler)
		t.Cleanup(srv.Close)

		t.Run("agent client should sent a successful request to the server", func(t *testing.T) {
			// given
			subj, err := agents.NewClient(srv.URL, expAgentName)
			assert.NoError(t, err)

			// when
			resp, err := subj.Register(t.Context(), agents.RegisterRequest{})

			// then
			assert.NoError(t, err)
			assert.Equal(t, agents.RegisterResponse{
				Config: model.AgentConfig{
					Name:        expSegment.Name,
					KeyBindings: expSegment.KeyBindings,
					Segment:     expSegment.Segment,
					Labels:      expSegment.Labels,
					Role:        model.DefaultRole,
					Hierarchy:   expHierarchy,
					KeepAlive:   30,
				},
			}, resp)
		})

		t.Run("agent client should return error if agent name is not found in topology", func(t *testing.T) {
			// given
			subj, err := agents.NewClient(srv.URL, "non-existent-agent")
			assert.NoError(t, err)

			// when
			resp, err := subj.Register(t.Context(), agents.RegisterRequest{})

			// then
			assert.ErrorIs(t, err, agents.ErrAgentNotFound)
			assert.Equal(t, agents.RegisterResponse{}, resp)
		})

		t.Run("server should return error if X-Agent-Name header is missing", func(t *testing.T) {
			// given
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+agents.PathRegister, nil)
			assert.NoError(t, err)

			// when
			httpResp, err := http.DefaultClient.Do(req)
			assert.NoError(t, err)
			defer httpResp.Body.Close()

			// then
			assert.Equal(t, http.StatusBadRequest, httpResp.StatusCode)
		})

		t.Run("server should return error if X-Agent-Name header is empty", func(t *testing.T) {
			// given
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+agents.PathRegister, nil)
			req.Header.Set("X-Agent-Name", "")
			assert.NoError(t, err)

			// when
			httpResp, err := http.DefaultClient.Do(req)
			assert.NoError(t, err)
			defer httpResp.Body.Close()

			// then
			assert.Equal(t, http.StatusBadRequest, httpResp.StatusCode)
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

				subj, err := agents.NewClient(faultySrv.URL, expAgentName)
				assert.NoError(t, err)

				resp, err := subj.Register(t.Context(), agents.RegisterRequest{})

				assert.ErrorIs(t, err, tt.expError)
				assert.Equal(t, agents.RegisterResponse{}, resp)
			})
		}
	})
}
