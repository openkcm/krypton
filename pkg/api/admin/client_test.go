package admin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/pkg/api"
	"github.com/openkcm/krypton/pkg/api/admin"
)

func TestClient(t *testing.T) {
	t.Run("should return error if baseURL is empty", func(t *testing.T) {
		// given when
		subj, err := admin.NewClient("")

		// then
		assert.ErrorIs(t, err, api.ErrBaseURLEmpty)
		assert.Nil(t, subj)
	})
}

func TestCreateTenant_Errors(t *testing.T) {
	t.Run("should return error if context is canceled", func(t *testing.T) {
		// given
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		subj, err := admin.NewClient("http://example.com")
		assert.NoError(t, err)

		// when
		resp, err := subj.CreateTenant(ctx, admin.CreateTenantRequest{})

		// then
		assert.ErrorIs(t, err, api.ErrFailedToSendRequest)
		assert.Equal(t, admin.CreateTenantResponse{}, resp)
	})

	tts := []struct {
		name     string
		handler  http.HandlerFunc
		expError error
	}{
		{
			name: "should return error if server returns 5xx status code",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expError: api.ErrUnexpectedStatusCode,
		},
		{
			name: "should return error if server response cannot be decoded",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte("invalid json"))
			},
			expError: api.ErrFailedToDecodeResponse,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// given
			srv := httptest.NewServer(tt.handler)
			t.Cleanup(srv.Close)

			subj, err := admin.NewClient(srv.URL)
			assert.NoError(t, err)

			// when
			resp, err := subj.CreateTenant(t.Context(), admin.CreateTenantRequest{})

			// then
			assert.ErrorIs(t, err, tt.expError)
			assert.Equal(t, admin.CreateTenantResponse{}, resp)
		})
	}
}

func TestGetTenant_Errors(t *testing.T) {
	t.Run("should return error if context is canceled", func(t *testing.T) {
		// given
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		subj, err := admin.NewClient("http://example.com")
		assert.NoError(t, err)

		// when
		resp, err := subj.GetTenant(ctx, admin.GetTenantRequest{ID: "some-id"})

		// then
		assert.ErrorIs(t, err, api.ErrFailedToSendRequest)
		assert.Equal(t, admin.GetTenantResponse{}, resp)
	})

	tts := []struct {
		name     string
		handler  http.HandlerFunc
		expError error
	}{
		{
			name: "should return error if server returns 5xx status code",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expError: api.ErrUnexpectedStatusCode,
		},
		{
			name: "should return error if server response cannot be decoded",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("invalid json"))
			},
			expError: api.ErrFailedToDecodeResponse,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// given
			srv := httptest.NewServer(tt.handler)
			t.Cleanup(srv.Close)

			subj, err := admin.NewClient(srv.URL)
			assert.NoError(t, err)

			// when
			resp, err := subj.GetTenant(t.Context(), admin.GetTenantRequest{ID: "some-id"})

			// then
			assert.ErrorIs(t, err, tt.expError)
			assert.Equal(t, admin.GetTenantResponse{}, resp)
		})
	}
}

func TestListTenants_Errors(t *testing.T) {
	t.Run("should return error if context is canceled", func(t *testing.T) {
		// given
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		subj, err := admin.NewClient("http://example.com")
		assert.NoError(t, err)

		// when
		resp, err := subj.ListTenants(ctx, admin.ListTenantsRequest{})

		// then
		assert.ErrorIs(t, err, api.ErrFailedToSendRequest)
		assert.Equal(t, admin.ListTenantsResponse{}, resp)
	})

	tts := []struct {
		name     string
		handler  http.HandlerFunc
		expError error
	}{
		{
			name: "should return error if server returns 5xx status code",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expError: api.ErrUnexpectedStatusCode,
		},
		{
			name: "should return error if server response cannot be decoded",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("invalid json"))
			},
			expError: api.ErrFailedToDecodeResponse,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// given
			srv := httptest.NewServer(tt.handler)
			t.Cleanup(srv.Close)

			subj, err := admin.NewClient(srv.URL)
			assert.NoError(t, err)

			// when
			resp, err := subj.ListTenants(t.Context(), admin.ListTenantsRequest{})

			// then
			assert.ErrorIs(t, err, tt.expError)
			assert.Equal(t, admin.ListTenantsResponse{}, resp)
		})
	}
}
