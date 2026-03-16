package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/pkg/api/admin"
)

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		assert.Failf(t, "failed to marshal data: %v", err.Error())
	}
	return data
}

func TestCreateTenant(t *testing.T) {
	handler := admin.NewHandler(tenantTestStore)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	t.Run("creates tenant with name only", func(t *testing.T) {
		// given
		tenantName := "tenant-" + uuid.NewString()
		body := mustMarshal(t, admin.CreateTenantRequest{
			Name: tenantName,
		})

		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+admin.PathTenants, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		// when
		resp, err := http.DefaultClient.Do(req)
		if !assert.NoError(t, err) {
			return
		}
		defer resp.Body.Close()

		// then
		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		var respBody admin.TenantResponse
		err = json.NewDecoder(resp.Body).Decode(&respBody)
		assert.NoError(t, err)
		assert.NotEmpty(t, respBody.ID)
		assert.Equal(t, tenantName, respBody.Name)
		assert.NotZero(t, respBody.CreatedAt)
		assert.NotZero(t, respBody.UpdatedAt)
	})

	t.Run("creates tenant with name and labels", func(t *testing.T) {
		// given
		tenantName := "tenant-" + uuid.NewString()
		body := mustMarshal(t, admin.CreateTenantRequest{
			Name: tenantName,
			Labels: map[string]string{
				"env":  "production",
				"team": "platform",
			},
		})

		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+admin.PathTenants, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		// when
		resp, err := http.DefaultClient.Do(req)
		if !assert.NoError(t, err) {
			return
		}
		defer resp.Body.Close()

		// then
		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		var respBody admin.TenantResponse
		err = json.NewDecoder(resp.Body).Decode(&respBody)
		assert.NoError(t, err)
		assert.NotEmpty(t, respBody.ID)
		assert.Equal(t, tenantName, respBody.Name)
		assert.Equal(t, "production", respBody.Labels["env"])
		assert.Equal(t, "platform", respBody.Labels["team"])
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		// given
		invalidJSON := []byte(`{"name": "test", invalid}`)

		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/admin/tenants", bytes.NewReader(invalidJSON))
		req.Header.Set("Content-Type", "application/json")

		// when
		resp, err := http.DefaultClient.Do(req)
		if !assert.NoError(t, err) {
			return
		}
		defer resp.Body.Close()

		// then
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns 400 for empty body", func(t *testing.T) {
		// given
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+admin.PathTenants, strings.NewReader(""))
		req.Header.Set("Content-Type", "application/json")

		// when
		resp, err := http.DefaultClient.Do(req)
		if !assert.NoError(t, err) {
			return
		}
		defer resp.Body.Close()

		// then
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

func TestGetTenant(t *testing.T) {
	handler := admin.NewHandler(tenantTestStore)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	t.Run("returns tenant by id", func(t *testing.T) {
		// given - create a tenant first
		tenantName := "tenant-" + uuid.NewString()
		createBody := mustMarshal(t, admin.CreateTenantRequest{
			Name: tenantName,
			Labels: map[string]string{
				"env": "test",
			},
		})

		createReq, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+admin.PathTenants, bytes.NewReader(createBody))
		createReq.Header.Set("Content-Type", "application/json")

		createResp, err := http.DefaultClient.Do(createReq)
		if !assert.NoError(t, err) {
			return
		}
		defer createResp.Body.Close()

		var createdTenant admin.TenantResponse
		err = json.NewDecoder(createResp.Body).Decode(&createdTenant)
		if !assert.NoError(t, err) {
			return
		}

		// when
		getReq, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+admin.PathTenants+"/"+createdTenant.ID, nil)

		getResp, err := http.DefaultClient.Do(getReq)
		if !assert.NoError(t, err) {
			return
		}
		defer getResp.Body.Close()

		// then
		assert.Equal(t, http.StatusOK, getResp.StatusCode)

		var gotTenant admin.TenantResponse
		err = json.NewDecoder(getResp.Body).Decode(&gotTenant)
		assert.NoError(t, err)
		assert.Equal(t, createdTenant.ID, gotTenant.ID)
		assert.Equal(t, tenantName, gotTenant.Name)
		assert.Equal(t, "test", gotTenant.Labels["env"])
	})

	t.Run("returns 404 for non-existent tenant", func(t *testing.T) {
		// given
		nonExistentID := uuid.NewString()

		// when
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+admin.PathTenants+"/"+nonExistentID, nil)

		resp, err := http.DefaultClient.Do(req)
		if !assert.NoError(t, err) {
			return
		}
		defer resp.Body.Close()

		// then
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

func TestCreateAndGetTenant(t *testing.T) {
	handler := admin.NewHandler(tenantTestStore)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	// given
	tenantName := "tenant-" + uuid.NewString()
	createBody := mustMarshal(t, admin.CreateTenantRequest{
		Name: tenantName,
		Labels: map[string]string{
			"environment": "staging",
			"region":      "us-west-2",
			"cost-center": "engineering",
		},
	})

	// when - create tenant
	createReq, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/admin/tenants", bytes.NewReader(createBody))
	createReq.Header.Set("Content-Type", "application/json")

	createResp, err := http.DefaultClient.Do(createReq)
	if !assert.NoError(t, err) {
		return
	}
	defer createResp.Body.Close()

	if !assert.Equal(t, http.StatusCreated, createResp.StatusCode) {
		return
	}

	var createdTenant admin.TenantResponse
	err = json.NewDecoder(createResp.Body).Decode(&createdTenant)
	if !assert.NoError(t, err) {
		return
	}

	// when - get tenant
	getReq, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+admin.PathTenants+"/"+createdTenant.ID, nil)

	getResp, err := http.DefaultClient.Do(getReq)
	if !assert.NoError(t, err) {
		return
	}
	defer getResp.Body.Close()

	assert.Equal(t, http.StatusOK, getResp.StatusCode)

	var gotTenant admin.TenantResponse
	err = json.NewDecoder(getResp.Body).Decode(&gotTenant)
	if !assert.NoError(t, err) {
		return
	}

	// then - verify data integrity
	assert.Equal(t, createdTenant.ID, gotTenant.ID)
	assert.Equal(t, createdTenant.Name, gotTenant.Name)
	assert.InDelta(t, createdTenant.CreatedAt, gotTenant.CreatedAt, 0.001)
	assert.InDelta(t, createdTenant.UpdatedAt, gotTenant.UpdatedAt, 0.001)

	// verify labels are preserved correctly
	assert.Equal(t, createdTenant.Labels["environment"], gotTenant.Labels["environment"])
	assert.Equal(t, createdTenant.Labels["region"], gotTenant.Labels["region"])
	assert.Equal(t, createdTenant.Labels["cost-center"], gotTenant.Labels["cost-center"])
}
