package integration

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/pkg/api/admin"
)

func TestCreateTenant(t *testing.T) {
	handler := admin.NewServerMux(tenantTestStore)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	t.Run("creates tenant with name only", func(t *testing.T) {
		// given
		expName := "tenant-" + uuid.NewString()

		// when `kr create tenant --name <name> --server <server-url>`
		cmd := newCLICommand(t.Context(), t.TempDir(), "create", "tenant", "--name", expName, "--server", server.URL)
		output, err := cmd.CombinedOutput()

		// then
		assert.NoError(t, err, "command should succeed, output: %s", string(output))
		resp := decode[admin.CreateTenantResponse](t, output)
		assert.NotEmpty(t, resp.ID)
		assert.Equal(t, expName, resp.Name)
	})

	t.Run("creates tenant with name and labels", func(t *testing.T) {
		// given
		expName := "tenant-" + uuid.NewString()
		expLabels := map[string]string{
			"env":  "production",
			"team": "platform",
		}
		labelArg := strings.Builder{}
		i := 1
		for k, v := range expLabels {
			labelArg.WriteString(k)
			labelArg.WriteString("=")
			labelArg.WriteString(v)
			if i < len(expLabels) {
				labelArg.WriteString(",")
			}
			i++
		}

		// when `kr create tenant --name <name> --label env=production,team=platform --server <server-url>`
		cmd := newCLICommand(t.Context(), t.TempDir(), "create", "tenant", "--name", expName, "--label", labelArg.String(), "--server", server.URL)
		output, err := cmd.CombinedOutput()

		// then
		assert.NoError(t, err, "command should succeed, output: %s", string(output))
		resp := decode[admin.CreateTenantResponse](t, output)
		assert.NotEmpty(t, resp.ID)
		assert.Equal(t, expName, resp.Name)
		assert.Equal(t, expLabels["env"], resp.Labels["env"])
		assert.Equal(t, expLabels["team"], resp.Labels["team"])
	})

	t.Run("fails when server is unavailable", func(t *testing.T) {
		// given
		unknownAddr := "http://localhost:59999"

		// when `kr create tenant --name test --server http://localhost:59999`
		cmd := newCLICommand(t.Context(), t.TempDir(), "create", "tenant", "--name", "test", "--server", unknownAddr)
		output, err := cmd.CombinedOutput()

		// then
		assert.Error(t, err, "command should fail when server is unavailable")
		assert.Contains(t, string(output), "connection refused")
	})
}

func TestGetTenant(t *testing.T) {
	handler := admin.NewServerMux(tenantTestStore)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	t.Run("gets tenant by id", func(t *testing.T) {
		// given - create a tenant first
		tenantName := "tenant-" + uuid.NewString()
		createCmd := newCLICommand(t.Context(), t.TempDir(), "create", "tenant", "--name", tenantName, "--server", server.URL)
		createOutput, err := createCmd.CombinedOutput()
		if !assert.NoError(t, err) {
			return
		}

		createResp := decode[admin.CreateTenantResponse](t, createOutput)

		// when `kr get tenant <tenant-id> --server <server-url>`
		getCmd := newCLICommand(t.Context(), t.TempDir(), "get", "tenant", createResp.ID, "--server", server.URL)
		getOutput, err := getCmd.CombinedOutput()

		// then
		assert.NoError(t, err, "command should succeed, output: %s", string(getOutput))
		getResp := decode[admin.GetTenantResponse](t, getOutput)
		assert.NotEmpty(t, getResp.ID)
		assert.Equal(t, tenantName, getResp.Name)
	})

	t.Run("fails for non-existent tenant", func(t *testing.T) {
		// given
		nonExistentID := uuid.NewString()

		// when `kr get tenant <non-existent-id> --server <server-url>`
		cmd := newCLICommand(t.Context(), t.TempDir(), "get", "tenant", nonExistentID, "--server", server.URL)
		output, err := cmd.CombinedOutput()

		// then
		assert.Error(t, err, "command should fail for non-existent tenant")
		assert.Contains(t, string(output), "not found")
	})

	t.Run("fails without tenant id argument", func(t *testing.T) {
		// when `kr get tenant --server <server-url>` (missing tenant id)
		cmd := newCLICommand(t.Context(), t.TempDir(), "get", "tenant", "--server", server.URL)
		output, err := cmd.CombinedOutput()

		// then
		assert.Error(t, err, "command should fail without tenant id")
		assert.Contains(t, string(output), "accepts 1 arg")
	})
}

func decode[T any](t *testing.T, output []byte) T {
	t.Helper()
	var result T
	err := json.Unmarshal(output, &result)
	if err != nil {
		assert.FailNowf(t, "failed to decode response", "output: %s, error: %v", string(output), err)
	}
	return result
}
