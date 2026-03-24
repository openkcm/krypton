package integration

import (
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/cli/output"
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
		out, err := cmd.CombinedOutput()

		// then
		assert.NoError(t, err, "command should succeed, output: %s", string(out))
		table := output.ParseTable(out)
		assert.Equal(t, output.TenantTable{}.Header(), table.Header)
		rows := table.Rows
		assert.Len(t, rows, 1)
		assert.NotEmpty(t, rows[0]["ID"])
		assert.Equal(t, expName, rows[0]["NAME"])
		assert.Equal(t, "<none>", rows[0]["LABELS"])
		assert.NotEmpty(t, rows[0]["CREATED"])
		assert.NotEmpty(t, rows[0]["UPDATED"])
	})

	t.Run("creates tenant with name and labels", func(t *testing.T) {
		// given
		expName := "tenant-" + uuid.NewString()
		expLabels := "env=production"

		// when `kr create tenant --name <name> --label env=production,team=platform --server <server-url>`
		cmd := newCLICommand(t.Context(), t.TempDir(), "create", "tenant", "--name", expName, "--label", expLabels, "--server", server.URL)
		out, err := cmd.CombinedOutput()

		// then
		assert.NoError(t, err, "command should succeed, output: %s", string(out))
		table := output.ParseTable(out)
		assert.Equal(t, output.TenantTable{}.Header(), table.Header)
		rows := table.Rows
		assert.Len(t, rows, 1)
		assert.NotEmpty(t, rows[0]["ID"])
		assert.Equal(t, expName, rows[0]["NAME"])
		assert.Equal(t, expLabels, rows[0]["LABELS"])
	})

	t.Run("fails when server is unavailable", func(t *testing.T) {
		// given
		unknownAddr := "http://localhost:59999"

		// when `kr create tenant --name test --server http://localhost:59999`
		cmd := newCLICommand(t.Context(), t.TempDir(), "create", "tenant", "--name", "test", "--server", unknownAddr)
		out, err := cmd.CombinedOutput()

		// then
		assert.Error(t, err, "command should fail when server is unavailable")
		assert.Contains(t, string(out), "connection refused")
	})
}

func TestGetTenant(t *testing.T) {
	handler := admin.NewServerMux(tenantTestStore)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	t.Run("gets tenant by id", func(t *testing.T) {
		// given - create a tenant first
		expName := "tenant-" + uuid.NewString()
		createCmd := newCLICommand(t.Context(), t.TempDir(), "create", "tenant", "--name", expName, "--server", server.URL)
		createOutput, err := createCmd.CombinedOutput()
		if !assert.NoError(t, err) {
			return
		}

		createTable := output.ParseTable(createOutput)
		assert.Len(t, createTable.Rows, 1)
		expID := createTable.Rows[0]["ID"]
		assert.NotEmpty(t, expID)

		// when `kr get tenant <tenant-id> --server <server-url>`
		getCmd := newCLICommand(t.Context(), t.TempDir(), "get", "tenant", expID, "--server", server.URL)
		out, err := getCmd.CombinedOutput()

		// then
		assert.NoError(t, err, "command should succeed, output: %s", string(out))
		table := output.ParseTable(out)
		assert.Equal(t, output.TenantTable{}.Header(), table.Header)
		rows := table.Rows
		assert.Len(t, rows, 1)
		assert.Equal(t, expID, rows[0]["ID"])
		assert.Equal(t, expName, rows[0]["NAME"])
	})

	t.Run("fails for non-existent tenant", func(t *testing.T) {
		// given
		nonExistentID := uuid.NewString()

		// when `kr get tenant <non-existent-id> --server <server-url>`
		cmd := newCLICommand(t.Context(), t.TempDir(), "get", "tenant", nonExistentID, "--server", server.URL)
		out, err := cmd.CombinedOutput()

		// then
		assert.Error(t, err, "command should fail for non-existent tenant")
		assert.Contains(t, string(out), "not found")
	})

	t.Run("fails without tenant id argument", func(t *testing.T) {
		// when `kr get tenant --server <server-url>` (missing tenant id)
		cmd := newCLICommand(t.Context(), t.TempDir(), "get", "tenant", "--server", server.URL)
		out, err := cmd.CombinedOutput()

		// then
		assert.Error(t, err, "command should fail without tenant id")
		assert.Contains(t, string(out), "accepts 1 arg")
	})
}
