package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"

	"github.com/openkcm/krypton/cli/state"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin"
)

// expTenant represents the JSON structure returned by the CLI's tenant commands.
type expTenant struct {
	ID        string            `json:"ID"`
	Name      string            `json:"Name"`
	Labels    map[string]string `json:"Labels,omitempty"`
	CreatedAt string            `json:"CreatedAt"`
	UpdatedAt string            `json:"UpdatedAt"`
}

func TestCreateTenant(t *testing.T) {
	tenantStore := newTenantStore(t, nil)
	serverAddr := startGRPCServer(t, func(srv *grpc.Server) {
		admin.RegisterTenantServiceServer(srv, admin.NewTenantService(tenantStore))
	})

	t.Run("creates tenant with name only", func(t *testing.T) {
		// given
		expName := "tenant-" + uuid.NewString()

		// when `kr create tenant --name <name> --json --server <server-addr>`
		cmd := newCLICommand(t.Context(), t.TempDir(), "create", "tenant", "--name", expName, "--json", "--server", serverAddr)
		output, err := cmd.CombinedOutput()

		// then
		assert.NoError(t, err, "command should succeed, output: %s", string(output))
		tenants := decode(t, output)
		if !assert.Len(t, tenants, 1) {
			return
		}
		assert.NotEmpty(t, tenants[0].ID)
		assert.Equal(t, expName, tenants[0].Name)
		assert.Empty(t, tenants[0].Labels)
		assert.NotEmpty(t, tenants[0].CreatedAt)
		assert.NotEmpty(t, tenants[0].UpdatedAt)
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

		// when `kr create tenant --name <name> --label env=production,team=platform --json --server <server-addr>`
		cmd := newCLICommand(t.Context(), t.TempDir(), "create", "tenant", "--name", expName, "--label", labelArg.String(), "--json", "--server", serverAddr)
		output, err := cmd.CombinedOutput()

		// then
		assert.NoError(t, err, "command should succeed, output: %s", string(output))
		tenants := decode(t, output)
		if !assert.Len(t, tenants, 1) {
			return
		}
		assert.NotEmpty(t, tenants[0].ID)
		assert.Equal(t, expName, tenants[0].Name)
		assert.Equal(t, expLabels["env"], tenants[0].Labels["env"])
		assert.Equal(t, expLabels["team"], tenants[0].Labels["team"])
		assert.NotEmpty(t, tenants[0].CreatedAt)
		assert.NotEmpty(t, tenants[0].UpdatedAt)
	})

	t.Run("fails when server is unavailable", func(t *testing.T) {
		// given
		unknownAddr := "localhost:59999"

		// when `kr create tenant --name test --server localhost:59999`
		cmd := newCLICommand(t.Context(), t.TempDir(), "create", "tenant", "--name", "test", "--server", unknownAddr)
		output, err := cmd.CombinedOutput()

		// then
		assert.Error(t, err, "command should fail when server is unavailable")
		assert.Contains(t, string(output), "connection")
	})
}

func TestGetTenant(t *testing.T) {
	tenantStore := newTenantStore(t, nil)
	serverAddr := startGRPCServer(t, func(srv *grpc.Server) {
		admin.RegisterTenantServiceServer(srv, admin.NewTenantService(tenantStore))
	})

	t.Run("gets tenant by id", func(t *testing.T) {
		// given - create a tenant first
		tenantName := "tenant-" + uuid.NewString()
		createCmd := newCLICommand(t.Context(), t.TempDir(), "create", "tenant", "--name", tenantName, "--json", "--server", serverAddr)
		createOutput, err := createCmd.CombinedOutput()
		if !assert.NoError(t, err) {
			return
		}

		tenants := decode(t, createOutput)
		if !assert.Len(t, tenants, 1) {
			return
		}

		// when `kr get tenant <tenant-id> --json --server <server-addr>`
		getCmd := newCLICommand(t.Context(), t.TempDir(), "get", "tenant", tenants[0].ID, "--json", "--server", serverAddr)
		getOutput, err := getCmd.CombinedOutput()

		// then
		assert.NoError(t, err, "command should succeed, output: %s", string(getOutput))
		tenants = decode(t, getOutput)
		if !assert.Len(t, tenants, 1) {
			return
		}
		assert.NotEmpty(t, tenants[0].ID)
		assert.Equal(t, tenantName, tenants[0].Name)
	})

	t.Run("fails for non-existent tenant", func(t *testing.T) {
		// given
		nonExistentID := uuid.NewString()

		// when `kr get tenant <non-existent-id> --server <server-addr>`
		cmd := newCLICommand(t.Context(), t.TempDir(), "get", "tenant", nonExistentID, "--server", serverAddr)
		output, err := cmd.CombinedOutput()

		// then
		assert.Error(t, err, "command should fail for non-existent tenant")
		assert.Contains(t, string(output), "not found")
	})

	t.Run("fails without tenant id argument", func(t *testing.T) {
		// when `kr get tenant --server <server-addr>` (missing tenant id)
		cmd := newCLICommand(t.Context(), t.TempDir(), "get", "tenant", "--server", serverAddr)
		output, err := cmd.CombinedOutput()

		// then
		assert.Error(t, err, "command should fail without tenant id")
		assert.Contains(t, string(output), "accepts 1 arg")
	})
}

func TestListTenants(t *testing.T) {
	t.Run("returns empty list when no tenants exist", func(t *testing.T) {
		// given
		tenantStore := newTenantStore(t, nil)
		serverAddr := startGRPCServer(t, func(srv *grpc.Server) {
			admin.RegisterTenantServiceServer(srv, admin.NewTenantService(tenantStore))
		})

		// when `kr get tenants --json --server <server-addr>`
		cmd := newCLICommand(t.Context(), t.TempDir(), "get", "tenants", "--json", "--server", serverAddr)
		output, err := cmd.CombinedOutput()

		// then
		assert.NoError(t, err, "command should succeed, output: %s", string(output))
		tenants := decode(t, output)
		assert.Empty(t, tenants)
	})

	t.Run("lists created tenants", func(t *testing.T) {
		// given
		tenantStore := newTenantStore(t, nil)
		serverAddr := startGRPCServer(t, func(srv *grpc.Server) {
			admin.RegisterTenantServiceServer(srv, admin.NewTenantService(tenantStore))
		})

		tenant1Name := "tenant-" + uuid.NewString()
		tenant2Name := "tenant-" + uuid.NewString()

		createCmd1 := newCLICommand(t.Context(), t.TempDir(), "create", "tenant", "--name", tenant1Name, "--json", "--server", serverAddr)
		_, err := createCmd1.CombinedOutput()
		assert.NoError(t, err)

		createCmd2 := newCLICommand(t.Context(), t.TempDir(), "create", "tenant", "--name", tenant2Name, "--json", "--server", serverAddr)
		_, err = createCmd2.CombinedOutput()
		assert.NoError(t, err)

		// when `kr get tenants --json --server <server-addr>`
		getCmd := newCLICommand(t.Context(), t.TempDir(), "get", "tenants", "--json", "--server", serverAddr)
		output, err := getCmd.CombinedOutput()

		// then
		assert.NoError(t, err, "command should succeed, output: %s", string(output))
		tenants := decode(t, output)
		assert.Len(t, tenants, 2)

		actTenantNames := map[string]struct{}{}
		for _, tenant := range tenants {
			actTenantNames[tenant.Name] = struct{}{}
		}
		for _, tenantName := range []string{tenant1Name, tenant2Name} {
			_, found := actTenantNames[tenantName]
			assert.True(t, found)
		}
	})
}

// TestSelectTenant tests the `kr select tenant` command.
//
// Note: Interactive mode (-i flag) cannot be tested here because the terminal selector
// requires a real TTY (it checks term.IsTerminal and uses term.MakeRaw for raw mode).
// Integration tests use exec.Command which provides piped stdin, not a real TTY.
// Interactive selection is covered by unit tests in cli/output/terminal/.
func TestSelectTenant(t *testing.T) {
	tenantStore := newTenantStore(t, nil)
	serverAddr := startGRPCServer(t, func(srv *grpc.Server) {
		admin.RegisterTenantServiceServer(srv, admin.NewTenantService(tenantStore))
	})

	t.Run("selects tenant by ID and persists config", func(t *testing.T) {
		// given
		homeDir := t.TempDir()
		tenantName := "tenant-" + uuid.NewString()
		createCmd := newCLICommand(t.Context(), homeDir, "create", "tenant", "--name", tenantName, "--json", "--server", serverAddr)
		createOutput, err := createCmd.CombinedOutput()
		assert.NoError(t, err)
		tenants := decode(t, createOutput)

		// when `kr select tenant <tenant-id> --server <server-addr>`
		selectCmd := newCLICommand(t.Context(), homeDir, "select", "tenant", tenants[0].ID, "--server", serverAddr)
		selectOutput, err := selectCmd.CombinedOutput()

		// then
		assert.NoError(t, err, "command should succeed, output: %s", string(selectOutput))
		assert.Contains(t, string(selectOutput), "Selected tenant:")
		assert.Contains(t, string(selectOutput), tenantName)

		// and state file was created with correct content
		statePath := filepath.Join(homeDir, ".krypton", "state.lock")
		stateData, err := os.ReadFile(statePath)
		assert.NoError(t, err)

		var st state.State
		err = json.Unmarshal(stateData, &st)
		assert.NoError(t, err)
		assert.NotNil(t, st.Tenant)
		assert.Equal(t, tenants[0].ID, st.Tenant.ID)
		assert.Equal(t, tenantName, st.Tenant.Name)
	})

	t.Run("fails for non-existent tenant", func(t *testing.T) {
		// when `kr select tenant <non-existent-id> --server <server-addr>`
		cmd := newCLICommand(t.Context(), t.TempDir(), "select", "tenant", uuid.NewString(), "--server", serverAddr)
		output, err := cmd.CombinedOutput()

		// then
		assert.Error(t, err)
		assert.Contains(t, string(output), "not found")
	})

	t.Run("fails when both ID and interactive flag provided", func(t *testing.T) {
		// when `kr select tenant <id> -i --server <server-addr>`
		cmd := newCLICommand(t.Context(), t.TempDir(), "select", "tenant", "some-id", "-i", "--server", serverAddr)
		output, err := cmd.CombinedOutput()

		// then
		assert.Error(t, err)
		assert.Contains(t, string(output), "cannot use both")
	})

	t.Run("fails when no ID and not interactive", func(t *testing.T) {
		// when `kr select tenant --server <server-addr>`
		cmd := newCLICommand(t.Context(), t.TempDir(), "select", "tenant", "--server", serverAddr)
		output, err := cmd.CombinedOutput()

		// then
		assert.Error(t, err)
		assert.Contains(t, string(output), "tenant ID required")
	})
}

func decode(t *testing.T, output []byte) []expTenant {
	t.Helper()
	var ts []expTenant
	err := json.Unmarshal(output, &ts)
	if err != nil {
		assert.FailNowf(t, "failed to decode response", "output: %s, error: %v", string(output), err)
	}
	return ts
}
