package integration

import (
	"encoding/json/v2"
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin"
	keypb "github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	"github.com/openkcm/krypton/pkg/validator"
)

func TestGetKeys(t *testing.T) {
	// given
	testDB, _ := createDatabase(t)
	tenantStore := newTenantStore(t, testDB)
	keyStore := newKeyStore(t, testDB)
	keyVersionStore := newKeyVersionStore(t, testDB)

	hierarchySpec := defaultTestHierarchy()
	topology := spec.Topology{
		Segments: []spec.TopologySegment{
			{Name: "root", Segment: spec.HierarchySegment{StartKind: "K0", EndKind: "K0"}},
			{Name: "agent", Segment: spec.HierarchySegment{StartKind: "K1", EndKind: "K3"}},
		},
	}
	rootSegment := spec.HierarchySegment{StartKind: "K0", EndKind: "K0"}
	keyValidator := validator.NewValidator(rootSegment, topology, hierarchySpec, tenantStore, keyStore)

	serverAddr := startGRPCServer(t, func(srv *grpc.Server) {
		admin.RegisterTenantServiceServer(srv, admin.NewTenantService(tenantStore))
		keypb.RegisterKeyServiceServer(srv, keypb.NewKeyService("root", newTransactor(t, testDB), keyStore, keyVersionStore, keyValidator, &noopJobPreparer{}, nil))
	})

	// login with no auth
	homeDir := t.TempDir()
	loginNoAuth(t, homeDir)

	// create tenant
	expTenantName := "tenant-" + uuid.New().String()
	cmd := newCLICommand(
		t.Context(),
		homeDir,
		"create",
		"tenant",
		"--name", expTenantName,
		"--json",
		"--server", serverAddr,
	)
	output, err := cmd.CombinedOutput()
	assert.NoError(t, err, "command should succeed, output: %s", string(output))

	tenants := decode(t, output)
	if !assert.Len(t, tenants, 1) {
		return
	}
	tenantID := tenants[0].ID

	// create hierarchy
	hierarchy := createKeyHierarchy(t, keyStore, tenantID)

	t.Run("key", func(t *testing.T) {
		t.Run("should get key for tenant and a key ID", func(t *testing.T) {
			// when
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"key",
				"--tenant-id", tenantID,
				"--key-id", hierarchy.e.ID,
				"--json",
				"--server", serverAddr)

			output, err = cmd.CombinedOutput()

			// then
			assert.NoError(t, err, "command should succeed, output: %s", string(output))

			actKeys := decodeKeys(t, output)
			require.Len(t, actKeys, 1)
			assert.Equal(t, hierarchy.e.Name, actKeys[0].Name)
			assert.Equal(t, tenantID, actKeys[0].TenantID)
			assert.Equal(t, hierarchy.e.Kind, actKeys[0].Kind)
			assert.Equal(t, hierarchy.e.ParentID, actKeys[0].ParentID)
			assert.Equal(t, "agent-azure", actKeys[0].ManagedBy)
			assert.Empty(t, actKeys[0].Labels)
			assert.Equal(t, model.KeyLifeCycleActive, actKeys[0].LifeCycleState)
			assert.Equal(t, model.KeyProcessingPending, actKeys[0].KeyProcessingState.Status)
			assert.Empty(t, actKeys[0].KeyProcessingState.JobID)
			assert.NotEmpty(t, actKeys[0].UpdatedAt)
			assert.NotEmpty(t, actKeys[0].CreatedAt)
		})

		t.Run("should fail if key does not exist", func(t *testing.T) {
			// when
			unknownKeyID := uuid.New().String()
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"key",
				"--tenant-id", tenantID,
				"--key-id", unknownKeyID,
				"--json",
				"--server", serverAddr)

			output, err = cmd.CombinedOutput()

			// then
			assert.Error(t, err, "command should fail, output: %s", string(output))
			assert.Contains(t, string(output), "not found")
		})

		t.Run("should fail if key ID parameter is not provided", func(t *testing.T) {
			// when
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"key",
				"--tenant-id", tenantID,
				"--json",
				"--server", serverAddr)

			output, err = cmd.CombinedOutput()

			// then
			assert.Error(t, err, "command should fail, output: %s", string(output))
			assert.Contains(t, string(output), "required flag(s) \"key-id\" not set")
		})

		t.Run("should fail if tenant does not exist", func(t *testing.T) {
			// when
			unknownTenantID := uuid.New().String()
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"key",
				"--tenant-id", unknownTenantID,
				"--key-id", hierarchy.e.ID,
				"--json",
				"--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.Error(t, err)
			assert.Contains(t, string(output), "not found")
		})

		t.Run("should fall back to selected tenant when tenant-id is not provided", func(t *testing.T) {
			//given
			// create selected tenant in store to test fetching tenant id from store when not provided as parameter
			tmpDir := homeDir
			seedSelectedTenant(t, tmpDir, tenantID, expTenantName)

			// when
			cmd = newCLICommand(
				t.Context(),
				tmpDir,
				"get",
				"key",
				"--key-id", hierarchy.h.ID,
				"--json",
				"--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.NoError(t, err, "command should succeed, output: %s", string(output))

			actKeys := decodeKeys(t, output)
			require.Len(t, actKeys, 1)
			assert.Equal(t, hierarchy.h.Name, actKeys[0].Name)
			assert.Equal(t, tenantID, actKeys[0].TenantID)
		})

		t.Run("should fail if tenant id parameter is not provided", func(t *testing.T) {
			//given
			// login with no auth
			homeDir := t.TempDir()
			loginNoAuth(t, homeDir)

			// when
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"key",
				"--key-id", hierarchy.e.ID,
				"--json",
				"--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.Error(t, err)
			assert.Contains(t, string(output), "no tenant selected")
		})
	})

	t.Run("parent-keys", func(t *testing.T) {
		t.Run("should get all parent keys", func(t *testing.T) {
			// when
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"parent-keys",
				"--key-id", hierarchy.e.ID,
				"--tenant-id", tenantID,
				"--json",
				"--server", serverAddr,
			)
			output, err = cmd.CombinedOutput()

			// then
			assert.NoError(t, err, "command should succeed, output: %s", string(output))

			actRes := decodeKeyRow(t, output)
			assert.Len(t, actRes, 3)
			assert.Equal(t, "A", actRes[0].Name)
			assert.Equal(t, hierarchy.root.Kind, actRes[0].Kind)

			assert.Equal(t, "B", actRes[1].Name)
			assert.Equal(t, hierarchy.b.Kind, actRes[1].Kind)

			assert.Equal(t, "E", actRes[2].Name)
			assert.Equal(t, hierarchy.e.Kind, actRes[2].Kind)
		})

		t.Run("should fall back to selected tenant when tenant-id is not provided", func(t *testing.T) {
			//given
			// create selected tenant in store to test fetching tenant id from store when not provided as parameter
			tmpDir := homeDir
			seedSelectedTenant(t, tmpDir, tenantID, expTenantName)

			// when
			cmd = newCLICommand(
				t.Context(),
				tmpDir,
				"get",
				"parent-keys",
				"--key-id", hierarchy.e.ID,
				"--json",
				"--server", serverAddr,
			)
			output, err = cmd.CombinedOutput()

			// then
			assert.NoError(t, err, "command should succeed, output: %s", string(output))

			actRes := decodeKeyRow(t, output)
			assert.Len(t, actRes, 3)
			assert.Equal(t, "A", actRes[0].Name)
			assert.Equal(t, hierarchy.root.Kind, actRes[0].Kind)
		})

		t.Run("should fail if no parent keys exist", func(t *testing.T) {
			// when
			unknownID := uuid.New().String()
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"parent-keys",
				"--key-id", unknownID,
				"--tenant-id", tenantID,
				"--server", serverAddr,
			)
			output, err = cmd.CombinedOutput()

			// then
			assert.Error(t, err)
			assert.Contains(t, string(output), "not found")
		})

		t.Run("should fail if tenant does not exist", func(t *testing.T) {
			// when
			unknownTenantID := uuid.New().String()
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"parent-keys",
				"--key-id", hierarchy.e.ID,
				"--tenant-id", unknownTenantID,
				"--server", serverAddr,
			)
			output, err = cmd.CombinedOutput()

			// then
			assert.Error(t, err)
			assert.Contains(t, string(output), "not found")
		})

		t.Run("should fail if key id parameter is not provided", func(t *testing.T) {
			// when
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"parent-keys",
				"--tenant-id", tenantID,
				"--server", serverAddr,
			)
			output, err = cmd.CombinedOutput()

			// then
			assert.Error(t, err)
			assert.Contains(t, string(output), "required flag(s) \"key-id\" not set")
		})

		t.Run("should fail if tenant id parameter is not provided", func(t *testing.T) {
			//given
			// login with no auth
			homeDir := t.TempDir()
			loginNoAuth(t, homeDir)

			// when
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"parent-keys",
				"--key-id", hierarchy.e.ID,
				"--server", serverAddr,
			)
			output, err = cmd.CombinedOutput()

			// then
			assert.Error(t, err)
			assert.Contains(t, string(output), "failed to get selected tenant: no tenant selected")
		})
	})

	t.Run("descendant-keys", func(t *testing.T) {
		t.Run("should get all descendant keys", func(t *testing.T) {
			// when
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"descendant-keys",
				"--key-id", hierarchy.root.ID,
				"--tenant-id", tenantID,
				"--json",
				"--server", serverAddr,
			)
			output, err = cmd.CombinedOutput()

			// then
			assert.NoError(t, err, "command should succeed, output: %s", string(output))

			actRes := decodeKeyRow(t, output)
			assert.Len(t, actRes, 8)

			assert.Equal(t, "A", actRes[0].Name)
			assert.Equal(t, hierarchy.root.Kind, actRes[0].Kind)

			assert.Equal(t, "B", actRes[1].Name)
			assert.Equal(t, hierarchy.b.Kind, actRes[1].Kind)
			assert.Equal(t, "C", actRes[2].Name)
			assert.Equal(t, hierarchy.c.Kind, actRes[2].Kind)

			assert.Equal(t, "D", actRes[3].Name)
			assert.Equal(t, hierarchy.d.Kind, actRes[3].Kind)
			assert.Equal(t, "E", actRes[4].Name)
			assert.Equal(t, hierarchy.e.Kind, actRes[4].Kind)
			assert.Equal(t, "F", actRes[5].Name)
			assert.Equal(t, hierarchy.f.Kind, actRes[5].Kind)
			assert.Equal(t, "G", actRes[6].Name)
			assert.Equal(t, hierarchy.g.Kind, actRes[6].Kind)

			assert.Equal(t, "H", actRes[7].Name)
			assert.Equal(t, hierarchy.h.Kind, actRes[7].Kind)
		})

		t.Run("should fall back to selected tenant when tenant-id is not provided", func(t *testing.T) {
			//given
			// create selected tenant in store to test fetching tenant id from store when not provided as parameter
			tmpDir := homeDir
			seedSelectedTenant(t, tmpDir, tenantID, expTenantName)

			// when
			cmd = newCLICommand(
				t.Context(),
				tmpDir,
				"get",
				"descendant-keys",
				"--key-id", hierarchy.root.ID,
				"--json",
				"--server", serverAddr,
			)
			output, err = cmd.CombinedOutput()

			// then
			assert.NoError(t, err, "command should succeed, output: %s", string(output))

			actRes := decodeKeyRow(t, output)
			assert.Len(t, actRes, 8)

			assert.Equal(t, "A", actRes[0].Name)
			assert.Equal(t, hierarchy.root.Kind, actRes[0].Kind)
		})

		t.Run("should fail if no descendant keys exist", func(t *testing.T) {
			// when
			unknownID := uuid.New().String()
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"descendant-keys",
				"--key-id", unknownID,
				"--tenant-id", tenantID,
				"--server", serverAddr,
			)
			output, err = cmd.CombinedOutput()

			// then
			assert.Error(t, err)
			assert.Contains(t, string(output), "not found")
		})

		t.Run("should fail if tenant does not exist", func(t *testing.T) {
			// when
			unknownTenantID := uuid.New().String()
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"descendant-keys",
				"--key-id", hierarchy.e.ID,
				"--tenant-id", unknownTenantID,
				"--server", serverAddr,
			)
			output, err = cmd.CombinedOutput()

			// then
			assert.Error(t, err)
			assert.Contains(t, string(output), "not found")
		})

		t.Run("should fail if key id parameter is not provided", func(t *testing.T) {
			// when
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"descendant-keys",
				"--tenant-id", tenantID,
				"--server", serverAddr,
			)
			output, err = cmd.CombinedOutput()

			// then
			assert.Error(t, err)
			assert.Contains(t, string(output), "required flag(s) \"key-id\" not set")
		})

		t.Run("should fail if tenant id parameter is not provided", func(t *testing.T) {
			//given
			// login with no auth
			homeDir := t.TempDir()
			loginNoAuth(t, homeDir)

			// when
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"descendant-keys",
				"--key-id", hierarchy.e.ID,
				"--server", serverAddr,
			)
			output, err = cmd.CombinedOutput()

			// then
			assert.Error(t, err)
			assert.Contains(t, string(output), "failed to get selected tenant: no tenant selected")
		})
	})

	t.Run("keys", func(t *testing.T) {
		t.Run("should get all keys for tenant descending order", func(t *testing.T) {
			// when
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"keys",
				"--tenant-id", tenantID,
				"--json",
				"--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.NoError(t, err, "command should succeed, output: %s", string(output))

			actKeyRows := decodeKeyRows(t, output)
			require.Len(t, actKeyRows, 1, "expected one page of results")

			actKeys := actKeyRows[0].Keys
			require.Len(t, actKeys, 8)

			assert.Equal(t, "H", actKeys[0].Name)
			assert.Equal(t, hierarchy.h.Kind, actKeys[0].Kind)

			assert.Equal(t, "G", actKeys[1].Name)
			assert.Equal(t, hierarchy.g.Kind, actKeys[1].Kind)

			assert.Equal(t, "F", actKeys[2].Name)
			assert.Equal(t, hierarchy.f.Kind, actKeys[2].Kind)

			assert.Equal(t, "E", actKeys[3].Name)
			assert.Equal(t, hierarchy.e.Kind, actKeys[3].Kind)

			assert.Equal(t, "D", actKeys[4].Name)
			assert.Equal(t, hierarchy.d.Kind, actKeys[4].Kind)

			assert.Equal(t, "C", actKeys[5].Name)
			assert.Equal(t, hierarchy.c.Kind, actKeys[5].Kind)

			assert.Equal(t, "B", actKeys[6].Name)
			assert.Equal(t, hierarchy.b.Kind, actKeys[6].Kind)

			assert.Equal(t, "A", actKeys[7].Name)
			assert.Equal(t, hierarchy.root.Kind, actKeys[7].Kind)
		})

		t.Run("should get all keys for tenant ascending order", func(t *testing.T) {
			// when
			cmd = newCLICommand(t.Context(),
				homeDir,
				"get",
				"keys",
				"--tenant-id", tenantID,
				"--order", "asc",
				"--json",
				"--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.NoError(t, err, "command should succeed, output: %s", string(output))

			actKeyRows := decodeKeyRows(t, output)
			require.Len(t, actKeyRows, 1, "expected one page of results")

			actKeys := actKeyRows[0].Keys
			require.Len(t, actKeys, 8)

			assert.Equal(t, "A", actKeys[0].Name)
			assert.Equal(t, hierarchy.root.Kind, actKeys[0].Kind)

			assert.Equal(t, "B", actKeys[1].Name)
			assert.Equal(t, hierarchy.b.Kind, actKeys[1].Kind)

			assert.Equal(t, "C", actKeys[2].Name)
			assert.Equal(t, hierarchy.c.Kind, actKeys[2].Kind)

			assert.Equal(t, "D", actKeys[3].Name)
			assert.Equal(t, hierarchy.d.Kind, actKeys[3].Kind)

			assert.Equal(t, "E", actKeys[4].Name)
			assert.Equal(t, hierarchy.e.Kind, actKeys[4].Kind)

			assert.Equal(t, "F", actKeys[5].Name)
			assert.Equal(t, hierarchy.f.Kind, actKeys[5].Kind)

			assert.Equal(t, "G", actKeys[6].Name)
			assert.Equal(t, hierarchy.g.Kind, actKeys[6].Kind)

			assert.Equal(t, "H", actKeys[7].Name)
			assert.Equal(t, hierarchy.h.Kind, actKeys[7].Kind)
		})

		t.Run("should fall back to selected tenant when tenant-id is not provided", func(t *testing.T) {
			//given
			// create selected tenant in store to test fetching tenant id from store when not provided as parameter
			tmpDir := homeDir
			seedSelectedTenant(t, tmpDir, tenantID, expTenantName)

			// when
			cmd = newCLICommand(
				t.Context(),
				tmpDir,
				"get",
				"keys",
				"--json",
				"--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.NoError(t, err, "command should succeed, output: %s", string(output))

			actKeyRows := decodeKeyRows(t, output)
			require.Len(t, actKeyRows, 1, "expected one page of results")

			actKeys := actKeyRows[0].Keys
			require.Len(t, actKeys, 8)
			assert.Equal(t, "H", actKeys[0].Name)
			assert.Equal(t, hierarchy.h.Kind, actKeys[0].Kind)
		})

		t.Run("should fail if tenant does not exist", func(t *testing.T) {
			// when
			unknownTenantID := uuid.New().String()
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"keys",
				"--tenant-id", unknownTenantID,
				"--json",
				"--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.Error(t, err)
			assert.Contains(t, string(output), "not found")
		})

		t.Run("should fail if tenant id parameter is not provided", func(t *testing.T) {
			//given
			// login with no auth
			homeDir := t.TempDir()
			loginNoAuth(t, homeDir)

			// when
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"keys",
				"--json",
				"--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.Error(t, err)
			assert.Contains(t, string(output), "no tenant selected")
		})

		t.Run("should filter by name", func(t *testing.T) {
			// when
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"keys",
				"--tenant-id", tenantID,
				"--name", "B",
				"--json",
				"--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.NoError(t, err, "command should succeed, output: %s", string(output))

			actKeyRows := decodeKeyRows(t, output)
			require.Len(t, actKeyRows, 1, "expected one page of results")

			actKeys := actKeyRows[0].Keys
			require.Len(t, actKeys, 1)
			assert.Equal(t, "B", actKeys[0].Name)
			assert.Equal(t, hierarchy.b.Kind, actKeys[0].Kind)
		})

		t.Run("should filter by kind", func(t *testing.T) {
			// when
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"keys",
				"--tenant-id", tenantID,
				"--kind", "K2",
				"--json",
				"--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.NoError(t, err, "command should succeed, output: %s", string(output))

			actKeyRows := decodeKeyRows(t, output)
			require.Len(t, actKeyRows, 1, "expected one page of results")

			actKeys := actKeyRows[0].Keys
			require.Len(t, actKeys, 4)
			expectedNames := []string{"G", "F", "E", "D"}
			for i, expectedName := range expectedNames {
				assert.Equal(t, expectedName, actKeys[i].Name)
				assert.Equal(t, model.KeyKind("K2"), actKeys[i].Kind)
			}
		})

		t.Run("should filter by life cycle state", func(t *testing.T) {
			// when
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"keys",
				"--tenant-id", tenantID,
				"--lifecycle-state", string(model.KeyLifeCycleActive),
				"--json",
				"--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.NoError(t, err, "command should succeed, output: %s", string(output))

			actKeyRows := decodeKeyRows(t, output)
			require.Len(t, actKeyRows, 1, "expected one page of results")

			actKeys := actKeyRows[0].Keys
			require.Len(t, actKeys, 1)
			assert.Equal(t, "E", actKeys[0].Name)
			assert.Equal(t, model.KeyLifeCycleActive, actKeys[0].LifeCycleState)
		})

		t.Run("should filter by managed-by", func(t *testing.T) {
			// when
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"keys",
				"--tenant-id", tenantID,
				"--managed-by", "agent-azure",
				"--json",
				"--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.NoError(t, err, "command should succeed, output: %s", string(output))

			actKeyRows := decodeKeyRows(t, output)
			require.Len(t, actKeyRows, 1, "expected one page of results")

			actKeys := actKeyRows[0].Keys
			require.Len(t, actKeys, 1)
			assert.Equal(t, "E", actKeys[0].Name)
			assert.Equal(t, "agent-azure", actKeys[0].ManagedBy)
		})

		t.Run("should filter by labels", func(t *testing.T) {
			// when
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"keys",
				"--tenant-id", tenantID,
				"--labels", "env=prod",
				"--json",
				"--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.NoError(t, err, "command should succeed, output: %s", string(output))

			actKeyRows := decodeKeyRows(t, output)
			require.Len(t, actKeyRows, 1, "expected one page of results")

			actKeys := actKeyRows[0].Keys
			require.Len(t, actKeys, 1)
			assert.Equal(t, "C", actKeys[0].Name)
			assert.Equal(t, model.Labels{"env": "prod"}, actKeys[0].Labels)
		})

		t.Run("should limit number of results", func(t *testing.T) {
			// when
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"keys",
				"--tenant-id", tenantID,
				"--limit", "3",
				"--json",
				"--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.NoError(t, err, "command should succeed, output: %s", string(output))

			actKeyRows := decodeKeyRows(t, output)
			require.Len(t, actKeyRows, 1, "expected one page of results")

			actKeys := actKeyRows[0].Keys
			require.Len(t, actKeys, 3)
			assert.Equal(t, "H", actKeys[0].Name)
			assert.Equal(t, "G", actKeys[1].Name)
			assert.Equal(t, "F", actKeys[2].Name)
		})

		t.Run("should fetch next page by cursor", func(t *testing.T) {
			// given
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"keys",
				"--tenant-id", tenantID,
				"--limit", "3",
				"--json",
				"--server", serverAddr)
			output, err = cmd.CombinedOutput()
			assert.NoError(t, err, "command should succeed, output: %s", string(output))

			actKeyRows := decodeKeyRows(t, output)
			require.Len(t, actKeyRows, 1, "expected one page of results")

			actKeys := actKeyRows[0].Keys
			require.Len(t, actKeys, 3)
			assert.Equal(t, "H", actKeys[0].Name)
			assert.Equal(t, "G", actKeys[1].Name)
			assert.Equal(t, "F", actKeys[2].Name)

			cursor := actKeyRows[0].Cursor

			// when
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"keys",
				"--tenant-id", tenantID,
				"--limit", "3",
				"--cursor", cursor,
				"--json",
				"--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.NoError(t, err, "command should succeed, output: %s", string(output))

			actKeyRows = decodeKeyRows(t, output)
			require.Len(t, actKeyRows, 1, "expected one page of results")

			actKeys = actKeyRows[0].Keys
			assert.Len(t, actKeys, 3)
			assert.Equal(t, "E", actKeys[0].Name)
			assert.Equal(t, "D", actKeys[1].Name)
			assert.Equal(t, "C", actKeys[2].Name)
		})

		t.Run("should show cursor in tabular when more pages exist", func(t *testing.T) {
			// when
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"keys",
				"--tenant-id", tenantID,
				"--limit", "3",
				"--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.NoError(t, err, "command should succeed, output: %s", string(output))
			assert.Contains(t, string(output), "Cursor:")
		})

		t.Run("should hide cursor in tabular when no more pages", func(t *testing.T) {
			// when
			cmd = newCLICommand(
				t.Context(),
				homeDir,
				"get",
				"keys",
				"--tenant-id", tenantID,
				"--limit", "20",
				"--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.NoError(t, err, "command should succeed, output: %s", string(output))
			assert.NotContains(t, string(output), "Cursor:")
		})
	})
}

type key struct {
	ID                 string
	Name               string
	TenantID           string
	Kind               model.KeyKind
	ParentID           *string
	ManagedBy          string
	Labels             model.Labels
	LifeCycleState     model.KeyLifeCycleState
	KeyProcessingState model.KeyProcessingState
	CreatedAt          string
	UpdatedAt          string
}

type keyRow struct {
	Kind           model.KeyKind
	ID             string
	ParentID       string
	Name           string
	LifeCycleState model.KeyLifeCycleState
	Labels         model.Labels
	ManagedBy      string
	Status         model.KeyProcessingStatus
}

type keyRows struct {
	Keys   []keyRow
	Cursor string
}

// keyHierarchy holds a test key tree with 8 keys across 4 levels (K0-K3).
// Each key is assigned to a different managing agent to test cross-agent hierarchy traversal.
//
// Tree structure:
//
//	A (K0, root)
//	├── B (K1, root)
//	│   ├── D (K2, agent-aws)
//	│   └── E (K2, agent-azure)
//	└── C (K1, root)
//	    ├── F (K2, agent-gcp)
//	    └── G (K2, agent-onprem)
//	        └── H (K3, agent-onprem-2)
type keyHierarchy struct {
	root model.Key // A
	b    model.Key
	c    model.Key
	d    model.Key
	e    model.Key
	f    model.Key
	g    model.Key
	h    model.Key
}

// createKeyHierarchy creates 8 keys forming the tree documented on [keyHierarchy].
// All keys start in pre-activation state with no labels. Each key is assigned to a distinct
// managing agent to support integration tests for cross-agent key distribution and hierarchy queries.
func createKeyHierarchy(t *testing.T, keyStore store.Key, tenantID string) keyHierarchy {
	t.Helper()
	ctx := t.Context()

	root := model.NewKey(tenantID, "A", "K0", nil, "root", nil)
	err := keyStore.CreateKey(ctx, root)
	require.NoError(t, err)

	b := model.NewKey(tenantID, "B", "K1", &root.ID, "root", nil)
	err = keyStore.CreateKey(ctx, b)
	require.NoError(t, err)

	c := model.NewKey(tenantID, "C", "K1", &root.ID, "root", nil)
	c.Labels = model.Labels{"env": "prod"}
	err = keyStore.CreateKey(ctx, c)
	require.NoError(t, err)

	d := model.NewKey(tenantID, "D", "K2", &b.ID, "agent-aws", nil)
	err = keyStore.CreateKey(ctx, d)
	require.NoError(t, err)

	e := model.NewKey(tenantID, "E", "K2", &b.ID, "agent-azure", nil)
	e.LifeCycleState = model.KeyLifeCycleActive
	err = keyStore.CreateKey(ctx, e)
	require.NoError(t, err)

	f := model.NewKey(tenantID, "F", "K2", &c.ID, "agent-gcp", nil)
	err = keyStore.CreateKey(ctx, f)
	require.NoError(t, err)

	g := model.NewKey(tenantID, "G", "K2", &c.ID, "agent-onprem", nil)
	err = keyStore.CreateKey(ctx, g)
	require.NoError(t, err)

	h := model.NewKey(tenantID, "H", "K3", &g.ID, "agent-onprem-2", nil)
	h.Labels = model.Labels{"env": "dev"}
	err = keyStore.CreateKey(ctx, h)
	require.NoError(t, err)

	return keyHierarchy{
		root: root,
		b:    b,
		c:    c,
		d:    d,
		e:    e,
		f:    f,
		g:    g,
		h:    h,
	}
}

func decodeKeyRow(t *testing.T, output []byte) []keyRow {
	t.Helper()
	var ts []keyRow
	err := json.Unmarshal(output, &ts)
	if err != nil {
		assert.FailNowf(t, "failed to decode response", "output: %s, error: %v", string(output), err)
	}
	return ts
}

func decodeKeys(t *testing.T, output []byte) []key {
	t.Helper()
	var ts []key
	err := json.Unmarshal(output, &ts)
	if err != nil {
		assert.FailNowf(t, "failed to decode response", "output: %s, error: %v", string(output), err)
	}
	return ts
}

func decodeKeyRows(t *testing.T, output []byte) []keyRows {
	t.Helper()
	var ts []keyRows
	err := json.Unmarshal(output, &ts)
	if err != nil {
		assert.FailNowf(t, "failed to decode response", "output: %s, error: %v", string(output), err)
	}
	return ts
}
