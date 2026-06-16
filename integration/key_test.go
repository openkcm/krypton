package integration

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
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
		keypb.RegisterKeyServiceServer(srv, keypb.NewKeyService("root", keyStore, keyValidator, &noopJobPreparer{}))
	})

	// create tenant
	// `kr create tenant --name <name> --json --server <server-addr>`
	expName := "tenant-" + uuid.NewString()
	cmd := newCLICommand(t.Context(), t.TempDir(), "create", "tenant", "--name", expName, "--json", "--server", serverAddr)
	output, err := cmd.CombinedOutput()
	assert.NoError(t, err, "command should succeed, output: %s", string(output))

	tenants := decode(t, output)
	if !assert.Len(t, tenants, 1) {
		return
	}
	tenantID := tenants[0].ID

	// create hierarchy
	hierarchy := createKeyHierarchy(t, keyStore, tenantID)

	t.Run("parent-keys", func(t *testing.T) {
		t.Run("should get all parent keys", func(t *testing.T) {
			// when
			cmd = newCLICommand(t.Context(), t.TempDir(), "get", "parent-keys", "--key-id", hierarchy.e.ID, "--tenant-id", tenantID, "--json", "--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.NoError(t, err, "command should succeed, output: %s", string(output))

			actRes := decodeKeyTreeRow(t, output)
			assert.Len(t, actRes, 3)
			assert.Equal(t, "A", actRes[0].Name)
			assert.Equal(t, hierarchy.root.Kind, actRes[0].Kind)

			assert.Equal(t, "B", actRes[1].Name)
			assert.Equal(t, hierarchy.b.Kind, actRes[1].Kind)

			assert.Equal(t, "E", actRes[2].Name)
			assert.Equal(t, hierarchy.e.Kind, actRes[2].Kind)
		})

		t.Run("should fail if no parent keys exist", func(t *testing.T) {
			// when
			unknownID := uuid.NewString()
			cmd = newCLICommand(t.Context(), t.TempDir(), "get", "parent-keys", "--key-id", unknownID, "--tenant-id", tenantID, "--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.Error(t, err)
			assert.Contains(t, string(output), "not found")
		})

		t.Run("should fail if tenant does not exist", func(t *testing.T) {
			// when
			unknownTenantID := uuid.NewString()
			cmd = newCLICommand(t.Context(), t.TempDir(), "get", "parent-keys", "--key-id", hierarchy.e.ID, "--tenant-id", unknownTenantID, "--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.Error(t, err)
			assert.Contains(t, string(output), "not found")
		})

		t.Run("should fail if key id parameter is not provided", func(t *testing.T) {
			// when
			cmd = newCLICommand(t.Context(), t.TempDir(), "get", "parent-keys", "--tenant-id", tenantID, "--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.Error(t, err)
			assert.Contains(t, string(output), "required flag(s) \"key-id\" not set")
		})

		t.Run("should fail if tenant id parameter is not provided", func(t *testing.T) {
			// when
			cmd = newCLICommand(t.Context(), t.TempDir(), "get", "parent-keys", "--key-id", hierarchy.e.ID, "--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.Error(t, err)
			assert.Contains(t, string(output), "required flag(s) \"tenant-id\" not set")
		})
	})

	t.Run("descendant-keys", func(t *testing.T) {
		t.Run("should get all descendant keys", func(t *testing.T) {
			// when
			cmd = newCLICommand(t.Context(), t.TempDir(), "get", "descendant-keys", "--key-id", hierarchy.root.ID, "--tenant-id", tenantID, "--json", "--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.NoError(t, err, "command should succeed, output: %s", string(output))

			actRes := decodeKeyTreeRow(t, output)
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

		t.Run("should fail if no descendant keys exist", func(t *testing.T) {
			// when
			unknownID := uuid.NewString()
			cmd = newCLICommand(t.Context(), t.TempDir(), "get", "descendant-keys", "--key-id", unknownID, "--tenant-id", tenantID, "--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.Error(t, err)
			assert.Contains(t, string(output), "not found")
		})

		t.Run("should fail if tenant does not exist", func(t *testing.T) {
			// when
			unknownTenantID := uuid.NewString()
			cmd = newCLICommand(t.Context(), t.TempDir(), "get", "descendant-keys", "--key-id", hierarchy.e.ID, "--tenant-id", unknownTenantID, "--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.Error(t, err)
			assert.Contains(t, string(output), "not found")
		})

		t.Run("should fail if key id parameter is not provided", func(t *testing.T) {
			// when
			cmd = newCLICommand(t.Context(), t.TempDir(), "get", "descendant-keys", "--tenant-id", tenantID, "--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.Error(t, err)
			assert.Contains(t, string(output), "required flag(s) \"key-id\" not set")
		})

		t.Run("should fail if tenant id parameter is not provided", func(t *testing.T) {
			// when
			cmd = newCLICommand(t.Context(), t.TempDir(), "get", "descendant-keys", "--key-id", hierarchy.e.ID, "--server", serverAddr)
			output, err = cmd.CombinedOutput()

			// then
			assert.Error(t, err)
			assert.Contains(t, string(output), "required flag(s) \"tenant-id\" not set")
		})
	})
}

type keyTreeRow struct {
	Kind      model.KeyKind
	ID        string
	ParentID  string
	Name      string
	ManagedBy string
	Status    string
}

// keyHierarchy holds a test key tree with the following structure:
//
//	A(K0)
//	  B(K1)
//	    D(K2)
//	    E(K2)
//	  C(K1)
//	    F(K2)
//	    G(K2)
//	      H(K3)
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

// createKeyHierarchy sets up a test key hierarchy with 8 keys across 4 levels and returns the created keys for reference in tests.
// keyHierarchy holds a test key tree with the following structure:
//
//	A(K0)
//	  B(K1)
//	    D(K2)
//	    E(K2)
//	  C(K1)
//	    F(K2)
//	    G(K2)
//	      H(K3)
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
	err = keyStore.CreateKey(ctx, c)
	require.NoError(t, err)

	d := model.NewKey(tenantID, "D", "K2", &b.ID, "agent-aws", nil)
	err = keyStore.CreateKey(ctx, d)
	require.NoError(t, err)

	e := model.NewKey(tenantID, "E", "K2", &b.ID, "agent-azure", nil)
	err = keyStore.CreateKey(ctx, e)
	require.NoError(t, err)

	f := model.NewKey(tenantID, "F", "K2", &c.ID, "agent-gcp", nil)
	err = keyStore.CreateKey(ctx, f)
	require.NoError(t, err)

	g := model.NewKey(tenantID, "G", "K2", &c.ID, "agent-onprem", nil)
	err = keyStore.CreateKey(ctx, g)
	require.NoError(t, err)

	h := model.NewKey(tenantID, "H", "K3", &g.ID, "agent-onprem-2", nil)
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

func decodeKeyTreeRow(t *testing.T, output []byte) []keyTreeRow {
	t.Helper()
	var ts []keyTreeRow
	err := json.Unmarshal(output, &ts)
	if err != nil {
		assert.FailNowf(t, "failed to decode response", "output: %s, error: %v", string(output), err)
	}
	return ts
}
