package kmip_test

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	ovhkmip "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/kmip"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/pkg/model"
)

func newTestHandler(t *testing.T, seeds ...kmip.SeedDEK) *kmip.TestHandler {
	t.Helper()
	return kmip.NewTestHandler(newTestMem(t, seeds...))
}

// activeAESSeed returns a seeded DEK ready for happy-path tests.
func activeAESSeed(tenantID, keyID string) kmip.SeedDEK {
	material := make([]byte, 32)
	for i := range material {
		material[i] = byte(i)
	}
	return kmip.SeedDEK{
		TenantID: tenantID, KeyID: keyID, Material: material,
		Algorithm: kmip.AlgorithmAES, LengthBits: 256, State: model.KeyLifeCycleActive,
	}
}

// asKMIPError unwraps a kmipserver.Error and returns its ResultReason. The
// second return is true iff err is a kmipserver.Error.
func asKMIPError(err error) (ovhkmip.ResultReason, bool) {
	if e, ok := errors.AsType[kmipserver.Error](err); ok {
		return e.Reason, true
	}
	return 0, false
}

func TestHandleGet(t *testing.T) {
	tenant := "tenant-a"
	keyID := "dek-mongodb-001"

	t.Run("happy path returns symmetric key", func(t *testing.T) {
		h := newTestHandler(t, activeAESSeed(tenant, keyID))
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		ctx := kmip.WithMemVault(context.Background(), securemem.NewMemVault())

		req := &payloads.GetRequestPayload{UniqueIdentifier: tenant + ":" + keyID}
		resp, err := h.Get(ctx, req)
		require.NoError(t, err)
		assert.Equal(t, ovhkmip.ObjectTypeSymmetricKey, resp.ObjectType)
		assert.Equal(t, req.UniqueIdentifier, resp.UniqueIdentifier)
		sk, ok := resp.Object.(*ovhkmip.SymmetricKey)
		require.True(t, ok, "Object type = %T", resp.Object)
		assert.Equal(t, ovhkmip.KeyFormatTypeRaw, sk.KeyBlock.KeyFormatType)
		assert.Equal(t, ovhkmip.CryptographicAlgorithmAES, sk.KeyBlock.CryptographicAlgorithm)
		assert.Equal(t, int32(256), sk.KeyBlock.CryptographicLength)
		mat, err := sk.KeyMaterial()
		require.NoError(t, err)
		require.Len(t, mat, 32)
		assert.Equal(t, byte(0), mat[0])
		assert.Equal(t, byte(31), mat[31])
	})

	t.Run("invalid identifier -> InvalidField", func(t *testing.T) {
		h := newTestHandler(t, activeAESSeed(tenant, keyID))
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		_, err := h.Get(context.Background(), &payloads.GetRequestPayload{UniqueIdentifier: "no-colon"})
		reason, ok := asKMIPError(err)
		require.True(t, ok, "err = %v", err)
		assert.Equal(t, ovhkmip.ResultReasonInvalidField, reason)
	})

	t.Run("no client cert -> PermissionDenied", func(t *testing.T) {
		h := newTestHandler(t, activeAESSeed(tenant, keyID))
		withPeerCerts(t, nil)
		_, err := h.Get(context.Background(), &payloads.GetRequestPayload{UniqueIdentifier: tenant + ":" + keyID})
		reason, ok := asKMIPError(err)
		require.True(t, ok, "err = %v", err)
		assert.Equal(t, ovhkmip.ResultReasonPermissionDenied, reason)
	})

	t.Run("cross-tenant -> PermissionDenied", func(t *testing.T) {
		h := newTestHandler(t, activeAESSeed(tenant, keyID))
		withPeerCerts(t, []*x509.Certificate{certWithCN("tenant-b")})
		_, err := h.Get(context.Background(), &payloads.GetRequestPayload{UniqueIdentifier: tenant + ":" + keyID})
		reason, ok := asKMIPError(err)
		require.True(t, ok, "err = %v", err)
		assert.Equal(t, ovhkmip.ResultReasonPermissionDenied, reason)
	})

	t.Run("missing key -> ItemNotFound", func(t *testing.T) {
		h := newTestHandler(t, activeAESSeed(tenant, keyID))
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		_, err := h.Get(context.Background(), &payloads.GetRequestPayload{UniqueIdentifier: tenant + ":missing"})
		reason, ok := asKMIPError(err)
		require.True(t, ok, "err = %v", err)
		assert.Equal(t, ovhkmip.ResultReasonItemNotFound, reason)
	})

	t.Run("destroyed key -> ItemNotFound", func(t *testing.T) {
		seed := activeAESSeed(tenant, keyID)
		seed.State = model.KeyLifeCycleDestroyed
		h := newTestHandler(t, seed)
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		_, err := h.Get(context.Background(), &payloads.GetRequestPayload{UniqueIdentifier: tenant + ":" + keyID})
		reason, ok := asKMIPError(err)
		require.True(t, ok, "err = %v", err)
		assert.Equal(t, ovhkmip.ResultReasonItemNotFound, reason)
	})

	t.Run("pre-activation -> PermissionDenied", func(t *testing.T) {
		seed := activeAESSeed(tenant, keyID)
		seed.State = model.KeyLifeCyclePreActivation
		h := newTestHandler(t, seed)
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		_, err := h.Get(context.Background(), &payloads.GetRequestPayload{UniqueIdentifier: tenant + ":" + keyID})
		reason, ok := asKMIPError(err)
		require.True(t, ok, "err = %v", err)
		assert.Equal(t, ovhkmip.ResultReasonPermissionDenied, reason)
	})

	t.Run("no secure vault -> GeneralFailure", func(t *testing.T) {
		h := newTestHandler(t, activeAESSeed(tenant, keyID))
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		_, err := h.Get(context.Background(), &payloads.GetRequestPayload{UniqueIdentifier: tenant + ":" + keyID})
		reason, ok := asKMIPError(err)
		require.True(t, ok, "err = %v", err)
		assert.Equal(t, ovhkmip.ResultReasonGeneralFailure, reason)
	})

	t.Run("unsupported algorithm -> GeneralFailure", func(t *testing.T) {
		seed := activeAESSeed(tenant, keyID)
		seed.Algorithm = kmip.AlgorithmUnknown
		h := newTestHandler(t, seed)
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		ctx := kmip.WithMemVault(context.Background(), securemem.NewMemVault())
		_, err := h.Get(ctx, &payloads.GetRequestPayload{UniqueIdentifier: tenant + ":" + keyID})
		reason, ok := asKMIPError(err)
		require.True(t, ok, "err = %v", err)
		assert.Equal(t, ovhkmip.ResultReasonGeneralFailure, reason)
	})

	t.Run("material backed by vault, cleared on DestroyAll", func(t *testing.T) {
		h := newTestHandler(t, activeAESSeed(tenant, keyID))
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		vault := securemem.NewMemVault()
		ctx := kmip.WithMemVault(context.Background(), vault)

		resp, err := h.Get(ctx, &payloads.GetRequestPayload{UniqueIdentifier: tenant + ":" + keyID})
		require.NoError(t, err)
		mat := *resp.Object.(*ovhkmip.SymmetricKey).KeyBlock.KeyValue.Plain.KeyMaterial.Bytes
		require.Len(t, mat, 32)
		assert.Equal(t, byte(0), mat[0])
		assert.Equal(t, byte(31), mat[31])
		// DestroyAll zeroes and unmaps the backing region; do not read mat after.
		require.NoError(t, vault.DestroyAll())
	})
}
