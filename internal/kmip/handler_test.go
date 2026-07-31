package kmip_test

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	ovhkmip "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/kmip"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

// requireFailure asserts the batch item failed with the given result reason.
func requireFailure(t *testing.T, bi *ovhkmip.ResponseBatchItem, reason ovhkmip.ResultReason) {
	t.Helper()
	require.Equal(t, ovhkmip.ResultStatusOperationFailed, bi.ResultStatus)
	require.Equal(t, reason, bi.ResultReason)
}

func TestHandleGet(t *testing.T) {
	tenant := "tenant-a"
	keyID := "dek-mongodb-001"
	uid := tenant + ":" + keyID + ":1"

	t.Run("happy path returns symmetric key for the requested version", func(t *testing.T) {
		material := sequentialMaterial(32)
		env := newTestEnv(t, tenant, keyID)
		env.seedSecret(t, material)
		h := kmip.NewTestHandler(env.mgr)
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		vault := securemem.NewMemVault()
		ctx := kmip.WithMemVault(context.Background(), vault)

		bi := h.Do(ctx, &payloads.GetRequestPayload{UniqueIdentifier: uid})
		require.Equal(t, ovhkmip.ResultStatusSuccess, bi.ResultStatus, "message = %s", bi.ResultMessage)

		resp, ok := bi.ResponsePayload.(*payloads.GetResponsePayload)
		require.True(t, ok, "payload type = %T", bi.ResponsePayload)
		assert.Equal(t, ovhkmip.ObjectTypeSymmetricKey, resp.ObjectType)
		assert.Equal(t, uid, resp.UniqueIdentifier)
		sk, ok := resp.Object.(*ovhkmip.SymmetricKey)
		require.True(t, ok, "Object type = %T", resp.Object)
		assert.Equal(t, ovhkmip.KeyFormatTypeRaw, sk.KeyBlock.KeyFormatType)
		assert.Equal(t, ovhkmip.CryptographicAlgorithmAES, sk.KeyBlock.CryptographicAlgorithm)
		assert.Equal(t, int32(256), sk.KeyBlock.CryptographicLength)
		mat, err := sk.KeyMaterial()
		require.NoError(t, err)
		assert.Equal(t, material, mat, "response bytes must be the unwrapped seeded material")

		// The material is owned by the connection vault until the
		// TerminateHook destroys it.
		require.NoError(t, vault.DestroyAll())
	})

	t.Run("invalid identifier -> InvalidField", func(t *testing.T) {
		h := kmip.NewTestHandler(failingEnv(t, tenant, keyID, errMustNotBeCalled).mgr)
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		bi := h.Do(context.Background(), &payloads.GetRequestPayload{UniqueIdentifier: "no-colon"})
		requireFailure(t, bi, ovhkmip.ResultReasonInvalidField)
	})

	t.Run("missing version -> InvalidField", func(t *testing.T) {
		h := kmip.NewTestHandler(failingEnv(t, tenant, keyID, errMustNotBeCalled).mgr)
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		bi := h.Do(context.Background(), &payloads.GetRequestPayload{UniqueIdentifier: tenant + ":" + keyID})
		requireFailure(t, bi, ovhkmip.ResultReasonInvalidField)
	})

	t.Run("unknown version -> ItemNotFound", func(t *testing.T) {
		env := newTestEnv(t, tenant, keyID)
		env.seedSecret(t, sequentialMaterial(32))
		h := kmip.NewTestHandler(env.mgr)
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		ctx := kmip.WithMemVault(context.Background(), securemem.NewMemVault())
		bi := h.Do(ctx, &payloads.GetRequestPayload{UniqueIdentifier: tenant + ":" + keyID + ":9"})
		requireFailure(t, bi, ovhkmip.ResultReasonItemNotFound)
	})

	t.Run("no client cert -> PermissionDenied", func(t *testing.T) {
		h := kmip.NewTestHandler(failingEnv(t, tenant, keyID, errMustNotBeCalled).mgr)
		withPeerCerts(t, nil)
		bi := h.Do(context.Background(), &payloads.GetRequestPayload{UniqueIdentifier: uid})
		requireFailure(t, bi, ovhkmip.ResultReasonPermissionDenied)
	})

	t.Run("cross-tenant -> PermissionDenied", func(t *testing.T) {
		h := kmip.NewTestHandler(failingEnv(t, tenant, keyID, errMustNotBeCalled).mgr)
		withPeerCerts(t, []*x509.Certificate{certWithCN("tenant-b")})
		bi := h.Do(context.Background(), &payloads.GetRequestPayload{UniqueIdentifier: uid})
		requireFailure(t, bi, ovhkmip.ResultReasonPermissionDenied)
	})

	t.Run("unknown key -> ItemNotFound", func(t *testing.T) {
		env := newTestEnv(t, tenant, keyID)
		h := kmip.NewTestHandler(env.mgr)
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		ctx := kmip.WithMemVault(context.Background(), securemem.NewMemVault())
		bi := h.Do(ctx, &payloads.GetRequestPayload{UniqueIdentifier: tenant + ":missing:1"})
		requireFailure(t, bi, ovhkmip.ResultReasonItemNotFound)
	})

	t.Run("key missing from key store -> ItemNotFound", func(t *testing.T) {
		env := newTestEnv(t, tenant, keyID)
		// A usable version exists but the key record is gone, so the
		// store.ErrKeyNotFound mapping arm is exercised.
		env.keys.getKeyByIDFn = func(context.Context, string, string) (*model.Key, error) {
			return nil, store.ErrKeyNotFound
		}
		h := kmip.NewTestHandler(env.mgr)
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		ctx := kmip.WithMemVault(context.Background(), securemem.NewMemVault())
		bi := h.Do(ctx, &payloads.GetRequestPayload{UniqueIdentifier: uid})
		requireFailure(t, bi, ovhkmip.ResultReasonItemNotFound)
	})

	t.Run("key without usable version -> ItemNotFound", func(t *testing.T) {
		env := newTestEnv(t, tenant, keyID)
		env.kvs.listKeyVersionsFn = func(context.Context, store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
			return store.ListKeyVersionsResult{}, nil
		}
		h := kmip.NewTestHandler(env.mgr)
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		ctx := kmip.WithMemVault(context.Background(), securemem.NewMemVault())
		bi := h.Do(ctx, &payloads.GetRequestPayload{UniqueIdentifier: uid})
		requireFailure(t, bi, ovhkmip.ResultReasonItemNotFound)
	})

	t.Run("key not active -> PermissionDenied", func(t *testing.T) {
		env := newTestEnv(t, tenant, keyID)
		env.keys.getKeyByIDFn = func(_ context.Context, id, _ string) (*model.Key, error) {
			return &model.Key{ID: id, TenantID: tenant, Kind: dekKind, LifeCycleState: model.KeyLifeCycleDeactivated}, nil
		}
		h := kmip.NewTestHandler(env.mgr)
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		ctx := kmip.WithMemVault(context.Background(), securemem.NewMemVault())
		bi := h.Do(ctx, &payloads.GetRequestPayload{UniqueIdentifier: uid})
		requireFailure(t, bi, ovhkmip.ResultReasonPermissionDenied)
	})

	t.Run("backend error sanitized to GeneralFailure", func(t *testing.T) {
		errBoom := errors.New("pq: connection refused host=db.internal:5432")
		h := kmip.NewTestHandler(failingEnv(t, tenant, keyID, errBoom).mgr)
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		ctx := kmip.WithMemVault(context.Background(), securemem.NewMemVault())
		bi := h.Do(ctx, &payloads.GetRequestPayload{UniqueIdentifier: uid})
		requireFailure(t, bi, ovhkmip.ResultReasonGeneralFailure)
		// The backend error text must not reach the wire — the kmip-go server
		// puts err.Error() verbatim into the ResultMessage.
		assert.NotContains(t, bi.ResultMessage, "db.internal")
	})

	t.Run("no secure vault -> GeneralFailure", func(t *testing.T) {
		env := newTestEnv(t, tenant, keyID)
		env.seedSecret(t, sequentialMaterial(32))
		h := kmip.NewTestHandler(env.mgr)
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		bi := h.Do(context.Background(), &payloads.GetRequestPayload{UniqueIdentifier: uid})
		requireFailure(t, bi, ovhkmip.ResultReasonGeneralFailure)
	})

	t.Run("vault name collision fails the request", func(t *testing.T) {
		env := newTestEnv(t, tenant, keyID)
		env.seedSecret(t, sequentialMaterial(32))
		h := kmip.NewTestHandler(env.mgr)
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		vault := securemem.NewMemVault()
		// Occupy the name the handler will use so Import collides.
		blocker := newSecureData(t, "blocker", []byte{0})
		require.NoError(t, vault.Import(kmip.PeekNextVaultName(uid), blocker))
		ctx := kmip.WithMemVault(context.Background(), vault)

		bi := h.Do(ctx, &payloads.GetRequestPayload{UniqueIdentifier: uid})
		requireFailure(t, bi, ovhkmip.ResultReasonGeneralFailure)
		// The securemem error text must not reach the wire.
		assert.NotContains(t, bi.ResultMessage, "vault data")
		require.NoError(t, vault.DestroyAll())
	})
}

func TestHandleGetAttributes(t *testing.T) {
	tenant := "tenant-a"
	keyID := "dek-mongodb-001"
	uid := tenant + ":" + keyID + ":1"

	t.Run("invalid identifier -> InvalidField", func(t *testing.T) {
		h := kmip.NewTestHandler(failingEnv(t, tenant, keyID, errMustNotBeCalled).mgr)
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		bi := h.Do(context.Background(), &payloads.GetAttributesRequestPayload{UniqueIdentifier: "no-colon"})
		requireFailure(t, bi, ovhkmip.ResultReasonInvalidField)
	})

	t.Run("no client cert -> PermissionDenied", func(t *testing.T) {
		h := kmip.NewTestHandler(failingEnv(t, tenant, keyID, errMustNotBeCalled).mgr)
		withPeerCerts(t, nil)
		bi := h.Do(context.Background(), &payloads.GetAttributesRequestPayload{UniqueIdentifier: uid})
		requireFailure(t, bi, ovhkmip.ResultReasonPermissionDenied)
	})

	t.Run("cross-tenant -> PermissionDenied", func(t *testing.T) {
		h := kmip.NewTestHandler(failingEnv(t, tenant, keyID, errMustNotBeCalled).mgr)
		withPeerCerts(t, []*x509.Certificate{certWithCN("tenant-b")})
		bi := h.Do(context.Background(), &payloads.GetAttributesRequestPayload{UniqueIdentifier: uid})
		requireFailure(t, bi, ovhkmip.ResultReasonPermissionDenied)
	})

	t.Run("authorized request -> OperationNotSupported", func(t *testing.T) {
		h := kmip.NewTestHandler(failingEnv(t, tenant, keyID, errMustNotBeCalled).mgr)
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		bi := h.Do(context.Background(), &payloads.GetAttributesRequestPayload{UniqueIdentifier: uid})
		requireFailure(t, bi, ovhkmip.ResultReasonOperationNotSupported)
	})
}
