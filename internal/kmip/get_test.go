package kmip

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"

	"github.com/openkcm/krypton/pkg/model"
)

func newTestHandler(t *testing.T, seeds ...SeedDEK) *handler {
	t.Helper()
	km := newTestMem(t, seeds...)
	return &handler{keyManager: km}
}

// activeAESSeed returns a seeded DEK ready for happy-path tests.
func activeAESSeed(tenantID, keyID string) SeedDEK {
	material := make([]byte, 32)
	for i := range material {
		material[i] = byte(i)
	}
	return SeedDEK{
		TenantID: tenantID, KeyID: keyID, Material: material,
		Algorithm: AlgorithmAES, LengthBits: 256, State: model.KeyLifeCycleActive,
	}
}

// asKMIPError unwraps a kmipserver.Error and returns its ResultReason. The
// second return is true iff err is a kmipserver.Error.
func asKMIPError(err error) (kmip.ResultReason, bool) {
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

		req := &payloads.GetRequestPayload{UniqueIdentifier: tenant + ":" + keyID}
		resp, err := h.handleGet(context.Background(), req)
		if err != nil {
			t.Fatalf("handleGet: %v", err)
		}
		if resp.ObjectType != kmip.ObjectTypeSymmetricKey {
			t.Fatalf("ObjectType = %v", resp.ObjectType)
		}
		if resp.UniqueIdentifier != req.UniqueIdentifier {
			t.Fatalf("UniqueIdentifier mismatch")
		}
		sk, ok := resp.Object.(*kmip.SymmetricKey)
		if !ok {
			t.Fatalf("Object type = %T", resp.Object)
		}
		if sk.KeyBlock.KeyFormatType != kmip.KeyFormatTypeRaw {
			t.Fatalf("KeyFormatType = %v", sk.KeyBlock.KeyFormatType)
		}
		if sk.KeyBlock.CryptographicAlgorithm != kmip.CryptographicAlgorithmAES {
			t.Fatalf("Algorithm = %v", sk.KeyBlock.CryptographicAlgorithm)
		}
		if sk.KeyBlock.CryptographicLength != 256 {
			t.Fatalf("Length = %d", sk.KeyBlock.CryptographicLength)
		}
		mat, err := sk.KeyMaterial()
		if err != nil {
			t.Fatalf("KeyMaterial: %v", err)
		}
		if len(mat) != 32 || mat[0] != 0 || mat[31] != 31 {
			t.Fatalf("material mismatch len=%d", len(mat))
		}
	})

	t.Run("invalid identifier -> InvalidField", func(t *testing.T) {
		h := newTestHandler(t, activeAESSeed(tenant, keyID))
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		_, err := h.handleGet(context.Background(), &payloads.GetRequestPayload{UniqueIdentifier: "no-colon"})
		reason, ok := asKMIPError(err)
		if !ok || reason != kmip.ResultReasonInvalidField {
			t.Fatalf("err = %v, reason = %v, want InvalidField", err, reason)
		}
	})

	t.Run("no client cert -> PermissionDenied", func(t *testing.T) {
		h := newTestHandler(t, activeAESSeed(tenant, keyID))
		withPeerCerts(t, nil)
		_, err := h.handleGet(context.Background(), &payloads.GetRequestPayload{UniqueIdentifier: tenant + ":" + keyID})
		reason, ok := asKMIPError(err)
		if !ok || reason != kmip.ResultReasonPermissionDenied {
			t.Fatalf("err = %v, reason = %v, want PermissionDenied", err, reason)
		}
	})

	t.Run("cross-tenant -> PermissionDenied", func(t *testing.T) {
		h := newTestHandler(t, activeAESSeed(tenant, keyID))
		withPeerCerts(t, []*x509.Certificate{certWithCN("tenant-b")})
		_, err := h.handleGet(context.Background(), &payloads.GetRequestPayload{UniqueIdentifier: tenant + ":" + keyID})
		reason, ok := asKMIPError(err)
		if !ok || reason != kmip.ResultReasonPermissionDenied {
			t.Fatalf("err = %v, reason = %v, want PermissionDenied", err, reason)
		}
	})

	t.Run("missing key -> ItemNotFound", func(t *testing.T) {
		h := newTestHandler(t, activeAESSeed(tenant, keyID))
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		_, err := h.handleGet(context.Background(), &payloads.GetRequestPayload{UniqueIdentifier: tenant + ":missing"})
		reason, ok := asKMIPError(err)
		if !ok || reason != kmip.ResultReasonItemNotFound {
			t.Fatalf("err = %v, reason = %v, want ItemNotFound", err, reason)
		}
	})

	t.Run("destroyed key -> ItemNotFound", func(t *testing.T) {
		seed := activeAESSeed(tenant, keyID)
		seed.State = model.KeyLifeCycleDestroyed
		h := newTestHandler(t, seed)
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		_, err := h.handleGet(context.Background(), &payloads.GetRequestPayload{UniqueIdentifier: tenant + ":" + keyID})
		reason, ok := asKMIPError(err)
		if !ok || reason != kmip.ResultReasonItemNotFound {
			t.Fatalf("err = %v, reason = %v, want ItemNotFound", err, reason)
		}
	})

	t.Run("pre-activation -> PermissionDenied", func(t *testing.T) {
		seed := activeAESSeed(tenant, keyID)
		seed.State = model.KeyLifeCyclePreActivation
		h := newTestHandler(t, seed)
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		_, err := h.handleGet(context.Background(), &payloads.GetRequestPayload{UniqueIdentifier: tenant + ":" + keyID})
		reason, ok := asKMIPError(err)
		if !ok || reason != kmip.ResultReasonPermissionDenied {
			t.Fatalf("err = %v, reason = %v, want PermissionDenied", err, reason)
		}
	})

	t.Run("wipes on registry drain", func(t *testing.T) {
		h := newTestHandler(t, activeAESSeed(tenant, keyID))
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		reg := newWipeRegistry()
		ctx := withWipeRegistry(context.Background(), reg)

		resp, err := h.handleGet(ctx, &payloads.GetRequestPayload{UniqueIdentifier: tenant + ":" + keyID})
		if err != nil {
			t.Fatalf("handleGet: %v", err)
		}
		mat := *resp.Object.(*kmip.SymmetricKey).KeyBlock.KeyValue.Plain.KeyMaterial.Bytes
		if mat[0] == 0 && mat[31] == 0 {
			t.Fatal("material zeroed before wipe")
		}
		reg.wipeAll()
		for i, b := range mat {
			if b != 0 {
				t.Fatalf("material[%d] = %d after wipe, want 0", i, b)
			}
		}
	})
}
