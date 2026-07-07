package kmip

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"

	"github.com/openkcm/krypton/pkg/model"
)

func TestHandleGetAttributes(t *testing.T) {
	tenant := "tenant-a"
	keyID := "dek-mongodb-001"
	uid := tenant + ":" + keyID

	t.Run("returns full attribute set when unfiltered", func(t *testing.T) {
		h := newTestHandler(t, activeAESSeed(tenant, keyID))
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})

		resp, err := h.handleGetAttributes(context.Background(), &payloads.GetAttributesRequestPayload{
			UniqueIdentifier: uid,
		})
		if err != nil {
			t.Fatalf("handleGetAttributes: %v", err)
		}
		if resp.UniqueIdentifier != uid {
			t.Fatalf("UniqueIdentifier = %q", resp.UniqueIdentifier)
		}
		got := indexAttrs(resp.Attribute)
		if len(got) != 4 {
			t.Fatalf("attribute count = %d, want 4", len(got))
		}
		if v := got[kmip.AttributeNameState]; v != kmip.StateActive {
			t.Fatalf("State = %v", v)
		}
		if v := got[kmip.AttributeNameCryptographicAlgorithm]; v != kmip.CryptographicAlgorithmAES {
			t.Fatalf("Algorithm = %v", v)
		}
		if v := got[kmip.AttributeNameCryptographicLength]; v != int32(256) {
			t.Fatalf("Length = %v", v)
		}
		if v := got[kmip.AttributeNameObjectType]; v != kmip.ObjectTypeSymmetricKey {
			t.Fatalf("ObjectType = %v", v)
		}
	})

	t.Run("filters to requested subset", func(t *testing.T) {
		h := newTestHandler(t, activeAESSeed(tenant, keyID))
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})

		resp, err := h.handleGetAttributes(context.Background(), &payloads.GetAttributesRequestPayload{
			UniqueIdentifier: uid,
			AttributeName: []kmip.AttributeName{
				kmip.AttributeNameCryptographicAlgorithm,
				kmip.AttributeNameCryptographicLength,
			},
		})
		if err != nil {
			t.Fatalf("handleGetAttributes: %v", err)
		}
		got := indexAttrs(resp.Attribute)
		if len(got) != 2 {
			t.Fatalf("attribute count = %d, want 2", len(got))
		}
		if _, ok := got[kmip.AttributeNameCryptographicAlgorithm]; !ok {
			t.Fatal("missing CryptographicAlgorithm")
		}
		if _, ok := got[kmip.AttributeNameCryptographicLength]; !ok {
			t.Fatal("missing CryptographicLength")
		}
		if _, ok := got[kmip.AttributeNameState]; ok {
			t.Fatal("unexpected State attribute in filtered response")
		}
	})

	t.Run("unknown attribute request yields empty set", func(t *testing.T) {
		h := newTestHandler(t, activeAESSeed(tenant, keyID))
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})

		resp, err := h.handleGetAttributes(context.Background(), &payloads.GetAttributesRequestPayload{
			UniqueIdentifier: uid,
			AttributeName:    []kmip.AttributeName{kmip.AttributeNameName},
		})
		if err != nil {
			t.Fatalf("handleGetAttributes: %v", err)
		}
		if len(resp.Attribute) != 0 {
			t.Fatalf("attribute count = %d, want 0", len(resp.Attribute))
		}
	})

	t.Run("invalid identifier -> InvalidField", func(t *testing.T) {
		h := newTestHandler(t, activeAESSeed(tenant, keyID))
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		_, err := h.handleGetAttributes(context.Background(), &payloads.GetAttributesRequestPayload{UniqueIdentifier: "no-colon"})
		reason, ok := asKMIPError(err)
		if !ok || reason != kmip.ResultReasonInvalidField {
			t.Fatalf("err = %v, reason = %v, want InvalidField", err, reason)
		}
	})

	t.Run("no client cert -> PermissionDenied", func(t *testing.T) {
		h := newTestHandler(t, activeAESSeed(tenant, keyID))
		withPeerCerts(t, nil)
		_, err := h.handleGetAttributes(context.Background(), &payloads.GetAttributesRequestPayload{UniqueIdentifier: uid})
		reason, ok := asKMIPError(err)
		if !ok || reason != kmip.ResultReasonPermissionDenied {
			t.Fatalf("err = %v, reason = %v, want PermissionDenied", err, reason)
		}
	})

	t.Run("cross-tenant -> PermissionDenied", func(t *testing.T) {
		h := newTestHandler(t, activeAESSeed(tenant, keyID))
		withPeerCerts(t, []*x509.Certificate{certWithCN("tenant-b")})
		_, err := h.handleGetAttributes(context.Background(), &payloads.GetAttributesRequestPayload{UniqueIdentifier: uid})
		reason, ok := asKMIPError(err)
		if !ok || reason != kmip.ResultReasonPermissionDenied {
			t.Fatalf("err = %v, reason = %v, want PermissionDenied", err, reason)
		}
	})

	t.Run("missing key -> ItemNotFound", func(t *testing.T) {
		h := newTestHandler(t, activeAESSeed(tenant, keyID))
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		_, err := h.handleGetAttributes(context.Background(), &payloads.GetAttributesRequestPayload{UniqueIdentifier: tenant + ":missing"})
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
		_, err := h.handleGetAttributes(context.Background(), &payloads.GetAttributesRequestPayload{UniqueIdentifier: uid})
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
		_, err := h.handleGetAttributes(context.Background(), &payloads.GetAttributesRequestPayload{UniqueIdentifier: uid})
		reason, ok := asKMIPError(err)
		if !ok || reason != kmip.ResultReasonPermissionDenied {
			t.Fatalf("err = %v, reason = %v, want PermissionDenied", err, reason)
		}
	})
}

func indexAttrs(attrs []kmip.Attribute) map[kmip.AttributeName]any {
	m := make(map[kmip.AttributeName]any, len(attrs))
	for _, a := range attrs {
		m[a.AttributeName] = a.AttributeValue
	}
	return m
}
