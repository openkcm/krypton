package kmip_test

import (
	"context"
	"crypto/x509"
	"testing"

	ovhkmip "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/kmip"
	"github.com/openkcm/krypton/pkg/model"
)

func TestHandleGetAttributes(t *testing.T) {
	tenant := "tenant-a"
	keyID := "dek-mongodb-001"
	uid := tenant + ":" + keyID

	t.Run("returns full attribute set when unfiltered", func(t *testing.T) {
		h := newTestHandler(t, activeAESSeed(tenant, keyID))
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})

		resp, err := h.GetAttributes(context.Background(), &payloads.GetAttributesRequestPayload{
			UniqueIdentifier: uid,
		})
		require.NoError(t, err)
		assert.Equal(t, uid, resp.UniqueIdentifier)
		got := indexAttrs(resp.Attribute)
		assert.Len(t, got, 4)
		assert.Equal(t, ovhkmip.StateActive, got[ovhkmip.AttributeNameState])
		assert.Equal(t, ovhkmip.CryptographicAlgorithmAES, got[ovhkmip.AttributeNameCryptographicAlgorithm])
		assert.Equal(t, int32(256), got[ovhkmip.AttributeNameCryptographicLength])
		assert.Equal(t, ovhkmip.ObjectTypeSymmetricKey, got[ovhkmip.AttributeNameObjectType])
	})

	t.Run("filters to requested subset", func(t *testing.T) {
		h := newTestHandler(t, activeAESSeed(tenant, keyID))
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})

		resp, err := h.GetAttributes(context.Background(), &payloads.GetAttributesRequestPayload{
			UniqueIdentifier: uid,
			AttributeName: []ovhkmip.AttributeName{
				ovhkmip.AttributeNameCryptographicAlgorithm,
				ovhkmip.AttributeNameCryptographicLength,
			},
		})
		require.NoError(t, err)
		got := indexAttrs(resp.Attribute)
		assert.Len(t, got, 2)
		assert.Contains(t, got, ovhkmip.AttributeNameCryptographicAlgorithm)
		assert.Contains(t, got, ovhkmip.AttributeNameCryptographicLength)
		assert.NotContains(t, got, ovhkmip.AttributeNameState)
	})

	t.Run("unknown attribute request yields empty set", func(t *testing.T) {
		h := newTestHandler(t, activeAESSeed(tenant, keyID))
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})

		resp, err := h.GetAttributes(context.Background(), &payloads.GetAttributesRequestPayload{
			UniqueIdentifier: uid,
			AttributeName:    []ovhkmip.AttributeName{ovhkmip.AttributeNameName},
		})
		require.NoError(t, err)
		assert.Empty(t, resp.Attribute)
	})

	t.Run("invalid identifier -> InvalidField", func(t *testing.T) {
		h := newTestHandler(t, activeAESSeed(tenant, keyID))
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		_, err := h.GetAttributes(context.Background(), &payloads.GetAttributesRequestPayload{UniqueIdentifier: "no-colon"})
		reason, ok := asKMIPError(err)
		require.True(t, ok, "err = %v", err)
		assert.Equal(t, ovhkmip.ResultReasonInvalidField, reason)
	})

	t.Run("no client cert -> PermissionDenied", func(t *testing.T) {
		h := newTestHandler(t, activeAESSeed(tenant, keyID))
		withPeerCerts(t, nil)
		_, err := h.GetAttributes(context.Background(), &payloads.GetAttributesRequestPayload{UniqueIdentifier: uid})
		reason, ok := asKMIPError(err)
		require.True(t, ok, "err = %v", err)
		assert.Equal(t, ovhkmip.ResultReasonPermissionDenied, reason)
	})

	t.Run("cross-tenant -> PermissionDenied", func(t *testing.T) {
		h := newTestHandler(t, activeAESSeed(tenant, keyID))
		withPeerCerts(t, []*x509.Certificate{certWithCN("tenant-b")})
		_, err := h.GetAttributes(context.Background(), &payloads.GetAttributesRequestPayload{UniqueIdentifier: uid})
		reason, ok := asKMIPError(err)
		require.True(t, ok, "err = %v", err)
		assert.Equal(t, ovhkmip.ResultReasonPermissionDenied, reason)
	})

	t.Run("missing key -> ItemNotFound", func(t *testing.T) {
		h := newTestHandler(t, activeAESSeed(tenant, keyID))
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		_, err := h.GetAttributes(context.Background(), &payloads.GetAttributesRequestPayload{UniqueIdentifier: tenant + ":missing"})
		reason, ok := asKMIPError(err)
		require.True(t, ok, "err = %v", err)
		assert.Equal(t, ovhkmip.ResultReasonItemNotFound, reason)
	})

	t.Run("destroyed key -> ItemNotFound", func(t *testing.T) {
		seed := activeAESSeed(tenant, keyID)
		seed.State = model.KeyLifeCycleDestroyed
		h := newTestHandler(t, seed)
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		_, err := h.GetAttributes(context.Background(), &payloads.GetAttributesRequestPayload{UniqueIdentifier: uid})
		reason, ok := asKMIPError(err)
		require.True(t, ok, "err = %v", err)
		assert.Equal(t, ovhkmip.ResultReasonItemNotFound, reason)
	})

	t.Run("pre-activation -> PermissionDenied", func(t *testing.T) {
		seed := activeAESSeed(tenant, keyID)
		seed.State = model.KeyLifeCyclePreActivation
		h := newTestHandler(t, seed)
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		_, err := h.GetAttributes(context.Background(), &payloads.GetAttributesRequestPayload{UniqueIdentifier: uid})
		reason, ok := asKMIPError(err)
		require.True(t, ok, "err = %v", err)
		assert.Equal(t, ovhkmip.ResultReasonPermissionDenied, reason)
	})

	t.Run("unsupported algorithm -> GeneralFailure", func(t *testing.T) {
		seed := activeAESSeed(tenant, keyID)
		seed.Algorithm = kmip.AlgorithmUnknown
		h := newTestHandler(t, seed)
		withPeerCerts(t, []*x509.Certificate{certWithCN(tenant)})
		_, err := h.GetAttributes(context.Background(), &payloads.GetAttributesRequestPayload{UniqueIdentifier: uid})
		reason, ok := asKMIPError(err)
		require.True(t, ok, "err = %v", err)
		assert.Equal(t, ovhkmip.ResultReasonGeneralFailure, reason)
	})
}

func indexAttrs(attrs []ovhkmip.Attribute) map[ovhkmip.AttributeName]any {
	m := make(map[ovhkmip.AttributeName]any, len(attrs))
	for _, a := range attrs {
		m[a.AttributeName] = a.AttributeValue
	}
	return m
}
