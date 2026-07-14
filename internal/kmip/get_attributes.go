package kmip

import (
	"context"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
)

// defaultAttributeNames is the canonical attribute set returned when a
// GetAttributes request does not name any specific attributes.
var defaultAttributeNames = []kmip.AttributeName{
	kmip.AttributeNameState,
	kmip.AttributeNameCryptographicAlgorithm,
	kmip.AttributeNameCryptographicLength,
	kmip.AttributeNameObjectType,
}

// handleGetAttributes implements the KMIP GetAttributes operation. Returns
// State, CryptographicAlgorithm, CryptographicLength, and ObjectType. If the
// request specifies attribute names, only the intersection with the
// supported set is returned.
func (h *handler) handleGetAttributes(ctx context.Context, req *payloads.GetAttributesRequestPayload) (*payloads.GetAttributesResponsePayload, error) {
	tenantID, keyID, err := parseKeyIdentifier(req.UniqueIdentifier)
	if err != nil {
		return nil, toKMIPError(err)
	}
	if err := authorizeTenant(ctx, tenantID); err != nil {
		return nil, toKMIPError(err)
	}

	info, err := h.keyManager.GetKeyInfo(ctx, tenantID, keyID)
	if err != nil {
		return nil, toKMIPError(err)
	}

	alg, err := kmipAlgorithm(info.Algorithm)
	if err != nil {
		return nil, toKMIPError(err)
	}

	names := req.AttributeName
	if len(names) == 0 {
		names = defaultAttributeNames
	}
	attrs := make([]kmip.Attribute, 0, len(names))
	for _, n := range names {
		switch n {
		case kmip.AttributeNameState:
			attrs = append(attrs, kmip.Attribute{AttributeName: n, AttributeValue: kmip.StateActive})
		case kmip.AttributeNameCryptographicAlgorithm:
			attrs = append(attrs, kmip.Attribute{AttributeName: n, AttributeValue: alg})
		case kmip.AttributeNameCryptographicLength:
			attrs = append(attrs, kmip.Attribute{AttributeName: n, AttributeValue: info.LengthBits})
		case kmip.AttributeNameObjectType:
			attrs = append(attrs, kmip.Attribute{AttributeName: n, AttributeValue: kmip.ObjectTypeSymmetricKey})
		}
	}

	return &payloads.GetAttributesResponsePayload{
		UniqueIdentifier: req.UniqueIdentifier,
		Attribute:        attrs,
	}, nil
}
