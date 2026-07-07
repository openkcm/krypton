package kmip

import (
	"context"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
)

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

	all := []kmip.Attribute{
		{AttributeName: kmip.AttributeNameState, AttributeValue: kmip.StateActive},
		{AttributeName: kmip.AttributeNameCryptographicAlgorithm, AttributeValue: kmipAlgorithm(info.Algorithm)},
		{AttributeName: kmip.AttributeNameCryptographicLength, AttributeValue: info.LengthBits},
		{AttributeName: kmip.AttributeNameObjectType, AttributeValue: kmip.ObjectTypeSymmetricKey},
	}

	var attrs []kmip.Attribute
	if len(req.AttributeName) == 0 {
		attrs = all
	} else {
		requested := make(map[kmip.AttributeName]struct{}, len(req.AttributeName))
		for _, n := range req.AttributeName {
			requested[n] = struct{}{}
		}
		attrs = make([]kmip.Attribute, 0, len(all))
		for _, a := range all {
			if _, ok := requested[a.AttributeName]; ok {
				attrs = append(attrs, a)
			}
		}
	}

	return &payloads.GetAttributesResponsePayload{
		UniqueIdentifier: req.UniqueIdentifier,
		Attribute:        attrs,
	}, nil
}
