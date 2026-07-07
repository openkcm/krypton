package kmip

import (
	"context"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/payloads"
)

// handleGet implements the KMIP Get operation. It parses the UniqueIdentifier
// (`tenantID:keyID`), enforces mTLS tenant authorization, fetches the DEK,
// and returns a SymmetricKey payload.
//
// Key material handling: the plaintext bytes are copied out of secure memory
// into a request-local slice, placed in the response, and registered on the
// connection's wipe registry so they are zeroed when the connection ends.
func (h *handler) handleGet(ctx context.Context, req *payloads.GetRequestPayload) (*payloads.GetResponsePayload, error) {
	tenantID, keyID, err := parseKeyIdentifier(req.UniqueIdentifier)
	if err != nil {
		return nil, toKMIPError(err)
	}
	if err := authorizeTenant(ctx, tenantID); err != nil {
		return nil, toKMIPError(err)
	}

	dek, err := h.keyManager.GetDEK(ctx, tenantID, keyID)
	if err != nil {
		return nil, toKMIPError(err)
	}

	material := make([]byte, 0, dek.LengthBits/8)
	material = append(material, dek.Material.SecureBytes()...)
	if reg := wipeRegistryFromCtx(ctx); reg != nil {
		reg.register(material)
	}

	return &payloads.GetResponsePayload{
		ObjectType:       kmip.ObjectTypeSymmetricKey,
		UniqueIdentifier: req.UniqueIdentifier,
		Object: &kmip.SymmetricKey{
			KeyBlock: kmip.KeyBlock{
				KeyFormatType:          kmip.KeyFormatTypeRaw,
				CryptographicAlgorithm: kmipAlgorithm(dek.Algorithm),
				CryptographicLength:    dek.LengthBits,
				KeyValue: &kmip.KeyValue{
					Plain: &kmip.PlainKeyValue{
						KeyMaterial: kmip.KeyMaterial{Bytes: &material},
					},
				},
			},
		},
	}, nil
}
