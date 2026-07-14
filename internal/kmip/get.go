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
// Key material handling: the plaintext bytes are copied into a locked region
// reserved from the connection's securemem.MemVault, so the response payload is
// backed by mlocked memory that the TerminateHook zeroes and unmaps when the
// connection ends. If no vault is present the handler fails closed rather than
// fall back to unlocked memory.
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

	alg, err := kmipAlgorithm(dek.Algorithm)
	if err != nil {
		return nil, toKMIPError(err)
	}

	vault := memVaultFromCtx(ctx)
	if vault == nil {
		return nil, toKMIPError(ErrNoSecureVault)
	}
	src := dek.Material.SecureBytes()
	sb, err := vault.Reserve(vaultName(req.UniqueIdentifier), len(src))
	if err != nil {
		return nil, toKMIPError(err)
	}
	copy(sb, src)
	material := []byte(sb)

	return &payloads.GetResponsePayload{
		ObjectType:       kmip.ObjectTypeSymmetricKey,
		UniqueIdentifier: req.UniqueIdentifier,
		Object: &kmip.SymmetricKey{
			KeyBlock: kmip.KeyBlock{
				KeyFormatType:          kmip.KeyFormatTypeRaw,
				CryptographicAlgorithm: alg,
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
