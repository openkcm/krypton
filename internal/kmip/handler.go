package kmip

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"

	"github.com/openkcm/krypton/internal/keyprocessor"
)

// handler dispatches KMIP operations to the key processor manager.
type handler struct {
	manager *keyprocessor.Manager
}

// newHandler routes the Get and GetAttributes operations behind the
// authorizer middleware.
func newHandler(mgr *keyprocessor.Manager) kmipserver.RequestHandler {
	h := &handler{manager: mgr}

	exec := kmipserver.NewBatchExecutor()
	exec.BatchItemUse(newAuthorizer().authorize)
	exec.Route(kmip.OperationGet, kmipserver.HandleFunc(h.handleGet))
	exec.Route(kmip.OperationGetAttributes, kmipserver.HandleFunc(h.handleGetAttributes))

	return exec
}

// handleGet exports the requested key version and returns it as a KMIP
// SymmetricKey. The material is imported into the connection's
// securemem.MemVault so it stays in mlocked memory until the TerminateHook
// destroys it; without a vault the handler fails closed.
func (h *handler) handleGet(ctx context.Context, req *payloads.GetRequestPayload) (*payloads.GetResponsePayload, error) {
	id, ok := keyIdentifierFromCtx(ctx)
	if !ok {
		// The auth middleware did not run — fail closed.
		slog.ErrorContext(ctx, "kmip: no authorized key identifier on context")
		return nil, toKMIPError(ErrInternal)
	}

	sec, err := h.manager.ExportSecret(ctx, keyprocessor.ExportSecretRequest{
		TenantID:   id.TenantID,
		KeyID:      id.KeyID,
		KeyVersion: id.Version,
	})
	if err != nil {
		return nil, toKMIPError(mapKeyProcessorError(ctx, id.TenantID, id.KeyID, err))
	}
	if sec.Data == nil {
		slog.ErrorContext(ctx, "kmip: exported secret without material",
			"tenant_id", id.TenantID, "key_id", id.KeyID)
		return nil, toKMIPError(ErrInternal)
	}
	// The exported material is ours until the vault takes ownership.
	imported := false
	defer func() {
		if !imported {
			_ = sec.Data.Destroy()
		}
	}()

	alg, err := kmipAlgorithm(sec.Algorithm)
	if err != nil {
		return nil, toKMIPError(err)
	}

	vault := memVaultFromCtx(ctx)
	if vault == nil {
		return nil, toKMIPError(ErrNoSecureVault)
	}

	if err := vault.Import(vaultName(req.UniqueIdentifier), sec.Data); err != nil {
		slog.ErrorContext(ctx, "kmip: importing secret into connection vault failed",
			"tenant_id", id.TenantID, "key_id", id.KeyID, "error", err)
		return nil, toKMIPError(ErrInternal)
	}
	imported = true
	material := []byte(sec.Data.SecureBytes())

	return &payloads.GetResponsePayload{
		ObjectType:       kmip.ObjectTypeSymmetricKey,
		UniqueIdentifier: req.UniqueIdentifier,
		Object: &kmip.SymmetricKey{
			KeyBlock: kmip.KeyBlock{
				KeyFormatType:          kmip.KeyFormatTypeRaw,
				CryptographicAlgorithm: alg,
				CryptographicLength:    int32(len(material) * 8), //nolint:gosec // key lengths are far below overflow
				KeyValue: &kmip.KeyValue{
					Plain: &kmip.PlainKeyValue{
						KeyMaterial: kmip.KeyMaterial{Bytes: &material},
					},
				},
			},
		},
	}, nil
}

// handleGetAttributes is not supported yet; authorized requests fail with
// OperationNotSupported.
func (h *handler) handleGetAttributes(ctx context.Context, _ *payloads.GetAttributesRequestPayload) (*payloads.GetAttributesResponsePayload, error) {
	if _, ok := keyIdentifierFromCtx(ctx); !ok {
		// The auth middleware did not run — fail closed.
		slog.ErrorContext(ctx, "kmip: no authorized key identifier on context")
		return nil, toKMIPError(ErrInternal)
	}

	return nil, toKMIPError(fmt.Errorf("%w: GetAttributes", ErrNotSupported))
}
