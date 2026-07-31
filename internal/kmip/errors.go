package kmip

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/pkg/store"
)

var (
	// ErrKeyNotFound signals that no key or usable material exists for the
	// given tenant/keyID.
	ErrKeyNotFound = errors.New("kmip: key not found")
	// ErrKeyNotActive signals that a key exists but is not Active.
	ErrKeyNotActive = errors.New("kmip: key not active")
	// ErrNotSupported signals that the requested operation is not supported.
	ErrNotSupported = errors.New("kmip: operation not supported")
	// ErrUnsupportedAlgorithm is returned when a DEK carries an algorithm that
	// has no KMIP wire-format mapping. Failing closed is preferable to putting a
	// wrong algorithm on the wire.
	ErrUnsupportedAlgorithm = errors.New("kmip: unsupported algorithm")
	// ErrNoSecureVault is returned when a handler that must hold key material
	// finds no per-connection secure-memory vault on the context. Handlers fail
	// closed rather than fall back to unlocked memory.
	ErrNoSecureVault = errors.New("kmip: no secure memory vault on context")
	// ErrInternal replaces backend errors so their text never reaches the
	// wire; the cause is logged server-side.
	ErrInternal = errors.New("kmip: internal error")
)

// toKMIPError converts an internal error into a KMIP protocol error with an
// appropriate ResultReason. Errors that do not match a known sentinel are
// returned unchanged; the batch executor maps those to GeneralFailure.
func toKMIPError(err error) error {
	switch {
	case errors.Is(err, ErrInvalidKeyIdentifier):
		return kmipserver.Errorf(kmip.ResultReasonInvalidField, "invalid key identifier format")
	case errors.Is(err, ErrKeyNotFound):
		return kmipserver.Errorf(kmip.ResultReasonItemNotFound, "key not found")
	case errors.Is(err, ErrKeyNotActive):
		// KMIP has no direct "not active" reason. PermissionDenied matches
		// the security posture — a key that is not usable must not be
		// distinguishable from an authorization failure to the client.
		return kmipserver.Errorf(kmip.ResultReasonPermissionDenied, "key not active")
	case errors.Is(err, ErrTenantMismatch), errors.Is(err, ErrNoClientCert):
		return kmipserver.Errorf(kmip.ResultReasonPermissionDenied, "permission denied")
	case errors.Is(err, ErrNotSupported):
		return kmipserver.Errorf(kmip.ResultReasonOperationNotSupported, "operation not supported")
	case errors.Is(err, ErrUnsupportedAlgorithm), errors.Is(err, ErrNoSecureVault), errors.Is(err, ErrInternal):
		// Server-side misconfiguration or missing vault — do not leak detail.
		return kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "internal server error")
	default:
		return err
	}
}

// mapKeyProcessorError maps keyprocessor/store errors to the KMIP sentinels;
// unmapped errors are logged and replaced by ErrInternal.
func mapKeyProcessorError(ctx context.Context, tenantID, keyID string, err error) error {
	switch {
	case errors.Is(err, store.ErrKeyNotFound),
		errors.Is(err, keyprocessor.ErrNoUsableKeyVersion):
		return fmt.Errorf("%w: %w", ErrKeyNotFound, err)
	case errors.Is(err, keyprocessor.ErrKeyNotActivated):
		return fmt.Errorf("%w: %w", ErrKeyNotActive, err)
	default:
		slog.ErrorContext(ctx, "kmip: exporting secret failed",
			"tenant_id", tenantID, "key_id", keyID, "error", err)
		return ErrInternal
	}
}

// kmipAlgorithm translates the cryptor key algorithm into the kmip-go wire
// constant; unsupported algorithms fail closed with ErrUnsupportedAlgorithm.
func kmipAlgorithm(a cryptor.KeyAlgorithm) (kmip.CryptographicAlgorithm, error) {
	switch a {
	case cryptor.KeyAlgorithmAES256:
		return kmip.CryptographicAlgorithmAES, nil
	default:
		return 0, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, a)
	}
}
