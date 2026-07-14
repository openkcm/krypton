package kmip

import (
	"errors"
	"fmt"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
)

var (
	// ErrUnsupportedAlgorithm is returned when a DEK carries an algorithm that
	// has no KMIP wire-format mapping. Failing closed is preferable to putting a
	// wrong algorithm on the wire.
	ErrUnsupportedAlgorithm = errors.New("kmip: unsupported algorithm")
	// ErrNoSecureVault is returned when a handler that must hold key material
	// finds no per-connection secure-memory vault on the context. Handlers fail
	// closed rather than fall back to unlocked memory.
	ErrNoSecureVault = errors.New("kmip: no secure memory vault on context")
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
	case errors.Is(err, ErrUnsupportedAlgorithm), errors.Is(err, ErrNoSecureVault):
		// Server-side misconfiguration or missing vault — do not leak detail.
		return kmipserver.Errorf(kmip.ResultReasonGeneralFailure, "internal server error")
	default:
		return err
	}
}

// kmipAlgorithm translates the internal Algorithm enum into the kmip-go
// wire-format constant. Unsupported algorithms return ErrUnsupportedAlgorithm
// so the handler fails closed rather than putting a wrong algorithm on the wire.
func kmipAlgorithm(a Algorithm) (kmip.CryptographicAlgorithm, error) {
	switch a {
	case AlgorithmAES:
		return kmip.CryptographicAlgorithmAES, nil
	default:
		return 0, fmt.Errorf("%w: %d", ErrUnsupportedAlgorithm, a)
	}
}
