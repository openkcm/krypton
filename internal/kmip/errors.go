package kmip

import (
	"errors"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
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
	default:
		return err
	}
}

// kmipAlgorithm translates the internal Algorithm enum into the kmip-go
// wire-format constant. It defaults to AES for AlgorithmUnknown so a
// misconfigured seed still produces a structurally valid response; callers
// that care should validate before serving.
func kmipAlgorithm(a Algorithm) kmip.CryptographicAlgorithm {
	switch a {
	case AlgorithmAES:
		return kmip.CryptographicAlgorithmAES
	default:
		return kmip.CryptographicAlgorithmAES
	}
}
