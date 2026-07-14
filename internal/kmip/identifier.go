package kmip

import (
	"errors"
	"strings"
)

// ErrInvalidKeyIdentifier is returned by parseKeyIdentifier when the input
// does not match the `tenantID:keyID` shape.
var ErrInvalidKeyIdentifier = errors.New("invalid key identifier format")

// parseKeyIdentifier splits a KMIP UniqueIdentifier of the form
// "tenantID:keyID" into its two parts. The key ID may contain further
// colons; only the first is treated as the separator.
func parseKeyIdentifier(s string) (tenantID, keyID string, err error) {
	idx := strings.IndexByte(s, ':')
	if idx <= 0 || idx == len(s)-1 {
		return "", "", ErrInvalidKeyIdentifier
	}
	return s[:idx], s[idx+1:], nil
}
