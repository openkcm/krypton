package kmip

import (
	"context"
	"crypto/x509"
	"errors"
	"strconv"
	"strings"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"
)

var (
	// ErrInvalidKeyIdentifier is returned when a UniqueIdentifier does not
	// match the `tenantID:keyID:keyVersion` shape.
	ErrInvalidKeyIdentifier = errors.New("invalid key identifier format")
	// ErrNoClientCert is returned when the connection carries no usable peer
	// certificate.
	ErrNoClientCert = errors.New("no client certificate on connection")
	// ErrTenantMismatch is returned when the client cert's CN does not match
	// the requested tenant.
	ErrTenantMismatch = errors.New("client certificate CN does not match tenant")
)

// peerCertsFn resolves peer certificates from a request context; a
// package-level indirection so tests can inject certs without a TLS
// connection.
var peerCertsFn = func(ctx context.Context) []*x509.Certificate {
	return kmipserver.PeerCertificates(ctx)
}

// keyIdentifier is a parsed, tenant-authorized KMIP UniqueIdentifier.
type keyIdentifier struct {
	TenantID string
	KeyID    string
	Version  int
}

// keyIdentifierKey is the context key for the authorized keyIdentifier.
type keyIdentifierKey struct{}

func withKeyIdentifier(ctx context.Context, id keyIdentifier) context.Context {
	return context.WithValue(ctx, keyIdentifierKey{}, id)
}

// keyIdentifierFromCtx returns the identifier stored by the auth middleware;
// handlers must fail closed when it is absent.
func keyIdentifierFromCtx(ctx context.Context) (keyIdentifier, bool) {
	id, ok := ctx.Value(keyIdentifierKey{}).(keyIdentifier)
	return id, ok
}

// authorizer parses KMIP UniqueIdentifiers and authorizes them against the
// client certificate's CN.
type authorizer struct{}

func newAuthorizer() *authorizer {
	return &authorizer{}
}

// authorizeIdentifier splits "tenantID:keyID:keyVersion" (exactly three
// non-empty segments) and checks the tenant against the client cert CN.
func (a *authorizer) authorizeIdentifier(ctx context.Context, uniqueIdentifier string) (keyIdentifier, error) {
	parts := strings.Split(uniqueIdentifier, ":")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return keyIdentifier{}, ErrInvalidKeyIdentifier
	}
	version, err := strconv.Atoi(parts[2])
	if err != nil {
		return keyIdentifier{}, ErrInvalidKeyIdentifier
	}
	id := keyIdentifier{TenantID: parts[0], KeyID: parts[1], Version: version}

	certs := peerCertsFn(ctx)
	if len(certs) == 0 || certs[0] == nil || certs[0].Subject.CommonName == "" {
		return keyIdentifier{}, ErrNoClientCert
	}
	if certs[0].Subject.CommonName != id.TenantID {
		return keyIdentifier{}, ErrTenantMismatch
	}
	return id, nil
}

// authorize is a kmipserver.BatchItemMiddleware: it authorizes the item's
// UniqueIdentifier and passes the parsed identifier to the handler via the
// context. Operations without a recognized identifier pass through untouched.
func (a *authorizer) authorize(next kmipserver.BatchItemNext, ctx context.Context, bi *kmip.RequestBatchItem) (*kmip.ResponseBatchItem, error) {
	var uid string
	switch pl := bi.RequestPayload.(type) {
	case *payloads.GetRequestPayload:
		uid = pl.UniqueIdentifier
	case *payloads.GetAttributesRequestPayload:
		uid = pl.UniqueIdentifier
	default:
		return next(ctx, bi)
	}

	id, err := a.authorizeIdentifier(ctx, uid)
	if err != nil {
		// The executor dereferences the batch item even on error; never nil.
		return &kmip.ResponseBatchItem{
			Operation:         bi.Operation,
			UniqueBatchItemID: bi.UniqueBatchItemID,
		}, toKMIPError(err)
	}

	return next(withKeyIdentifier(ctx, id), bi)
}
