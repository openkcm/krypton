package kmip

import (
	"context"
	"crypto/x509"
	"errors"

	"github.com/ovh/kmip-go/kmipserver"
)

// peerCertsFn resolves the peer certificates from a request context. It is a
// package-level indirection so unit tests can inject a fake without having
// to establish an actual TLS connection.
var peerCertsFn = func(ctx context.Context) []*x509.Certificate {
	return kmipserver.PeerCertificates(ctx)
}

// ErrNoClientCert is returned when the request context carries no peer
// certificate — either mTLS was not enforced or the connection is not TLS.
var ErrNoClientCert = errors.New("no client certificate on connection")

// ErrTenantMismatch is returned when the client cert's CN does not match
// the tenantID in the requested key identifier.
var ErrTenantMismatch = errors.New("client certificate CN does not match tenant")

// clientTenantFromCtx returns the CN of the client's leaf certificate. It
// returns ErrNoClientCert if no peer certificate is present.
func clientTenantFromCtx(ctx context.Context) (string, error) {
	certs := peerCertsFn(ctx)
	if len(certs) == 0 || certs[0] == nil {
		return "", ErrNoClientCert
	}
	cn := certs[0].Subject.CommonName
	if cn == "" {
		return "", ErrNoClientCert
	}
	return cn, nil
}

// authorizeTenant returns nil if the connecting client's CN matches the
// requested tenantID. All other cases (missing cert, mismatched CN) return
// an error suitable for mapping to KMIP PermissionDenied.
func authorizeTenant(ctx context.Context, tenantID string) error {
	cn, err := clientTenantFromCtx(ctx)
	if err != nil {
		return err
	}
	if cn != tenantID {
		return ErrTenantMismatch
	}
	return nil
}
