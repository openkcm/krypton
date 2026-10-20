//go:build helmtests

package unit_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// The file tests generate their certificates and keys at test time: the repository holds no
// key material.

// PEM block types of private key files.
const (
	pkcs8Key = "PRIVATE KEY"     // PKCS #8: RSA, ECDSA or Ed25519 key
	pkcs1Key = "RSA PRIVATE KEY" // PKCS #1: RSA key
	sec1Key  = "EC PRIVATE KEY"  // SEC 1: ECDSA key
)

// keyFormat is a format of private key files.
type keyFormat struct {
	name      string
	blockType string
	newKey    func(t *testing.T) crypto.Signer
}

// keyFormats are the formats of private key files that values.yaml documents (tls.key at
// extraVolumes).
var keyFormats = []keyFormat{
	{name: "PKCS #8 RSA", blockType: pkcs8Key, newKey: newRSAKey},
	{name: "PKCS #8 ECDSA", blockType: pkcs8Key, newKey: newECDSAKey},
	{name: "PKCS #8 Ed25519", blockType: pkcs8Key, newKey: newEd25519Key},
	{name: "PKCS #1 RSA", blockType: pkcs1Key, newKey: newRSAKey},
	{name: "SEC 1 ECDSA", blockType: sec1Key, newKey: newECDSAKey},
}

// must returns value, or fails the test with err. Call it as must(f())(t).
func must[T any](value T, err error) func(t *testing.T) T {
	return func(t *testing.T) T {
		t.Helper()

		if err != nil {
			t.Fatal(err)
		}

		return value
	}
}

func newRSAKey(t *testing.T) crypto.Signer {
	t.Helper()
	return must(rsa.GenerateKey(rand.Reader, 2048))(t)
}

func newECDSAKey(t *testing.T) crypto.Signer {
	t.Helper()
	return must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))(t)
}

func newEd25519Key(t *testing.T) crypto.Signer {
	t.Helper()

	_, key, err := ed25519.GenerateKey(rand.Reader)

	return must(crypto.Signer(key), err)(t)
}

// testCA is a certificate authority created for a test.
type testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// newRootCA creates a self-signed CA.
func newRootCA(t *testing.T, name string) *testCA {
	t.Helper()

	key := newECDSAKey(t)
	template := caTemplate(t, name)

	return &testCA{cert: createCertificate(t, template, template, key.Public(), key), key: key}
}

// newIntermediateCA creates a CA issued by ca.
func (ca *testCA) newIntermediateCA(t *testing.T, name string) *testCA {
	t.Helper()

	key := newECDSAKey(t)

	return &testCA{cert: createCertificate(t, caTemplate(t, name), ca.cert, key.Public(), ca.key), key: key}
}

// issue creates a certificate for TLS clients and servers with the common name, the URI SANs
// (identities of Krypton nodes) and the DNS names.
func (ca *testCA) issue(t *testing.T, key crypto.Signer, commonName string, uris []string,
	dnsNames ...string,
) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: serialNumber(t),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	for _, uri := range uris {
		template.URIs = append(template.URIs, must(url.Parse(uri))(t))
	}

	return createCertificate(t, template, ca.cert, key.Public(), ca.key)
}

func caTemplate(t *testing.T, name string) *x509.Certificate {
	t.Helper()

	return &x509.Certificate{
		SerialNumber:          serialNumber(t),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
}

func createCertificate(t *testing.T, template, parent *x509.Certificate, pub crypto.PublicKey,
	signer crypto.Signer,
) *x509.Certificate {
	t.Helper()

	der := must(x509.CreateCertificate(rand.Reader, template, parent, pub, signer))(t)

	return must(x509.ParseCertificate(der))(t)
}

func serialNumber(t *testing.T) *big.Int {
	t.Helper()
	return must(rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64)))(t)
}

// certPEM encodes the certificates as CERTIFICATE blocks, in the given order.
func certPEM(certs ...*x509.Certificate) []byte {
	var out bytes.Buffer
	for _, cert := range certs {
		_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}

	return out.Bytes()
}

// keyPEM encodes the private key as a PEM block of the given type.
func keyPEM(t *testing.T, key crypto.Signer, blockType string) []byte {
	t.Helper()

	var der []byte

	switch blockType {
	case pkcs8Key:
		der = must(x509.MarshalPKCS8PrivateKey(key))(t)
	case pkcs1Key:
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			t.Fatal("PKCS #1 needs an RSA key")
		}

		der = x509.MarshalPKCS1PrivateKey(rsaKey)
	case sec1Key:
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatal("SEC 1 needs an ECDSA key")
		}

		der = must(x509.MarshalECPrivateKey(ecKey))(t)
	default:
		t.Fatalf("unknown private key block type %q", blockType)
	}

	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

// testPKI are the CAs of a file test: a root CA, an intermediate CA issued by it that issues
// the client and server certificates, and an unrelated CA.
type testPKI struct {
	root, intermediate, other *testCA
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()

	root := newRootCA(t, "Test Root CA")

	return &testPKI{
		root:         root,
		intermediate: root.newIntermediateCA(t, "Test Intermediate CA"),
		other:        newRootCA(t, "Other CA"),
	}
}

// files returns the content of the TLS files of a Krypton node in the layout that values.yaml
// documents (extraVolumes): tls.crt with its certificate, issued by the intermediate CA with
// the URI SANs and DNS names, and then the intermediate CA; tls.key with its private key in
// the given format; and ca.crt with two CA certificates, an unrelated one and the root CA.
func (p *testPKI) files(t *testing.T, format keyFormat, name string, uris []string,
	dnsNames ...string,
) ([]byte, []byte, []byte) {
	t.Helper()

	key := format.newKey(t)
	cert := p.intermediate.issue(t, key, name, uris, dnsNames...)

	return certPEM(cert, p.intermediate.cert), keyPEM(t, key, format.blockType),
		certPEM(p.other.cert, p.root.cert)
}
