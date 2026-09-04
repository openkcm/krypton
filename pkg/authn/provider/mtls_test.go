package provider_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json/v2"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/clock"
	"github.com/openkcm/krypton/pkg/authn"
	"github.com/openkcm/krypton/pkg/authn/provider"
)

func TestMTLSValidate(t *testing.T) {
	// given
	ctx := t.Context()
	validCertPaths := newTestPKI(t)
	invalidCertPaths := newTestPKI(t)
	subj := &provider.MTLS{}
	tts := []struct {
		name  string
		tknFn func() *authn.Token
		res   authn.ValidationResult
	}{
		{
			name:  "invalid type",
			tknFn: func() *authn.Token { return &authn.Token{Type: "invalid"} },
			res:   authn.ValidationResult{Status: authn.InvalidStatus},
		},
		{
			name:  "invalid value",
			tknFn: func() *authn.Token { return &authn.Token{Type: authn.MTLS, Value: []byte("invalid"), ExpiredAt: 1} },
			res:   authn.ValidationResult{Status: authn.InvalidStatus},
		},
		{
			name: "if a non existing private key file is used, return invalid",
			tknFn: func() *authn.Token {
				v := provider.MTLSCredentialsValue{
					PrivateKeyPath: "/non/existing/path/client-key.pem",
					PublicCertPath: validCertPaths.clientPublicKeyPath,
					CaCertPath:     validCertPaths.caCertPath,
				}
				b, err := json.Marshal(v)
				require.NoError(t, err)
				return &authn.Token{Type: authn.MTLS, Value: b, ExpiredAt: clock.UnixNano(time.Now().Add(1 * time.Hour).UnixNano())}
			},
			res: authn.ValidationResult{Status: authn.InvalidStatus},
		},
		{
			name: "if a non existing public key file is used, return invalid",
			tknFn: func() *authn.Token {
				v := provider.MTLSCredentialsValue{
					PrivateKeyPath: validCertPaths.clientPrivateKeyPath,
					PublicCertPath: "/non/existing/path/client.pem",
					CaCertPath:     validCertPaths.caCertPath,
				}
				b, err := json.Marshal(v)
				require.NoError(t, err)
				return &authn.Token{Type: authn.MTLS, Value: b, ExpiredAt: clock.UnixNano(time.Now().Add(1 * time.Hour).UnixNano())}
			},
			res: authn.ValidationResult{Status: authn.InvalidStatus},
		},
		{
			name: "if a non existing ca cert file is used, return invalid",
			tknFn: func() *authn.Token {
				v := provider.MTLSCredentialsValue{
					PrivateKeyPath: validCertPaths.clientPrivateKeyPath,
					PublicCertPath: validCertPaths.clientPublicKeyPath,
					CaCertPath:     "/non/existing/path/ca.pem",
				}
				b, err := json.Marshal(v)
				require.NoError(t, err)
				return &authn.Token{Type: authn.MTLS, Value: b, ExpiredAt: clock.UnixNano(time.Now().Add(1 * time.Hour).UnixNano())}
			},
			res: authn.ValidationResult{Status: authn.InvalidStatus},
		},
		{
			name: "if different ca is used, return invalid",
			tknFn: func() *authn.Token {
				v := provider.MTLSCredentialsValue{
					PrivateKeyPath: validCertPaths.clientPrivateKeyPath,
					PublicCertPath: validCertPaths.clientPublicKeyPath,
					CaCertPath:     invalidCertPaths.caCertPath,
				}
				b, err := json.Marshal(v)
				require.NoError(t, err)
				return &authn.Token{Type: authn.MTLS, Value: b, ExpiredAt: clock.UnixNano(time.Now().Add(1 * time.Hour).UnixNano())}
			},
			res: authn.ValidationResult{Status: authn.InvalidStatus},
		},
		{
			name: "if different key is used, return invalid",
			tknFn: func() *authn.Token {
				v := provider.MTLSCredentialsValue{
					PrivateKeyPath: invalidCertPaths.clientPrivateKeyPath,
					PublicCertPath: validCertPaths.clientPublicKeyPath,
					CaCertPath:     validCertPaths.caCertPath,
				}
				b, err := json.Marshal(v)
				require.NoError(t, err)
				return &authn.Token{Type: authn.MTLS, Value: b, ExpiredAt: clock.UnixNano(time.Now().Add(1 * time.Hour).UnixNano())}
			},
			res: authn.ValidationResult{Status: authn.InvalidStatus},
		},
		{
			name: "if different cert is used, return invalid",
			tknFn: func() *authn.Token {
				v := provider.MTLSCredentialsValue{
					PrivateKeyPath: validCertPaths.clientPrivateKeyPath,
					PublicCertPath: invalidCertPaths.clientPublicKeyPath,
					CaCertPath:     validCertPaths.caCertPath,
				}
				b, err := json.Marshal(v)
				require.NoError(t, err)
				return &authn.Token{Type: authn.MTLS, Value: b, ExpiredAt: clock.UnixNano(time.Now().Add(1 * time.Hour).UnixNano())}
			},
			res: authn.ValidationResult{Status: authn.InvalidStatus},
		},
		{
			name: "valid cert/key pair",
			tknFn: func() *authn.Token {
				v := provider.MTLSCredentialsValue{
					PrivateKeyPath: validCertPaths.clientPrivateKeyPath,
					PublicCertPath: validCertPaths.clientPublicKeyPath,
					CaCertPath:     validCertPaths.caCertPath,
				}
				b, err := json.Marshal(v)
				require.NoError(t, err)
				return &authn.Token{Type: authn.MTLS, Value: b, ExpiredAt: clock.UnixNano(time.Now().Add(1 * time.Hour).UnixNano())}
			},
			res: authn.ValidationResult{Status: authn.ValidStatus},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			res, err := subj.Validate(ctx, tt.tknFn())

			// then
			assert.NoError(t, err)
			assert.Equal(t, tt.res, res)
		})
	}
}

func TestMTLSVerify(t *testing.T) {
	// given
	ctx := t.Context()
	validCertPaths := newTestPKI(t)
	invalidCertPaths := newTestPKI(t)
	subj := &provider.MTLS{}
	tts := []struct {
		name    string
		credFn  func() *authn.Credentials
		wantErr bool
	}{
		{
			name:    "nil credentials",
			credFn:  func() *authn.Credentials { return nil },
			wantErr: true,
		},
		{
			name:    "invalid type",
			credFn:  func() *authn.Credentials { return &authn.Credentials{Type: "invalid"} },
			wantErr: true,
		},
		{
			name: "invalid value",
			credFn: func() *authn.Credentials {
				return &authn.Credentials{Type: authn.MTLS, Value: []byte("invalid")}
			},
			wantErr: true,
		},
		{
			name: "if a non existing private key file is used, return error",
			credFn: func() *authn.Credentials {
				v := provider.MTLSCredentialsValue{
					PrivateKeyPath: "/non/existing/path/client-key.pem",
					PublicCertPath: validCertPaths.clientPublicKeyPath,
					CaCertPath:     validCertPaths.caCertPath,
				}
				b, err := json.Marshal(v)
				require.NoError(t, err)
				return &authn.Credentials{Type: authn.MTLS, Value: b}
			},
			wantErr: true,
		},
		{
			name: "if a non existing public key file is used, return error",
			credFn: func() *authn.Credentials {
				v := provider.MTLSCredentialsValue{
					PrivateKeyPath: validCertPaths.clientPrivateKeyPath,
					PublicCertPath: "/non/existing/path/client.pem",
					CaCertPath:     validCertPaths.caCertPath,
				}
				b, err := json.Marshal(v)
				require.NoError(t, err)
				return &authn.Credentials{Type: authn.MTLS, Value: b}
			},
			wantErr: true,
		},
		{
			name: "if a non existing ca cert file is used, return error",
			credFn: func() *authn.Credentials {
				v := provider.MTLSCredentialsValue{
					PrivateKeyPath: validCertPaths.clientPrivateKeyPath,
					PublicCertPath: validCertPaths.clientPublicKeyPath,
					CaCertPath:     "/non/existing/path/ca.pem",
				}
				b, err := json.Marshal(v)
				require.NoError(t, err)
				return &authn.Credentials{Type: authn.MTLS, Value: b}
			},
			wantErr: true,
		},
		{
			name: "if different ca is used, return error",
			credFn: func() *authn.Credentials {
				v := provider.MTLSCredentialsValue{
					PrivateKeyPath: validCertPaths.clientPrivateKeyPath,
					PublicCertPath: validCertPaths.clientPublicKeyPath,
					CaCertPath:     invalidCertPaths.caCertPath,
				}
				b, err := json.Marshal(v)
				require.NoError(t, err)
				return &authn.Credentials{Type: authn.MTLS, Value: b}
			},
			wantErr: true,
		},
		{
			name: "if different key is used, return error",
			credFn: func() *authn.Credentials {
				v := provider.MTLSCredentialsValue{
					PrivateKeyPath: invalidCertPaths.clientPrivateKeyPath,
					PublicCertPath: validCertPaths.clientPublicKeyPath,
					CaCertPath:     validCertPaths.caCertPath,
				}
				b, err := json.Marshal(v)
				require.NoError(t, err)
				return &authn.Credentials{Type: authn.MTLS, Value: b}
			},
			wantErr: true,
		},
		{
			name: "if different cert is used, return error",
			credFn: func() *authn.Credentials {
				v := provider.MTLSCredentialsValue{
					PrivateKeyPath: validCertPaths.clientPrivateKeyPath,
					PublicCertPath: invalidCertPaths.clientPublicKeyPath,
					CaCertPath:     validCertPaths.caCertPath,
				}
				b, err := json.Marshal(v)
				require.NoError(t, err)
				return &authn.Credentials{Type: authn.MTLS, Value: b}
			},
			wantErr: true,
		},
		{
			name: "valid cert/key pair",
			credFn: func() *authn.Credentials {
				v := provider.MTLSCredentialsValue{
					PrivateKeyPath: validCertPaths.clientPrivateKeyPath,
					PublicCertPath: validCertPaths.clientPublicKeyPath,
					CaCertPath:     validCertPaths.caCertPath,
				}
				b, err := json.Marshal(v)
				require.NoError(t, err)
				return &authn.Credentials{Type: authn.MTLS, Value: b}
			},
			wantErr: false,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			tkn, err := subj.Verify(ctx, tt.credFn())

			// then
			if !tt.wantErr {
				require.NoError(t, err)
				assert.Equal(t, authn.MTLS, tkn.Type)
				assert.NotEmpty(t, tkn.Value)
				assert.Zero(t, tkn.ExpiredAt)
			} else {
				assert.ErrorIs(t, err, authn.ErrInvalidCredentials)
				assert.Nil(t, tkn)
			}
		})
	}
}

func TestMTLSCredentialValueTLSConfig(t *testing.T) {
	// given
	pki := newTestPKI(t)
	tts := []struct {
		name    string
		subjFn  func() *provider.MTLSCredentialsValue
		wantErr bool
	}{
		{
			name: "invalid private key path",
			subjFn: func() *provider.MTLSCredentialsValue {
				return &provider.MTLSCredentialsValue{
					PrivateKeyPath: "/non/existing/path/client-key.pem",
					PublicCertPath: pki.clientPublicKeyPath,
					CaCertPath:     pki.caCertPath,
				}
			},
			wantErr: true,
		},
		{
			name: "invalid public key path",
			subjFn: func() *provider.MTLSCredentialsValue {
				return &provider.MTLSCredentialsValue{
					PrivateKeyPath: pki.clientPrivateKeyPath,
					PublicCertPath: "/non/existing/path/client.pem",
					CaCertPath:     pki.caCertPath,
				}
			},
			wantErr: true,
		},
		{
			name: "invalid ca cert path",
			subjFn: func() *provider.MTLSCredentialsValue {
				return &provider.MTLSCredentialsValue{
					PrivateKeyPath: pki.clientPrivateKeyPath,
					PublicCertPath: pki.clientPublicKeyPath,
					CaCertPath:     "/non/existing/path/ca.pem",
				}
			},
			wantErr: true,
		},
		{
			name: "valid cert/key pair",
			subjFn: func() *provider.MTLSCredentialsValue {
				return &provider.MTLSCredentialsValue{
					PrivateKeyPath: pki.clientPrivateKeyPath,
					PublicCertPath: pki.clientPublicKeyPath,
					CaCertPath:     pki.caCertPath,
				}
			},
			wantErr: false,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			tlsConfig, err := tt.subjFn().TLSConfig()

			// then
			if !tt.wantErr {
				require.NoError(t, err)
				assert.NotNil(t, tlsConfig)
				assert.NotNil(t, tlsConfig.Certificates)
				assert.NotEmpty(t, tlsConfig.Certificates)
				assert.NotNil(t, tlsConfig.RootCAs)
			} else {
				assert.Error(t, err)
				assert.Nil(t, tlsConfig)
			}
		})
	}
}

func TestNewMTLSCredentialsValue(t *testing.T) {
	tts := []struct {
		name    string
		subjFn  func() []byte
		wantErr bool
	}{
		{
			name: "valid MTLSCredentialsValue",
			subjFn: func() []byte {
				v := provider.MTLSCredentialsValue{
					PrivateKeyPath: "/path/to/private.key",
					PublicCertPath: "/path/to/public.crt",
					CaCertPath:     "/path/to/ca.crt",
				}
				b, err := json.Marshal(v)
				require.NoError(t, err)
				return b
			},
			wantErr: false,
		},
		{
			name: "invalid JSON",
			subjFn: func() []byte {
				return []byte("invalid")
			},
			wantErr: true,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			v, err := provider.NewMTLSCredentialsValue(tt.subjFn())

			// then
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, v)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, v)
			}
		})
	}
}

func TestMTLSVerifyWithIntermediateCert(t *testing.T) {
	ctx := t.Context()
	pki := newTestPKIWithIntermediate(t)
	subj := &provider.MTLS{}

	tts := []struct {
		name    string
		credFn  func() *authn.Credentials
		wantErr bool
	}{
		{
			name: "valid chain with intermediate CA",
			credFn: func() *authn.Credentials {
				v := provider.MTLSCredentialsValue{
					PrivateKeyPath: pki.clientPrivateKeyPath,
					PublicCertPath: pki.clientPublicKeyPath,
					CaCertPath:     pki.caCertPath,
				}
				b, err := json.Marshal(v)
				require.NoError(t, err)
				return &authn.Credentials{Type: authn.MTLS, Value: b}
			},
			wantErr: false,
		},
		{
			name: "chain with intermediate but wrong root CA returns error",
			credFn: func() *authn.Credentials {
				wrongRoot := newTestPKI(t)
				v := provider.MTLSCredentialsValue{
					PrivateKeyPath: pki.clientPrivateKeyPath,
					PublicCertPath: pki.clientPublicKeyPath,
					CaCertPath:     wrongRoot.caCertPath,
				}
				b, err := json.Marshal(v)
				require.NoError(t, err)
				return &authn.Credentials{Type: authn.MTLS, Value: b}
			},
			wantErr: true,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			tkn, err := subj.Verify(ctx, tt.credFn())

			// then
			if !tt.wantErr {
				require.NoError(t, err)
				assert.Equal(t, authn.MTLS, tkn.Type)
				assert.NotEmpty(t, tkn.Value)
				assert.Zero(t, tkn.ExpiredAt)
			} else {
				assert.Error(t, err)
				assert.Nil(t, tkn)
			}
		})
	}
}

type testPKI struct {
	caCertPath           string
	clientPublicKeyPath  string
	clientPrivateKeyPath string
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "gen CA key")
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err, "sign CA")
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err, "parse CA")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	clientCertPEM, clientKeyPEM := issueCert(t, caCert, caKey, pkix.Name{CommonName: "client"}, true, nil)
	pki := &testPKI{}

	dir := t.TempDir()
	pki.caCertPath = filepath.Join(dir, "ca.pem")
	writeFile(t, pki.caCertPath, caPEM)

	pki.clientPublicKeyPath = filepath.Join(dir, "client.pem")
	writeFile(t, pki.clientPublicKeyPath, clientCertPEM)

	pki.clientPrivateKeyPath = filepath.Join(dir, "client-key.pem")
	writeFile(t, pki.clientPrivateKeyPath, clientKeyPEM)

	return pki
}

func issueCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, subject pkix.Name, client bool, ips []net.IP) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "gen key for %s", subject.CommonName)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err, "gen serial")
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IPAddresses:  ips,
	}
	if client {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	require.NoError(t, err, "sign cert for %s", subject.CommonName)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err, "marshal key for %s", subject.CommonName)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// newTestPKIWithIntermediate creates a 3-level chain: Root CA → Intermediate CA → Leaf cert.
// The client cert PEM file contains both the leaf and intermediate certs so that
// tls.LoadX509KeyPair loads them into cert.Certificate[0] and cert.Certificate[1].
func newTestPKIWithIntermediate(t *testing.T) *testPKI {
	t.Helper()

	// --- Root CA ---
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "gen root CA key")
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-root-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	require.NoError(t, err, "sign root CA")
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err, "parse root CA")
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})

	// --- Intermediate CA ---
	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "gen intermediate CA key")
	intTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test-intermediate-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, rootCert, &intKey.PublicKey, rootKey)
	require.NoError(t, err, "sign intermediate CA")
	intCert, err := x509.ParseCertificate(intDER)
	require.NoError(t, err, "parse intermediate CA")
	intPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intDER})

	// --- Leaf client cert (signed by intermediate) ---
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "gen leaf key")
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err, "gen serial")
	leafTmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "client-with-intermediate"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, intCert, &leafKey.PublicKey, intKey)
	require.NoError(t, err, "sign leaf cert")
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	leafKeyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	require.NoError(t, err, "marshal leaf key")
	leafKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER})

	// --- Write files ---
	dir := t.TempDir()
	pki := &testPKI{}

	// CA file contains only the root
	pki.caCertPath = filepath.Join(dir, "root-ca.pem")
	writeFile(t, pki.caCertPath, rootPEM)

	// Client cert file contains leaf + intermediate (bundle)
	certBundle := append(leafPEM, intPEM...)
	pki.clientPublicKeyPath = filepath.Join(dir, "client.pem")
	writeFile(t, pki.clientPublicKeyPath, certBundle)

	pki.clientPrivateKeyPath = filepath.Join(dir, "client-key.pem")
	writeFile(t, pki.clientPrivateKeyPath, leafKeyPEM)

	return pki
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, data, 0o600), "write %s", path)
}
