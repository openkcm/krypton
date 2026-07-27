package cryptor_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/securemem"
)

func TestDecryptRequestValidate(t *testing.T) {
	// given
	validData, err := securemem.NewData("valid", 1)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = validData.Destroy()
	})

	destroyedData, err := securemem.NewData("destroyed", 1)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = destroyedData.Destroy()
	})
	_ = destroyedData.Destroy()

	tts := []struct {
		name    string
		req     cryptor.DecryptRequest
		wantErr error
	}{
		{
			name: "valid request with secret",
			req: cryptor.DecryptRequest{
				Ciphertext: validData,
				Secret: cryptor.Secret{
					Algorithm: cryptor.KeyAlgorithmAES256,
					Data:      validData,
				},
			},
			wantErr: nil,
		},
		{
			name:    "missing ciphertext",
			req:     cryptor.DecryptRequest{},
			wantErr: cryptor.ErrRequest,
		},
		{
			name: "destroyed ciphertext",
			req: cryptor.DecryptRequest{
				Ciphertext: destroyedData,
			},
			wantErr: cryptor.ErrRequest,
		},
		{
			name: "empty ciphertext data",
			req: cryptor.DecryptRequest{
				Ciphertext: &securemem.Data{},
			},
			wantErr: cryptor.ErrRequest,
		},
		{
			name: "empty algorithm in secret",
			req: cryptor.DecryptRequest{
				Ciphertext: validData,
				Secret: cryptor.Secret{
					Data: validData,
				},
			},
			wantErr: cryptor.ErrRequest,
		},
		{
			name: "empty data in secret",
			req: cryptor.DecryptRequest{
				Ciphertext: validData,
				Secret: cryptor.Secret{
					Algorithm: cryptor.KeyAlgorithmAES256,
					Data:      &securemem.Data{},
				},
			},
			wantErr: cryptor.ErrRequest,
		},
		{
			name: "destroyed data in secret",
			req: cryptor.DecryptRequest{
				Ciphertext: validData,
				Secret: cryptor.Secret{
					Algorithm: cryptor.KeyAlgorithmAES256,
					Data:      destroyedData,
				},
			},
			wantErr: cryptor.ErrRequest,
		},
		{
			name: "nil data in secret",
			req: cryptor.DecryptRequest{
				Ciphertext: validData,
				Secret: cryptor.Secret{
					Algorithm: cryptor.KeyAlgorithmAES256,
					Data:      nil,
				},
			},
			wantErr: cryptor.ErrRequest,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			err := tt.req.Validate()

			// then
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestEncryptRequestValidate(t *testing.T) {
	// given
	validData, err := securemem.NewData("valid", 1)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = validData.Destroy()
	})

	destroyedData, err := securemem.NewData("destroyed", 1)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = destroyedData.Destroy()
	})
	_ = destroyedData.Destroy()

	tts := []struct {
		name    string
		req     cryptor.EncryptRequest
		wantErr error
	}{
		{
			name: "valid request with secret",
			req: cryptor.EncryptRequest{
				Plaintext: validData,
				Secret: cryptor.Secret{
					Algorithm: cryptor.KeyAlgorithmAES256,
					Data:      validData,
				},
			},
			wantErr: nil,
		},
		{
			name:    "missing plaintext",
			req:     cryptor.EncryptRequest{},
			wantErr: cryptor.ErrRequest,
		},
		{
			name: "destroyed plaintext",
			req: cryptor.EncryptRequest{
				Plaintext: destroyedData,
			},
			wantErr: cryptor.ErrRequest,
		},
		{
			name: "empty ciphertext data",
			req: cryptor.EncryptRequest{
				Plaintext: &securemem.Data{},
			},
			wantErr: cryptor.ErrRequest,
		},
		{
			name: "empty algorithm in secret",
			req: cryptor.EncryptRequest{
				Plaintext: validData,
				Secret: cryptor.Secret{
					Data: validData,
				},
			},
			wantErr: cryptor.ErrRequest,
		},
		{
			name: "empty data in secret",
			req: cryptor.EncryptRequest{
				Plaintext: validData,
				Secret: cryptor.Secret{
					Algorithm: cryptor.KeyAlgorithmAES256,
					Data:      &securemem.Data{},
				},
			},
			wantErr: cryptor.ErrRequest,
		},
		{
			name: "destroyed data in secret",
			req: cryptor.EncryptRequest{
				Plaintext: validData,
				Secret: cryptor.Secret{
					Algorithm: cryptor.KeyAlgorithmAES256,
					Data:      destroyedData,
				},
			},
			wantErr: cryptor.ErrRequest,
		},
		{
			name: "nil data in secret",
			req: cryptor.EncryptRequest{
				Plaintext: validData,
				Secret: cryptor.Secret{
					Algorithm: cryptor.KeyAlgorithmAES256,
					Data:      nil,
				},
			},
			wantErr: cryptor.ErrRequest,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			err := tt.req.Validate()

			// then
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}
