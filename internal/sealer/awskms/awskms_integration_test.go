package awskms

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/sealer"
)

const unknownKeyARN = "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000"

func TestAWSKMSSealUnseal_AWSEmulator(t *testing.T) {
	// given
	emulator := startAWSEmulator(t)
	keyARN := emulator.createKey(t)
	client := emulator.newSealer(emulator.createRole(t, keyARN))
	plaintext := []byte("a 32 byte secret for the l2 key!")
	metadata := map[string]string{sealer.ProviderKeyMetadataKey(TypeAwsKms): keyARN}

	// when
	sealed, err := client.Seal(t.Context(), sealer.SealRequest{
		TenantID:  "tenant-1",
		Plaintext: secureData(t, plaintext),
		AAD:       []byte("tenant-1:dk-1:1:1"),
		Metadata:  metadata,
	})
	require.NoError(t, err)

	unsealed, err := client.Unseal(t.Context(), sealer.UnsealRequest{
		TenantID:   "tenant-1",
		Ciphertext: sealed.Ciphertext,
		AAD:        []byte("tenant-1:dk-1:1:1"),
		Metadata:   metadata,
	})

	// then
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, []byte(sealed.Ciphertext.SecureBytes()))
	assert.Equal(t, plaintext, []byte(unsealed.Plaintext.SecureBytes()))
}

func TestAWSKMSUnseal_OtherContext_AWSEmulator(t *testing.T) {
	// given
	emulator := startAWSEmulator(t)
	keyARN := emulator.createKey(t)
	client := emulator.newSealer(emulator.createRole(t, keyARN))
	metadata := map[string]string{sealer.ProviderKeyMetadataKey(TypeAwsKms): keyARN}

	sealed, err := client.Seal(t.Context(), sealer.SealRequest{
		TenantID:  "tenant-1",
		Plaintext: secureData(t, []byte("secret")),
		AAD:       []byte("tenant-1:dk-1:1:1"),
		Metadata:  metadata,
	})
	require.NoError(t, err)

	tests := []struct {
		name     string
		tenantID string
		aad      string
		wantErr  bool
	}{
		{name: "same context", tenantID: "tenant-1", aad: "tenant-1:dk-1:1:1"},
		{name: "other AAD", tenantID: "tenant-1", aad: "tenant-1:dk-2:1:1", wantErr: true},
		{name: "other tenant", tenantID: "tenant-2", aad: "tenant-1:dk-1:1:1", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			_, err := client.Unseal(t.Context(), sealer.UnsealRequest{
				TenantID:   tt.tenantID,
				Ciphertext: sealed.Ciphertext,
				AAD:        []byte(tt.aad),
				Metadata:   metadata,
			})

			// then
			if !tt.wantErr {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrDecrypt)
			var invalid *types.InvalidCiphertextException
			require.ErrorAs(t, err, &invalid)
		})
	}
}

func TestAWSKMSUnseal_DisabledKey_AWSEmulator(t *testing.T) {
	// given
	emulator := startAWSEmulator(t)
	keyARN := emulator.createKey(t)
	client := emulator.newSealer(emulator.createRole(t, keyARN))
	plaintext := []byte("a 32 byte secret for the l2 key!")
	metadata := map[string]string{sealer.ProviderKeyMetadataKey(TypeAwsKms): keyARN}

	sealed, err := client.Seal(t.Context(), sealer.SealRequest{
		TenantID:  "tenant-1",
		Plaintext: secureData(t, plaintext),
		AAD:       []byte("tenant-1:dk-1:1:1"),
		Metadata:  metadata,
	})
	require.NoError(t, err)

	unseal := func() (sealer.UnsealResponse, error) {
		return client.Unseal(t.Context(), sealer.UnsealRequest{
			TenantID:   "tenant-1",
			Ciphertext: sealed.Ciphertext,
			AAD:        []byte("tenant-1:dk-1:1:1"),
			Metadata:   metadata,
		})
	}

	// when
	emulator.disableKey(t, keyARN)
	_, errDisabled := unseal()
	emulator.enableKey(t, keyARN)
	unsealed, errEnabled := unseal()

	// then
	require.ErrorIs(t, errDisabled, ErrDecrypt)
	var disabled *types.DisabledException
	require.ErrorAs(t, errDisabled, &disabled)

	require.NoError(t, errEnabled)
	assert.Equal(t, plaintext, []byte(unsealed.Plaintext.SecureBytes()))
}

func TestAWSKMSSeal_UnknownKey_AWSEmulator(t *testing.T) {
	// given
	emulator := startAWSEmulator(t)
	client := emulator.newSealer(emulator.createRole(t, emulator.createKey(t)))
	metadata := map[string]string{sealer.ProviderKeyMetadataKey(TypeAwsKms): unknownKeyARN}

	// when
	_, err := client.Seal(t.Context(), sealer.SealRequest{
		TenantID:  "tenant-1",
		Plaintext: secureData(t, []byte("secret")),
		Metadata:  metadata,
	})

	// then
	require.ErrorIs(t, err, ErrEncrypt)
	var notFound *types.NotFoundException
	require.ErrorAs(t, err, &notFound)
}
