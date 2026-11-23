package awskms

import (
	"context"
	"errors"
	"maps"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/securemem"
)

const testKeyARN = "arn:aws:kms:eu-central-1:111122223333:key/1234abcd"

var (
	errKMS             = errors.New("kms unavailable")
	errContextMismatch = errors.New("invalid ciphertext")
)

type fakeKMS struct {
	err      error
	keyIDs   []string
	contexts map[string]map[string]string
}

func (f *fakeKMS) Encrypt(_ context.Context, in *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	f.keyIDs = append(f.keyIDs, *in.KeyId)
	if f.err != nil {
		return nil, f.err
	}
	blob := slices.Clone(in.Plaintext)
	slices.Reverse(blob)
	if f.contexts == nil {
		f.contexts = map[string]map[string]string{}
	}
	f.contexts[string(blob)] = in.EncryptionContext
	return &kms.EncryptOutput{CiphertextBlob: blob}, nil
}

func (f *fakeKMS) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	f.keyIDs = append(f.keyIDs, *in.KeyId)
	if f.err != nil {
		return nil, f.err
	}
	if !maps.Equal(f.contexts[string(in.CiphertextBlob)], in.EncryptionContext) {
		return nil, errContextMismatch
	}
	plain := slices.Clone(in.CiphertextBlob)
	slices.Reverse(plain)
	return &kms.DecryptOutput{Plaintext: plain}, nil
}

func secureData(t *testing.T, b []byte) *securemem.Data {
	t.Helper()
	d, err := securemem.NewData("test", len(b))
	require.NoError(t, err)
	copy(d.SecureBytes(), b)
	return d
}

func keyMetadata() map[string]string {
	return map[string]string{sealer.ProviderKeyMetadataKey(TypeAwsKms): testKeyARN}
}

func TestSealUnsealRoundTrip(t *testing.T) {
	// given
	fake := &fakeKMS{}
	client := &Client{kms: fake}
	secret := []byte("a 32 byte secret for the l2 key!")

	// when
	sealed, err := client.Seal(t.Context(), sealer.SealRequest{
		TenantID:  "t-1",
		Plaintext: secureData(t, secret),
		AAD:       []byte("t-1:dk-1:1:1"),
		Metadata:  keyMetadata(),
	})
	require.NoError(t, err)
	unsealed, err := client.Unseal(t.Context(), sealer.UnsealRequest{
		TenantID:   "t-1",
		Ciphertext: sealed.Ciphertext,
		AAD:        []byte("t-1:dk-1:1:1"),
		Metadata:   keyMetadata(),
	})

	// then
	require.NoError(t, err)
	assert.NotEqual(t, secret, sealed.Ciphertext.SecureBytes())
	assert.Equal(t, secret, []byte(unsealed.Plaintext.SecureBytes()))
	assert.Equal(t, []string{testKeyARN, testKeyARN}, fake.keyIDs)
	assert.Equal(t, map[string]string{"tenant": "t-1", "aad": "t-1:dk-1:1:1"},
		fake.contexts[string(sealed.Ciphertext.SecureBytes())])
}

func TestUnsealWithOtherAAD(t *testing.T) {
	// given
	client := &Client{kms: &fakeKMS{}}
	sealed, err := client.Seal(t.Context(), sealer.SealRequest{
		TenantID:  "t-1",
		Plaintext: secureData(t, []byte("secret")),
		AAD:       []byte("t-1:dk-1:1:1"),
		Metadata:  keyMetadata(),
	})
	require.NoError(t, err)

	// when
	_, err = client.Unseal(t.Context(), sealer.UnsealRequest{
		TenantID:   "t-1",
		Ciphertext: sealed.Ciphertext,
		AAD:        []byte("t-1:dk-2:1:1"),
		Metadata:   keyMetadata(),
	})

	// then
	require.ErrorIs(t, err, ErrDecrypt)
	require.ErrorIs(t, err, errContextMismatch)
}

func TestEncryptionContextWithoutValues(t *testing.T) {
	assert.Nil(t, encryptionContext("", nil))
}

func TestSealWithoutKeyARN(t *testing.T) {
	// given
	fake := &fakeKMS{}
	client := &Client{kms: fake}

	// when
	_, err := client.Seal(t.Context(), sealer.SealRequest{Plaintext: secureData(t, []byte("secret"))})

	// then
	require.ErrorIs(t, err, ErrKeyARNMissing)
	assert.Empty(t, fake.keyIDs)
}

func TestKMSErrors(t *testing.T) {
	// given
	client := &Client{kms: &fakeKMS{err: errKMS}}

	// when
	_, sealErr := client.Seal(t.Context(), sealer.SealRequest{
		Plaintext: secureData(t, []byte("secret")),
		Metadata:  keyMetadata(),
	})
	_, unsealErr := client.Unseal(t.Context(), sealer.UnsealRequest{
		Ciphertext: secureData(t, []byte("blob")),
		Metadata:   keyMetadata(),
	})

	// then
	require.ErrorIs(t, sealErr, ErrEncrypt)
	require.ErrorIs(t, sealErr, errKMS)
	require.ErrorIs(t, unsealErr, ErrDecrypt)
	require.ErrorIs(t, unsealErr, errKMS)
}
