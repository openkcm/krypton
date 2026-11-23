package awskms

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/securemem"
)

const testKeyARN = "arn:aws:kms:eu-central-1:111122223333:key/1234abcd"

var errKMS = errors.New("kms unavailable")

type fakeKMS struct {
	err    error
	keyIDs []string
}

func (f *fakeKMS) Encrypt(_ context.Context, in *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	f.keyIDs = append(f.keyIDs, *in.KeyId)
	if f.err != nil {
		return nil, f.err
	}
	blob := slices.Clone(in.Plaintext)
	slices.Reverse(blob)
	return &kms.EncryptOutput{CiphertextBlob: blob}, nil
}

func (f *fakeKMS) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	f.keyIDs = append(f.keyIDs, *in.KeyId)
	if f.err != nil {
		return nil, f.err
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
		Plaintext: secureData(t, secret),
		Metadata:  keyMetadata(),
	})
	require.NoError(t, err)
	unsealed, err := client.Unseal(t.Context(), sealer.UnsealRequest{
		Ciphertext: sealed.Ciphertext,
		Metadata:   keyMetadata(),
	})

	// then
	require.NoError(t, err)
	assert.NotEqual(t, secret, sealed.Ciphertext.SecureBytes())
	assert.Equal(t, secret, []byte(unsealed.Plaintext.SecureBytes()))
	assert.Equal(t, []string{testKeyARN, testKeyARN}, fake.keyIDs)
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
