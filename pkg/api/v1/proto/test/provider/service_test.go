package provider_test

import (
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/sealer/providertest"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	provider "github.com/openkcm/krypton/pkg/api/v1/proto/test/provider"
)

func TestServiceKeyLifecycle(t *testing.T) {
	testProvider, err := providertest.New(t.Context())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, testProvider.Close()) })

	service := provider.NewService(testProvider)

	created, err := service.CreateKey(t.Context(), &provider.CreateKeyRequest{})
	require.NoError(t, err)
	require.NotNil(t, created.GetKeyRef())
	keyID := created.GetKeyRef().GetKeyId()
	assert.NotEmpty(t, keyID)
	assert.NotEmpty(t, created.GetAccessToken())
	assert.Equal(t, int32(1), created.GetKeyRef().GetKeyVersion())

	rotatedAuth, err := service.RotateAuth(t.Context(), &provider.RotateAuthRequest{KeyId: keyID})
	require.NoError(t, err)
	assert.NotEmpty(t, rotatedAuth.GetAccessToken())
	assert.NotEqual(t, created.GetAccessToken(), rotatedAuth.GetAccessToken())

	rotatedKey, err := service.RotateKey(t.Context(), &provider.RotateKeyRequest{KeyId: keyID})
	require.NoError(t, err)
	assert.Equal(t, keyID, rotatedKey.GetKeyRef().GetKeyId())
	assert.Equal(t, int32(2), rotatedKey.GetKeyRef().GetKeyVersion())

	_, err = service.DestroyKey(t.Context(), &provider.DestroyKeyRequest{KeyId: keyID})
	require.NoError(t, err)
}

func TestServiceRejectsBadRequests(t *testing.T) {
	testProvider, err := providertest.New(t.Context())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, testProvider.Close()) })

	service := provider.NewService(testProvider)
	unknownID := uuid.New().String()
	tests := []struct {
		name     string
		call     func() error
		wantCode codes.Code
	}{
		{"rotate auth rejects a missing request", func() error {
			_, err := service.RotateAuth(t.Context(), nil)
			return err
		}, codes.InvalidArgument},
		{"rotate key rejects an empty ID", func() error {
			_, err := service.RotateKey(t.Context(), &provider.RotateKeyRequest{})
			return err
		}, codes.InvalidArgument},
		{"destroy key rejects a malformed ID", func() error {
			_, err := service.DestroyKey(t.Context(), &provider.DestroyKeyRequest{KeyId: "invalid"})
			return err
		}, codes.InvalidArgument},
		{"rotate auth reports an unknown key", func() error {
			_, err := service.RotateAuth(t.Context(), &provider.RotateAuthRequest{KeyId: unknownID})
			return err
		}, codes.NotFound},
		{"rotate key reports an unknown key", func() error {
			_, err := service.RotateKey(t.Context(), &provider.RotateKeyRequest{KeyId: unknownID})
			return err
		}, codes.NotFound},
		{"destroy key reports an unknown key", func() error {
			_, err := service.DestroyKey(t.Context(), &provider.DestroyKeyRequest{KeyId: unknownID})
			return err
		}, codes.NotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertStatus(t, tt.call(), tt.wantCode, proto.Code_ERROR_CODE_ABORT)
		})
	}
}

func TestServiceMarksProviderFailuresRetryable(t *testing.T) {
	testProvider, err := providertest.New(t.Context())
	require.NoError(t, err)
	require.NoError(t, testProvider.Close())

	_, err = provider.NewService(testProvider).CreateKey(t.Context(), &provider.CreateKeyRequest{})

	assertStatus(t, err, codes.Internal, proto.Code_ERROR_CODE_RETRY)
}

func assertStatus(t *testing.T, err error, wantCode codes.Code, wantFlag proto.Code) {
	t.Helper()
	require.Error(t, err)

	st := status.Convert(err)
	assert.Equal(t, wantCode, st.Code())
	require.Len(t, st.Details(), 1)

	detail, ok := st.Details()[0].(*proto.ErrorDetails)
	require.True(t, ok)
	assert.Equal(t, wantFlag, detail.GetCode())
}
