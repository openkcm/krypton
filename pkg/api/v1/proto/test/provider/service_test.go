package provider_test

import (
	"os"
	"path/filepath"
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

func TestServiceInstanceLifecycle(t *testing.T) {
	service := newService(t)
	instanceID := uuid.New().String()

	_, err := service.UpsertInstance(t.Context(), &provider.UpsertInstanceRequest{InstanceId: instanceID})
	require.NoError(t, err)

	_, err = service.UpsertKey(t.Context(), &provider.UpsertKeyRequest{
		InstanceId: instanceID,
		KeyId:      "key:1",
	})
	require.NoError(t, err)

	_, err = service.UpsertKeyAuth(t.Context(), &provider.UpsertKeyAuthRequest{
		InstanceId:  instanceID,
		KeyId:       "key:1",
		AccessToken: "token",
	})
	require.NoError(t, err)

	_, err = service.DeleteInstance(t.Context(), &provider.DeleteInstanceRequest{InstanceId: instanceID})
	require.NoError(t, err)
}

func TestServiceRejectsBadRequests(t *testing.T) {
	service := newService(t)
	instanceID := uuid.New().String()
	require.NoError(t, upsertInstance(t, service, instanceID))

	tests := []struct {
		name string
		call func() error
	}{
		{"upsert instance rejects a missing request", func() error {
			_, err := service.UpsertInstance(t.Context(), nil)
			return err
		}},
		{"upsert key rejects an empty key ID", func() error {
			_, err := service.UpsertKey(t.Context(), &provider.UpsertKeyRequest{InstanceId: instanceID})
			return err
		}},
		{"upsert key auth rejects an empty instance ID", func() error {
			_, err := service.UpsertKeyAuth(t.Context(), &provider.UpsertKeyAuthRequest{KeyId: "key", AccessToken: "token"})
			return err
		}},
		{"upsert key auth rejects an empty key ID", func() error {
			_, err := service.UpsertKeyAuth(t.Context(), &provider.UpsertKeyAuthRequest{InstanceId: instanceID, AccessToken: "token"})
			return err
		}},
		{"upsert key auth rejects an empty token", func() error {
			_, err := service.UpsertKeyAuth(t.Context(), &provider.UpsertKeyAuthRequest{InstanceId: instanceID, KeyId: "key"})
			return err
		}},
		{"delete rejects an empty instance ID", func() error {
			_, err := service.DeleteInstance(t.Context(), &provider.DeleteInstanceRequest{})
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertStatus(t, tt.call(), codes.InvalidArgument, proto.Code_ERROR_CODE_ABORT)
		})
	}
}

func TestServiceReportsMissingInstances(t *testing.T) {
	service := newService(t)
	instanceID := uuid.New().String()

	tests := []struct {
		name string
		call func() error
	}{
		{"upsert key", func() error {
			_, err := service.UpsertKey(t.Context(), &provider.UpsertKeyRequest{InstanceId: instanceID, KeyId: "key"})
			return err
		}},
		{"upsert key auth", func() error {
			_, err := service.UpsertKeyAuth(t.Context(), &provider.UpsertKeyAuthRequest{InstanceId: instanceID, KeyId: "key", AccessToken: "token"})
			return err
		}},
		{"delete instance", func() error {
			_, err := service.DeleteInstance(t.Context(), &provider.DeleteInstanceRequest{InstanceId: instanceID})
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertStatus(t, tt.call(), codes.NotFound, proto.Code_ERROR_CODE_ABORT)
		})
	}
}

func TestServiceMarksProviderFailuresRetryable(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "provider")
	configureTestProvider(t, dir)
	testProvider, err := providertest.New()
	require.NoError(t, err)
	require.NoError(t, os.Remove(dir))
	require.NoError(t, os.WriteFile(dir, []byte("not a directory"), 0o600))

	_, err = provider.NewService(testProvider).UpsertInstance(t.Context(), &provider.UpsertInstanceRequest{InstanceId: uuid.New().String()})
	assertStatus(t, err, codes.Internal, proto.Code_ERROR_CODE_RETRY)
}

func newService(t *testing.T) *provider.Service {
	t.Helper()
	configureTestProvider(t, t.TempDir())
	testProvider, err := providertest.New()
	require.NoError(t, err)
	return provider.NewService(testProvider)
}

func configureTestProvider(t *testing.T, dir string) {
	t.Helper()
	t.Setenv(providertest.EnableEnv, providertest.EnableAck)
	t.Setenv(providertest.DirectoryEnv, dir)
}

func upsertInstance(t *testing.T, service *provider.Service, instanceID string) error {
	t.Helper()
	_, err := service.UpsertInstance(t.Context(), &provider.UpsertInstanceRequest{InstanceId: instanceID})
	return err
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
