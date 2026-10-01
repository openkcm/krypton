package actions_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"uuid"

	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/openkcm/krypton/internal/handler/announcekey"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/actions"
)

type fakeStore struct {
	group orbital.JobGroup
	found bool
	err   error

	gotID uuid.UUID
}

func (f *fakeStore) GetJobGroup(_ context.Context, id uuid.UUID) (orbital.JobGroup, bool, error) {
	f.gotID = id
	return f.group, f.found, f.err
}

// setupActionClient wires the ActionService against the given store over an
// in-memory bufconn connection and returns a client for it.
func setupActionClient(t *testing.T, store actions.JobGroupStore) actions.ActionServiceClient {
	t.Helper()

	srv := grpc.NewServer()
	actions.RegisterActionServiceServer(srv, actions.NewService(store))

	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)
	go func() {
		if err := srv.Serve(lis); err != nil {
			assert.Fail(t, "action service server error", err)
		}
	}()
	dialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}

	t.Cleanup(func() {
		srv.GracefulStop()
	})

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		conn.Close()
	})

	return actions.NewActionServiceClient(conn)
}

func assertErrorDetails(t *testing.T, expCode proto.Code, actErr error) {
	t.Helper()

	st := status.Convert(actErr)
	dts := st.Details()
	require.Len(t, dts, 1, "expected 1 error detail")

	dt, ok := dts[0].(*proto.ErrorDetails)
	require.True(t, ok, "expected error details of type proto.ErrorDetails")
	assert.Equal(t, expCode, dt.GetCode())
}

func TestGetAction_Errors(t *testing.T) {
	validID := uuid.New()

	tests := []struct {
		name       string
		reqID      string
		store      *fakeStore
		wantCode   codes.Code
		wantDetail proto.Code
	}{
		{
			name:       "invalid uuid",
			reqID:      "not-a-uuid",
			store:      &fakeStore{},
			wantCode:   codes.InvalidArgument,
			wantDetail: proto.Code_ERROR_CODE_ABORT,
		},
		{
			name:       "store error",
			reqID:      validID.String(),
			store:      &fakeStore{err: errors.New("boom")},
			wantCode:   codes.Internal,
			wantDetail: proto.Code_ERROR_CODE_RETRY,
		},
		{
			name:       "not found",
			reqID:      validID.String(),
			store:      &fakeStore{found: false},
			wantCode:   codes.NotFound,
			wantDetail: proto.Code_ERROR_CODE_ABORT,
		},
		{
			name:       "unknown job group type",
			reqID:      validID.String(),
			store:      &fakeStore{found: true, group: orbital.JobGroup{ID: validID, Type: "mystery"}},
			wantCode:   codes.NotFound,
			wantDetail: proto.Code_ERROR_CODE_ABORT,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli := setupActionClient(t, tt.store)

			resp, err := cli.GetAction(context.Background(), &actions.GetActionRequest{Id: tt.reqID})

			require.Error(t, err)
			assert.Nil(t, resp)
			assert.Equal(t, tt.wantCode, status.Code(err))
			assertErrorDetails(t, tt.wantDetail, err)
		})
	}
}

func TestGetAction_Success(t *testing.T) {
	id := uuid.New()
	store := &fakeStore{
		found: true,
		group: orbital.JobGroup{
			ID:        id,
			Type:      announcekey.JobGroupType,
			Status:    orbital.JobGroupStatusProcessing,
			CreatedAt: 100,
			UpdatedAt: 200,
			Labels: orbital.Labels{
				actions.LabelKeyTargetType: actions.TargetType_TARGET_TYPE_KEY.String(),
				actions.LabelKeyTargetID:   "tenant-1:key-1",
				actions.LabelKeyCascading:  "true",
			},
		},
	}
	cli := setupActionClient(t, store)

	resp, err := cli.GetAction(context.Background(), &actions.GetActionRequest{Id: id.String()})
	require.NoError(t, err)

	assert.Equal(t, id, store.gotID, "request id is parsed and forwarded to the store")

	a := resp.GetAction()
	require.NotNil(t, a)
	assert.Equal(t, id.String(), a.GetId())
	assert.Equal(t, actions.ActionType_ANNOUNCE_KEY, a.GetType())
	assert.Equal(t, string(orbital.JobGroupStatusProcessing), a.GetStatus())
	assert.Equal(t, actions.TargetType_TARGET_TYPE_KEY, a.GetTargetType())
	assert.Equal(t, "tenant-1:key-1", a.GetTargetId())
	assert.True(t, a.GetCascading())
	assert.Equal(t, int64(100), a.GetCreatedAt())
	assert.Equal(t, int64(200), a.GetUpdatedAt())
}

func TestGetAction_DefaultsWhenLabelsAbsent(t *testing.T) {
	id := uuid.New()
	store := &fakeStore{
		found: true,
		group: orbital.JobGroup{
			ID:     id,
			Type:   announcekey.JobGroupType,
			Labels: orbital.Labels{actions.LabelKeyCascading: "notabool"},
		},
	}
	cli := setupActionClient(t, store)

	resp, err := cli.GetAction(context.Background(), &actions.GetActionRequest{Id: id.String()})
	require.NoError(t, err)

	a := resp.GetAction()
	require.NotNil(t, a)
	assert.Equal(t, actions.TargetType_TARGET_TYPE_UNSPECIFIED, a.GetTargetType())
	assert.Empty(t, a.GetTargetId())
	assert.False(t, a.GetCascading())
}
