package announcekey_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/reconciler/handler/announcekey"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

type fakeKeyStore struct {
	keys          map[string]*model.Key
	updateStateFn func(ctx context.Context, query store.UpdateKeyStateQuery) error
}

func newFakeKeyStore() *fakeKeyStore {
	return &fakeKeyStore{keys: make(map[string]*model.Key)}
}

func (f *fakeKeyStore) CreateKey(_ context.Context, key model.Key) error {
	f.keys[key.ID] = &key
	return nil
}

func (f *fakeKeyStore) GetKeyByID(_ context.Context, id, tenantID string) (*model.Key, error) {
	k, ok := f.keys[id]
	if !ok || k.TenantID != tenantID {
		return nil, store.ErrKeyNotFound
	}
	return k, nil
}

func (f *fakeKeyStore) GetParentKeys(_ context.Context, _ store.GetParentKeysQuery) (store.GetParentKeysResult, error) {
	return store.GetParentKeysResult{}, nil
}

func (f *fakeKeyStore) GetDescendantKeys(_ context.Context, _ store.GetDescendantKeysQuery) (store.GetDescendantKeysResult, error) {
	return store.GetDescendantKeysResult{}, nil
}

func (f *fakeKeyStore) UpdateKeyState(ctx context.Context, query store.UpdateKeyStateQuery) error {
	if f.updateStateFn != nil {
		return f.updateStateFn(ctx, query)
	}
	k, ok := f.keys[query.ID]
	if !ok || k.TenantID != query.TenantID {
		return store.ErrKeyNotFound
	}
	k.State = query.NewState
	return nil
}

func TestOnJobFailed(t *testing.T) {
	t.Run("should update key state to announce-failed", func(t *testing.T) {
		keyStore := newFakeKeyStore()
		key := model.NewKey("tenant-1", "test-key", "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), key))

		handler := announcekey.NewHandler(keyStore)

		data := announcekey.TaskData{
			KeyID:    key.ID,
			TenantID: key.TenantID,
			Kind:     "K0",
			Name:     "test-key",
			Target:   "root",
		}
		jobData, err := json.Marshal(data)
		require.NoError(t, err)

		job := orbital.Job{
			ID:           uuid.Must(uuid.NewUUID()),
			Data:         jobData,
			Type:         announcekey.JobType,
			ErrorMessage: "agent failed",
		}

		err = handler.OnJobFailed(t.Context(), job)
		assert.NoError(t, err)
		assert.Equal(t, model.KeyStateAnnounceFailed, keyStore.keys[key.ID].State)
	})

	t.Run("should return error on invalid job data", func(t *testing.T) {
		handler := announcekey.NewHandler(newFakeKeyStore())

		job := orbital.Job{
			ID:   uuid.Must(uuid.NewUUID()),
			Data: []byte("invalid"),
			Type: announcekey.JobType,
		}

		err := handler.OnJobFailed(t.Context(), job)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unmarshal job data")
	})

	t.Run("should return error when store update fails", func(t *testing.T) {
		storeErr := errors.New("db error")
		keyStore := newFakeKeyStore()
		keyStore.updateStateFn = func(_ context.Context, _ store.UpdateKeyStateQuery) error {
			return storeErr
		}

		handler := announcekey.NewHandler(keyStore)

		data := announcekey.TaskData{
			KeyID:    "key-1",
			TenantID: "tenant-1",
			Kind:     "K0",
			Name:     "test-key",
			Target:   "root",
		}
		jobData, err := json.Marshal(data)
		require.NoError(t, err)

		job := orbital.Job{
			ID:   uuid.Must(uuid.NewUUID()),
			Data: jobData,
			Type: announcekey.JobType,
		}

		err = handler.OnJobFailed(t.Context(), job)
		assert.ErrorIs(t, err, storeErr)
	})
}

func TestOnJobCanceled(t *testing.T) {
	t.Run("should update key state to announce-failed", func(t *testing.T) {
		keyStore := newFakeKeyStore()
		key := model.NewKey("tenant-1", "test-key", "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), key))

		handler := announcekey.NewHandler(keyStore)

		data := announcekey.TaskData{
			KeyID:    key.ID,
			TenantID: key.TenantID,
			Kind:     "K0",
			Name:     "test-key",
			Target:   "root",
		}
		jobData, err := json.Marshal(data)
		require.NoError(t, err)

		job := orbital.Job{
			ID:   uuid.Must(uuid.NewUUID()),
			Data: jobData,
			Type: announcekey.JobType,
		}

		err = handler.OnJobCanceled(t.Context(), job)
		assert.NoError(t, err)
		assert.Equal(t, model.KeyStateAnnounceFailed, keyStore.keys[key.ID].State)
	})
}
