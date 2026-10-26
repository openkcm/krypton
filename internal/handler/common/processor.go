package common

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/grpcconn"
	"github.com/openkcm/krypton/internal/handler"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents/keys"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents/keyversions"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

type State struct {
	Manager    *keyprocessor.Manager
	Config     *config.RootConfig
	Registry   *grpcconn.Registry
	Stores     store.Stores
	Key        *model.Key
	KeyVersion *model.KeyVersion
	IsNewKV    bool
	RootName   string
}

var (
	ErrKeyVersionNotFound      = errors.New("key version not found")
	ErrNoParentKeyVersionFound = errors.New("no parent key version found")
	ErrInternalError           = errors.New("internal error")
)

func NewProcessor(
	rootName string,
	manager *keyprocessor.Manager,
	cfg *config.RootConfig,
	registry *grpcconn.Registry,
	stores store.Stores,
) (*State, *OrbitalResponseError) {
	return &State{
		RootName: rootName,
		Manager:  manager,
		Config:   cfg,
		Registry: registry,
		Stores:   stores,
	}, nil
}

func (s *State) LoadKeyAndVersions(ctx context.Context, kid handler.KeyIdentifier) *OrbitalResponseError {
	or := s.loadKey(ctx, kid)
	if or != nil {
		return or
	}

	or = s.loadKeyVersions(ctx)
	if or != nil {
		return or
	}

	return nil
}

func (s *State) MarkKeyFailed(ctx context.Context, failedErr error) *OrbitalResponseError {
	if s.Key == nil {
		return OrbitalFail(fmt.Errorf("%w: key is nil", ErrInternalError))
	}

	ks := s.Stores.Keys
	key := s.Key

	err := ks.UpdateKeyStates(ctx, store.UpdateKeyStatesQuery{
		ID:         key.ID,
		TenantID:   key.TenantID,
		FromState:  []model.KeyLifeCycleState{key.LifeCycleState},
		ToState:    key.LifeCycleState,
		FromStatus: []model.KeyProcessingStatus{key.KeyProcessingState.Status},
		ToStatus:   model.KeyProcessingFailed,
	})
	if err != nil {
		return OrbitalContinue(err)
	}
	// this error should not happen, but if it does, we will retry the task
	return OrbitalFail(failedErr)
}

func (s *State) GenerateAndSealSecret(ctx context.Context) *OrbitalResponseError {
	if s.Key == nil {
		return OrbitalFail(fmt.Errorf("%w: key is nil", ErrInternalError))
	}
	if s.KeyVersion == nil {
		return s.MarkKeyFailed(ctx, fmt.Errorf("%w: key version is nil", ErrInternalError))
	}
	if s.Manager == nil {
		return s.MarkKeyFailed(ctx, fmt.Errorf("%w: key processor manager is nil", ErrInternalError))
	}
	if s.RootName == "" {
		return s.MarkKeyFailed(ctx, fmt.Errorf("%w: root name is empty", ErrInternalError))
	}

	key := s.Key
	isManagedByRoot := key.ManagedBy == s.RootName

	// check if key is root key
	isRootKey, or := s.isRootKey(ctx)
	if or != nil {
		return or
	}

	// check if the key is managed by root and is not a root key, if so, we need to generate and seal the secret for this key version
	if !isManagedByRoot || isRootKey || !s.IsNewKV {
		return nil
	}

	kv := s.KeyVersion
	aad := fmt.Appendf(nil, "%s:%s:%d:%d", key.TenantID, key.ID, kv.Version, kv.Revision)
	_, err := s.Manager.GenerateAndSealSecret(ctx, keyprocessor.GenerateAndSealSecretRequest{
		KeyVersion: *kv,
		AAD:        aad,
		KeyKind:    key.Kind,
	})
	if err != nil {
		return OrbitalContinue(err)
	}
	return nil
}

func (s *State) UpsertRemote(ctx context.Context) *OrbitalResponseError {
	if s.Key == nil {
		return OrbitalFail(fmt.Errorf("%w: key is nil", ErrInternalError))
	}
	if s.KeyVersion == nil {
		return s.MarkKeyFailed(ctx, fmt.Errorf("%w: key version is nil", ErrInternalError))
	}
	if s.Registry == nil {
		return s.MarkKeyFailed(ctx, fmt.Errorf("%w: registry is nil, cannot upsert key version", ErrInternalError))
	}

	managedBy := s.Key.ManagedBy
	isManagedByRoot := managedBy == s.RootName

	if isManagedByRoot {
		return nil
	}

	conn, ok := s.Registry.Get(managedBy)
	if !ok {
		return s.MarkKeyFailed(ctx, fmt.Errorf("no connection found for agent %s", managedBy))
	}

	or := s.upsertRemoteKey(ctx, conn)
	if or != nil {
		return or
	}

	return s.upsertRemoteKeyVersion(ctx, conn)
}

func (s *State) MarkKeyAsActiveAndComplete(ctx context.Context) *OrbitalResponseError {
	if s.Key == nil {
		return OrbitalFail(fmt.Errorf("%w: key is nil", ErrInternalError))
	}
	key := s.Key

	err := s.Stores.Keys.UpdateKeyStates(ctx, store.UpdateKeyStatesQuery{
		ID:         key.ID,
		TenantID:   key.TenantID,
		FromState:  []model.KeyLifeCycleState{model.KeyLifeCycleActive},
		ToState:    model.KeyLifeCycleActive,
		FromStatus: []model.KeyProcessingStatus{model.KeyProcessingPending},
		ToStatus:   model.KeyProcessingCompleted,
	})
	if err != nil {
		return OrbitalContinue(err)
	}
	return nil
}

func (s *State) upsertRemoteKey(ctx context.Context, conn *grpc.ClientConn) *OrbitalResponseError {
	k := s.Key
	var parentID string
	if k.ParentID != nil {
		parentID = *k.ParentID
	}

	_, err := keys.NewKeyServiceClient(conn).
		UpsertKey(ctx, &keys.UpsertKeyRequest{
			TenantId:       k.TenantID,
			KeyId:          k.ID,
			Kind:           string(k.Kind),
			Name:           k.Name,
			ParentId:       parentID,
			LifecycleState: string(k.LifeCycleState),
			ManagedBy:      k.ManagedBy,
			Labels:         map[string]string(k.Labels),
		})
	if err == nil {
		return nil
	}

	if proto.Retryable(err) {
		return OrbitalContinue(err)
	}
	return s.MarkKeyFailed(ctx, fmt.Errorf("failed to upsert key to remote agent %s: %w", k.ManagedBy, err))
}

func (s *State) upsertRemoteKeyVersion(ctx context.Context, conn *grpc.ClientConn) *OrbitalResponseError {
	kv := s.KeyVersion
	k := s.Key

	var parentKeyID string
	if kv.ParentKeyID != nil {
		parentKeyID = *kv.ParentKeyID
	}
	var parentKeyVersion int32
	if kv.ParentKeyVersion != nil {
		parentKeyVersion = int32(*kv.ParentKeyVersion)
	}

	_, err := keyversions.NewKeyVersionServiceClient(conn).
		UpsertKeyVersion(ctx, &keyversions.UpsertKeyVersionRequest{
			TenantId:        kv.TenantID,
			KeyId:           kv.KeyID,
			Version:         int32(kv.Version),
			Revision:        int32(kv.Revision),
			ParentId:        parentKeyID,
			ParentVersion:   parentKeyVersion,
			LifecycleState:  string(kv.LifeCycleState),
			ProcessingState: string(kv.ProcessingState),
		})
	if err == nil {
		return nil
	}

	if proto.Retryable(err) {
		return OrbitalContinue(err)
	}

	return s.MarkKeyFailed(ctx, fmt.Errorf("failed to upsert key version to remote agent %s: %w", k.ManagedBy, err))
}

func (s *State) isRootKey(ctx context.Context) (bool, *OrbitalResponseError) {
	if s.Key == nil {
		return false, OrbitalFail(fmt.Errorf("%w: key is nil", ErrInternalError))
	}
	if s.Config == nil {
		return false, s.MarkKeyFailed(ctx, fmt.Errorf("%w: config is nil", ErrInternalError))
	}

	key := s.Key
	kspec, ok := s.Config.Hierarchy.FindKeySpec(key.Kind)
	if !ok {
		return false, s.MarkKeyFailed(ctx, fmt.Errorf("key kind %s not found in hierarchy", key.Kind))
	}
	return kspec.Role == spec.KeyRoleRoot, nil
}

func (s *State) loadKey(ctx context.Context, kid handler.KeyIdentifier) *OrbitalResponseError {
	key, err := s.Stores.Keys.GetKeyByID(ctx, kid.ID, kid.TenantID)
	if err == nil {
		s.Key = key
		return nil
	}

	if errors.Is(err, store.ErrKeyNotFound) {
		return OrbitalFail(fmt.Errorf("key not found: %w", err))
	}

	return OrbitalContinue(err)
}

func (s *State) loadKeyVersions(ctx context.Context) *OrbitalResponseError {
	kv, err := s.fetchAndUpdateExistingKeyVersion(ctx)
	if err == nil {
		s.KeyVersion = kv
		return nil
	}

	if !errors.Is(err, ErrKeyVersionNotFound) {
		return OrbitalContinue(err)
	}

	kv, err = s.createKeyVersionFromParent(ctx)
	if err == nil {
		s.KeyVersion = kv
		s.IsNewKV = true
		return nil
	}

	if errors.Is(err, ErrNoParentKeyVersionFound) {
		return s.MarkKeyFailed(ctx, err)
	}

	return OrbitalContinue(err)
}

func (s *State) fetchAndUpdateExistingKeyVersion(ctx context.Context) (*model.KeyVersion, error) {
	kvStore := s.Stores.KeyVersions
	key := s.Key
	// check if keyversion is already present
	kvList, err := kvStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
		TenantID: key.TenantID,
		KeyID:    key.ID,
		OrderBy: []store.KeyVersionOrder{
			store.KeyVersionOrderVersionDesc,
			store.KeyVersionOrderRevisionDesc,
		},
		Limit: 1,
	})
	if err != nil {
		return nil, err
	}
	if len(kvList.KeyVersions) == 0 {
		return nil, ErrKeyVersionNotFound
	}

	kv := kvList.KeyVersions[0]
	err = kvStore.UpdateKeyVersionStates(ctx, store.UpdateKeyVersionStatesQuery{
		TenantID:            kv.TenantID,
		KeyID:               kv.KeyID,
		Version:             kv.Version,
		Revision:            kv.Revision,
		FromProcessingState: []model.KeyVersionProcessingState{kv.ProcessingState},
		ToProcessingState:   model.KeyVersionUsable,
		FromLifeCycleState:  []model.KeyLifeCycleState{kv.LifeCycleState},
		ToLifeCycleState:    model.KeyLifeCycleActive,
	})
	if err != nil {
		return nil, err
	}
	kv.LifeCycleState = model.KeyLifeCycleActive
	kv.ProcessingState = model.KeyVersionUsable
	return &kv, nil
}

func (s *State) createKeyVersionFromParent(ctx context.Context) (*model.KeyVersion, error) {
	kvStore := s.Stores.KeyVersions
	key := s.Key

	var parentKeyVersion *int
	if key.ParentID != nil {
		// if not there we need to create a new keyversion based on the parent keyversion
		pkv, err := kvStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID:        key.TenantID,
			KeyID:           *key.ParentID,
			ProcessingState: model.KeyVersionUsable,
			LifeCycleState:  model.KeyLifeCycleActive,
			OrderBy: []store.KeyVersionOrder{
				store.KeyVersionOrderVersionDesc,
				store.KeyVersionOrderRevisionDesc,
			},
			Limit: 1,
		})
		if err != nil {
			return nil, err
		}
		if len(pkv.KeyVersions) == 0 {
			return nil, fmt.Errorf("%w: parent key version not found for key %s", ErrNoParentKeyVersionFound, key.ID)
		}
		parentKeyVersion = new(pkv.KeyVersions[0].Version)
	}

	kv := model.NewKeyVersion(key.TenantID, key.ID, 1, key.ParentID, parentKeyVersion)
	kv.LifeCycleState = model.KeyLifeCycleActive
	kv.ProcessingState = model.KeyVersionUsable

	kvres, err := kvStore.CreateKeyVersion(ctx, store.CreateKeyVersionQuery{
		KeyVersion: kv,
	})
	if err != nil {
		return nil, err
	}

	return &kvres.KeyVersion, nil
}
