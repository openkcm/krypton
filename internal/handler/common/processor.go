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

type Processor struct {
	manager    *keyprocessor.Manager
	config     *config.RootConfig
	registry   *grpcconn.Registry
	stores     store.Stores
	rootName   string
	Key        *model.Key
	KeyVersion *model.KeyVersion
	IsNewKV    bool
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
) *Processor {
	return &Processor{
		rootName: rootName,
		manager:  manager,
		config:   cfg,
		registry: registry,
		stores:   stores,
	}
}

func (p *Processor) ResolveKeyAndVersions(ctx context.Context, kid handler.KeyIdentifier) *OrbitalResponseError {
	or := p.loadKey(ctx, kid)
	if or != nil {
		return or
	}

	or = p.resolveKeyVersions(ctx)
	if or != nil {
		return or
	}

	return nil
}

func (p *Processor) MarkKeyFailed(ctx context.Context, failedErr error) *OrbitalResponseError {
	if p.Key == nil {
		return OrbitalFail(fmt.Errorf("%w: key is nil", ErrInternalError))
	}

	ks := p.stores.Keys
	key := p.Key

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

func (p *Processor) GenerateAndSealSecret(ctx context.Context) *OrbitalResponseError {
	if p.Key == nil {
		return OrbitalFail(fmt.Errorf("%w: key is nil", ErrInternalError))
	}
	if p.KeyVersion == nil {
		return p.MarkKeyFailed(ctx, fmt.Errorf("%w: key version is nil", ErrInternalError))
	}
	if p.manager == nil {
		return p.MarkKeyFailed(ctx, fmt.Errorf("%w: key processor manager is nil", ErrInternalError))
	}
	if p.rootName == "" {
		return p.MarkKeyFailed(ctx, fmt.Errorf("%w: root name is empty", ErrInternalError))
	}
	if p.config == nil {
		return p.MarkKeyFailed(ctx, fmt.Errorf("%w: config is nil", ErrInternalError))
	}

	key := p.Key
	isManagedByRoot := key.ManagedBy == p.rootName

	isRootKey, or := p.isRootKey(ctx)
	if or != nil {
		return or
	}

	skipGeneration := !isManagedByRoot || isRootKey || !p.IsNewKV

	if skipGeneration {
		return nil
	}

	kv := p.KeyVersion
	aad := kv.AAD()
	if aad == nil {
		return p.MarkKeyFailed(ctx, fmt.Errorf("%w: failed to generate AAD for key version", ErrInternalError))
	}

	_, err := p.manager.GenerateAndSealSecret(ctx, keyprocessor.GenerateAndSealSecretRequest{
		KeyVersion: *kv,
		AAD:        aad,
		KeyKind:    key.Kind,
	})
	if err != nil {
		return OrbitalContinue(err)
	}
	return nil
}

func (p *Processor) UpsertRemote(ctx context.Context) *OrbitalResponseError {
	if p.Key == nil {
		return OrbitalFail(fmt.Errorf("%w: key is nil", ErrInternalError))
	}
	if p.KeyVersion == nil {
		return p.MarkKeyFailed(ctx, fmt.Errorf("%w: key version is nil", ErrInternalError))
	}
	if p.registry == nil {
		return p.MarkKeyFailed(ctx, fmt.Errorf("%w: registry is nil, cannot upsert key version", ErrInternalError))
	}
	if p.rootName == "" {
		return p.MarkKeyFailed(ctx, fmt.Errorf("%w: root name is empty", ErrInternalError))
	}

	managedBy := p.Key.ManagedBy
	isManagedByRoot := managedBy == p.rootName

	if isManagedByRoot {
		return nil
	}

	conn, ok := p.registry.Get(managedBy)
	if !ok {
		return p.MarkKeyFailed(ctx, fmt.Errorf("%w: no connection found for agent %s", ErrInternalError, managedBy))
	}

	or := p.upsertRemoteKey(ctx, conn)
	if or != nil {
		return or
	}

	return p.upsertRemoteKeyVersion(ctx, conn)
}

func (p *Processor) MarkKeyComplete(ctx context.Context) *OrbitalResponseError {
	if p.Key == nil {
		return OrbitalFail(fmt.Errorf("%w: key is nil", ErrInternalError))
	}
	key := p.Key

	err := p.stores.Keys.UpdateKeyStates(ctx, store.UpdateKeyStatesQuery{
		ID:         key.ID,
		TenantID:   key.TenantID,
		FromState:  []model.KeyLifeCycleState{key.LifeCycleState},
		ToState:    key.LifeCycleState,
		FromStatus: []model.KeyProcessingStatus{model.KeyProcessingPending},
		ToStatus:   model.KeyProcessingCompleted,
	})
	if err != nil {
		return OrbitalContinue(err)
	}
	return nil
}

func (p *Processor) upsertRemoteKey(ctx context.Context, conn *grpc.ClientConn) *OrbitalResponseError {
	k := p.Key
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
	return p.MarkKeyFailed(ctx, fmt.Errorf("failed to upsert key to remote agent %s: %w", k.ManagedBy, err))
}

func (p *Processor) upsertRemoteKeyVersion(ctx context.Context, conn *grpc.ClientConn) *OrbitalResponseError {
	kv := p.KeyVersion
	k := p.Key

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

	return p.MarkKeyFailed(ctx, fmt.Errorf("failed to upsert key version to remote agent %s: %w", k.ManagedBy, err))
}

func (p *Processor) isRootKey(ctx context.Context) (bool, *OrbitalResponseError) {
	key := p.Key
	kspec, ok := p.config.Hierarchy.FindKeySpec(key.Kind)
	if !ok {
		return false, p.MarkKeyFailed(ctx, fmt.Errorf("%w: key kind %s not found in hierarchy", ErrInternalError, key.Kind))
	}
	return kspec.Role == spec.KeyRoleRoot, nil
}

func (p *Processor) loadKey(ctx context.Context, kid handler.KeyIdentifier) *OrbitalResponseError {
	key, err := p.stores.Keys.GetKeyByID(ctx, kid.ID, kid.TenantID)
	if err == nil {
		p.Key = key
		return nil
	}

	if errors.Is(err, store.ErrKeyNotFound) {
		return OrbitalFail(fmt.Errorf("key not found: %w", err))
	}

	return OrbitalContinue(err)
}

func (p *Processor) resolveKeyVersions(ctx context.Context) *OrbitalResponseError {
	kv, err := p.fetchAndUpdateExistingKeyVersion(ctx)
	if err == nil {
		p.KeyVersion = kv
		return nil
	}

	if !errors.Is(err, ErrKeyVersionNotFound) {
		return OrbitalContinue(err)
	}

	kv, err = p.deriveKeyVersionFromParent(ctx)
	if err == nil {
		p.KeyVersion = kv
		p.IsNewKV = true
		return nil
	}

	if errors.Is(err, ErrNoParentKeyVersionFound) {
		return p.MarkKeyFailed(ctx, err)
	}

	return OrbitalContinue(err)
}

func (p *Processor) fetchAndUpdateExistingKeyVersion(ctx context.Context) (*model.KeyVersion, error) {
	kvStore := p.stores.KeyVersions
	key := p.Key
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
		ToLifeCycleState:    key.LifeCycleState,
	})
	if err != nil {
		return nil, err
	}
	kv.LifeCycleState = key.LifeCycleState
	kv.ProcessingState = model.KeyVersionUsable
	return &kv, nil
}

func (p *Processor) deriveKeyVersionFromParent(ctx context.Context) (*model.KeyVersion, error) {
	kvStore := p.stores.KeyVersions
	key := p.Key

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
