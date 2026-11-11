package orchestrator

import (
	"context"
	"errors"
	"fmt"

	"github.com/openkcm/orbital"
	"google.golang.org/grpc"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/grpcconn"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents/keys"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents/keyversions"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

// KeyOperator orchestrates key processing steps within a transaction.
// It is not safe for concurrent use.
//
// Call [LoadKey] then [ResolveKeyVersions] first to populate Key, KeyVersion,
// and IsNewKV before calling subsequent steps.
type KeyOperator struct {
	Key        *model.Key
	KeyVersion *model.KeyVersion
	IsNewKV    bool
	cfg        KeyOperatorConfig
}

// KeyOperatorConfig holds the dependencies for a [KeyOperator].
type KeyOperatorConfig struct {
	Manager    *keyprocessor.Manager
	RootConfig *config.RootConfig
	Registry   *grpcconn.Registry
	Stores     store.Stores
	KID        *KeyIdentifier
}

type (
	operatorStepFunc     func(context.Context) *OrbitalOperatorError
	operatorPipelineFunc func(op *KeyOperator) []operatorStepFunc
)

var (
	ErrNoKeyVersionYet         = errors.New("key version not yet created")
	ErrNoParentKeyVersionFound = errors.New("no parent key version found")
	ErrInternal                = errors.New("internal error")
)

// NewKeyOperator creates an operator with the given config.
func NewKeyOperator(
	cfg KeyOperatorConfig,
) *KeyOperator {
	return &KeyOperator{
		cfg: cfg,
	}
}

// Execute runs the configured steps in order, completing the response on success.
func (m *KeyOperator) Execute(ctx context.Context, pipelineFunc operatorPipelineFunc, resp *orbital.HandlerResponse) error {
	if pipelineFunc == nil {
		return OrbitalFail(fmt.Errorf("%w: pipeline function is nil", ErrInternal)).
			Apply(resp)
	}
	steps := pipelineFunc(m)
	for _, step := range steps {
		oe := step(ctx)
		if oe != nil {
			return oe.Apply(resp)
		}
	}
	resp.Complete()
	return nil
}

// MarkKeyFailed sets the key's processing state to failed and returns the original error.
func (m *KeyOperator) MarkKeyFailed(ctx context.Context, failedErr error) *OrbitalOperatorError {
	if m.Key == nil {
		return OrbitalFail(fmt.Errorf("%w: key is nil", ErrInternal))
	}

	ks := m.cfg.Stores.Keys
	key := m.Key

	err := ks.UpdateKeyStates(ctx, store.UpdateKeyStatesQuery{
		ID:         key.ID,
		TenantID:   key.TenantID,
		FromState:  []model.KeyLifeCycleState{key.LifeCycleState},
		ToState:    key.LifeCycleState,
		FromStatus: []model.KeyProcessingStatus{key.KeyProcessingState.Status},
		ToStatus:   model.KeyProcessingFailed,
	})
	if err != nil {
		// DB update failed; retry so the caller can attempt the full operation again.
		return OrbitalContinue(err)
	}
	// Key marked as failed in DB; surface the original error as permanent.
	return OrbitalFail(failedErr)
}

// GenerateAndSealLocalSecret generates and seals a secret for new, non-root, locally managed key versions.
func (m *KeyOperator) GenerateAndSealLocalSecret(ctx context.Context) *OrbitalOperatorError {
	if m.Key == nil {
		return OrbitalFail(fmt.Errorf("%w: key is nil", ErrInternal))
	}
	if m.KeyVersion == nil {
		return m.MarkKeyFailed(ctx, fmt.Errorf("%w: key version is nil", ErrInternal))
	}
	if m.cfg.Manager == nil {
		return m.MarkKeyFailed(ctx, fmt.Errorf("%w: key processor manager is nil", ErrInternal))
	}
	if m.cfg.RootConfig == nil {
		return m.MarkKeyFailed(ctx, fmt.Errorf("%w: config is nil", ErrInternal))
	}

	key := m.Key
	isManagedByRoot := key.ManagedBy == m.cfg.RootConfig.Name

	isRootKey, or := m.isRootKey(ctx)
	if or != nil {
		return or
	}

	skipGeneration := !isManagedByRoot || isRootKey || !m.IsNewKV

	if skipGeneration {
		return nil
	}

	kv := m.KeyVersion
	aad := kv.AAD()
	if aad == nil {
		return m.MarkKeyFailed(ctx, fmt.Errorf("%w: failed to generate AAD for key version", ErrInternal))
	}

	_, err := m.cfg.Manager.GenerateAndSealSecret(ctx, keyprocessor.GenerateAndSealSecretRequest{
		KeyVersion: *kv,
		AAD:        aad,
		KeyKind:    key.Kind,
	})
	if err != nil {
		return OrbitalContinue(err)
	}
	return nil
}

// MarkKeyCompleted sets the key's processing state to completed.
func (m *KeyOperator) MarkKeyCompleted(ctx context.Context) *OrbitalOperatorError {
	if m.Key == nil {
		return OrbitalFail(fmt.Errorf("%w: key is nil", ErrInternal))
	}
	key := m.Key

	err := m.cfg.Stores.Keys.UpdateKeyStates(ctx, store.UpdateKeyStatesQuery{
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

// UpsertRemoteKey pushes the key to its managing remote agent via gRPC.
func (m *KeyOperator) UpsertRemoteKey(ctx context.Context) *OrbitalOperatorError {
	if m.Key == nil {
		return OrbitalFail(fmt.Errorf("%w: key is nil", ErrInternal))
	}

	isLocal, or := m.isKeyLocal(ctx)
	if or != nil {
		return or
	}
	if isLocal {
		return nil
	}

	conn, or := m.resolveRemoteConn(ctx)
	if or != nil {
		return or
	}

	k := m.Key
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
	return m.MarkKeyFailed(ctx, fmt.Errorf("failed to upsert key to remote agent %s: %w", k.ManagedBy, err))
}

// UpsertRemoteKeyVersion pushes the key version to its managing remote agent via gRPC.
func (m *KeyOperator) UpsertRemoteKeyVersion(ctx context.Context) *OrbitalOperatorError {
	if m.Key == nil {
		return OrbitalFail(fmt.Errorf("%w: key is nil", ErrInternal))
	}
	if m.KeyVersion == nil {
		return m.MarkKeyFailed(ctx, fmt.Errorf("%w: key version is nil", ErrInternal))
	}

	isLocal, or := m.isKeyLocal(ctx)
	if or != nil {
		return or
	}
	if isLocal {
		return nil
	}

	conn, or := m.resolveRemoteConn(ctx)
	if or != nil {
		return or
	}

	kv := m.KeyVersion
	k := m.Key

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

	return m.MarkKeyFailed(ctx, fmt.Errorf("failed to upsert key version to remote agent %s: %w", k.ManagedBy, err))
}

// LoadKey fetches the key by KID from the store.
func (m *KeyOperator) LoadKey(ctx context.Context) *OrbitalOperatorError {
	kid := m.cfg.KID
	if kid == nil {
		return OrbitalFail(fmt.Errorf("%w: key identifier is nil", ErrInternal))
	}
	key, err := m.cfg.Stores.Keys.GetKeyByID(ctx, kid.ID, kid.TenantID)
	if err == nil {
		m.Key = key
		return nil
	}

	if errors.Is(err, store.ErrKeyNotFound) {
		return OrbitalFail(fmt.Errorf("key not found: %w", err))
	}

	return OrbitalContinue(err)
}

// ResolveKeyVersions resolves or creates the key version for the loaded key.
func (m *KeyOperator) ResolveKeyVersions(ctx context.Context) *OrbitalOperatorError {
	if m.Key == nil {
		return OrbitalFail(fmt.Errorf("%w: key is nil", ErrInternal))
	}
	kv, err := m.fetchAndUpdateExistingKeyVersion(ctx)
	if err == nil {
		m.KeyVersion = kv
		return nil
	}

	if !errors.Is(err, ErrNoKeyVersionYet) {
		return OrbitalContinue(err)
	}

	kv, err = m.deriveKeyVersionFromParent(ctx)
	if err == nil {
		m.KeyVersion = kv
		m.IsNewKV = true
		return nil
	}

	if errors.Is(err, ErrNoParentKeyVersionFound) {
		return m.MarkKeyFailed(ctx, err)
	}

	return OrbitalContinue(err)
}

func (m *KeyOperator) fetchAndUpdateExistingKeyVersion(ctx context.Context) (*model.KeyVersion, error) {
	kvStore := m.cfg.Stores.KeyVersions
	key := m.Key
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
		return nil, ErrNoKeyVersionYet
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

func (m *KeyOperator) deriveKeyVersionFromParent(ctx context.Context) (*model.KeyVersion, error) {
	kvStore := m.cfg.Stores.KeyVersions
	key := m.Key

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
	kv.LifeCycleState = key.LifeCycleState
	kv.ProcessingState = model.KeyVersionUsable

	kvres, err := kvStore.CreateKeyVersion(ctx, store.CreateKeyVersionQuery{
		KeyVersion: kv,
	})
	if err != nil {
		return nil, err
	}

	return &kvres.KeyVersion, nil
}

func (m *KeyOperator) isKeyLocal(ctx context.Context) (bool, *OrbitalOperatorError) {
	if m.Key == nil {
		return false, OrbitalFail(fmt.Errorf("%w: key is nil", ErrInternal))
	}
	if m.cfg.RootConfig == nil {
		return false, m.MarkKeyFailed(ctx, fmt.Errorf("%w: config is nil", ErrInternal))
	}

	managedBy := m.Key.ManagedBy
	if managedBy == m.cfg.RootConfig.Name {
		return true, nil
	}

	return false, nil
}

// resolveRemoteConn returns the gRPC connection for the key's managing agent.
// If the key is locally managed, local is true and conn is nil.
func (m *KeyOperator) resolveRemoteConn(ctx context.Context) (*grpc.ClientConn, *OrbitalOperatorError) {
	if m.Key == nil {
		return nil, OrbitalFail(fmt.Errorf("%w: key is nil", ErrInternal))
	}
	if m.cfg.Registry == nil {
		return nil, m.MarkKeyFailed(ctx, fmt.Errorf("%w: registry is nil", ErrInternal))
	}

	managedBy := m.Key.ManagedBy

	c, ok := m.cfg.Registry.Get(managedBy)
	if !ok {
		return nil, m.MarkKeyFailed(ctx, fmt.Errorf("%w: no connection found for agent %s", ErrInternal, managedBy))
	}
	return c, nil
}

func (m *KeyOperator) isRootKey(ctx context.Context) (bool, *OrbitalOperatorError) {
	if m.Key == nil {
		return false, OrbitalFail(fmt.Errorf("%w: key is nil", ErrInternal))
	}
	if m.cfg.RootConfig == nil {
		return false, m.MarkKeyFailed(ctx, fmt.Errorf("%w: config is nil", ErrInternal))
	}

	key := m.Key
	kspec, ok := m.cfg.RootConfig.Hierarchy.FindKeySpec(key.Kind)
	if !ok {
		return false, m.MarkKeyFailed(ctx, fmt.Errorf("%w: key kind %s not found in hierarchy", ErrInternal, key.Kind))
	}
	return kspec.Role == spec.KeyRoleRoot, nil
}
