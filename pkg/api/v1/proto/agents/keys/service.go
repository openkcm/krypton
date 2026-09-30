package keys

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/clock"
	"github.com/openkcm/krypton/internal/keyoperator"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	"github.com/openkcm/krypton/pkg/validator"
)

type Service struct {
	UnimplementedKeyServiceServer

	transactor store.Transactor
	manager    *keyprocessor.Manager
}

// NewKeyService constructs the agent-side KeyService.
func NewKeyService(t store.Transactor, manager *keyprocessor.Manager) *Service {
	return &Service{
		transactor: t,
		manager:    manager,
	}
}

// UpsertKey creates or reconciles a key on this agent.
// Repeated calls with the same identity are idempotent.
func (s *Service) UpsertKey(ctx context.Context, req *UpsertKeyRequest) (*UpsertKeyResponse, error) {
	err := validator.ValidateKeyUpsert(validator.UpsertKeyInput{
		TenantID:       req.GetTenantId(),
		KeyID:          req.GetKeyId(),
		Kind:           req.GetKind(),
		Name:           req.GetName(),
		ManagedBy:      req.GetManagedBy(),
		ParentID:       req.GetParentId(),
		LifecycleState: req.GetLifecycleState(),
	})
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.InvalidArgument, err.Error()),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	newKey := newKey(req)
	err = store.ChainTransaction(ctx, s.transactor,
		validator.ValidateTenant(newKey.TenantID),
		keyoperator.UpsertKey(newKey),
	)
	if err != nil {
		return nil, mapToProtoErr(err)
	}

	return &UpsertKeyResponse{}, nil
}

// ActivateKey activates a previously mirrored key on this agent: it
// creates the first key version, seals its material, and flips the key
// and version to Active. The key row must already exist (via UpsertKey).
// Unlike the root-side activation it performs no parent business-rule
// validation and takes the parent key version from the request rather
// than resolving it locally. Repeated calls are idempotent via the
// compare-and-set state transitions.
func (s *Service) ActivateKey(ctx context.Context, req *ActivateKeyRequest) (*ActivateKeyResponse, error) {
	tenantID := req.GetTenantId()
	keyID := req.GetKeyId()

	if err := validator.ValidateActivateRequest(validator.ActivateInput{
		TenantID: tenantID, KeyID: keyID,
	}); err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.InvalidArgument, err.Error()),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	var parentKeyVersion *int
	if req.ParentKeyVersion != nil {
		v := int(req.GetParentKeyVersion())
		parentKeyVersion = &v
	}

	resolve := keyoperator.InitAgentKeyVersion(tenantID, keyID, parentKeyVersion)

	err := store.ChainTransaction(ctx, s.transactor,
		keyoperator.UpdateKeyState(tenantID, keyID, keyoperator.Transition{
			FromLifeCycle:  []model.KeyLifeCycleState{model.KeyLifeCyclePreActivation},
			ToLifeCycle:    model.KeyLifeCycleActive,
			FromProcessing: []model.KeyProcessingStatus{model.KeyProcessingCompleted},
			ToProcessing:   model.KeyProcessingInProgress,
		}),

		keyoperator.CreateKeyVersion(tenantID, keyID, resolve),
		keyoperator.GenerateAndSealKeyMaterial(s.manager, tenantID, keyID, resolve),

		keyoperator.UpdateKeyVersionState(tenantID, keyID, resolve, keyoperator.VersionTransition{
			FromProcessing: []model.KeyVersionProcessingState{model.KeyVersionActivating},
			ToProcessing:   model.KeyVersionUsable,
			FromLifeCycle:  []model.KeyLifeCycleState{model.KeyLifeCyclePreActivation},
			ToLifeCycle:    model.KeyLifeCycleActive,
		}),

		keyoperator.UpdateKeyState(tenantID, keyID, keyoperator.Transition{
			FromLifeCycle:  []model.KeyLifeCycleState{model.KeyLifeCycleActive},
			ToLifeCycle:    model.KeyLifeCycleActive,
			FromProcessing: []model.KeyProcessingStatus{model.KeyProcessingInProgress},
			ToProcessing:   model.KeyProcessingCompleted,
		}),
	)
	if err != nil {
		return nil, mapToProtoErr(err)
	}

	return &ActivateKeyResponse{}, nil
}

func newKey(req *UpsertKeyRequest) model.Key {
	parentID := req.GetParentId()
	now := clock.Now()
	return model.Key{
		ID:                 req.GetKeyId(),
		Name:               req.GetName(),
		TenantID:           req.GetTenantId(),
		Kind:               model.KeyKind(req.GetKind()),
		ParentID:           &parentID,
		ManagedBy:          req.GetManagedBy(),
		Labels:             req.GetLabels(),
		LifeCycleState:     model.KeyLifeCycleState(req.GetLifecycleState()),
		KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
		CreatedAt:          now,
		UpdatedAt:          now,
	}
}
