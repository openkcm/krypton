package keys

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/clock"
	"github.com/openkcm/krypton/internal/keyoperator"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	"github.com/openkcm/krypton/pkg/validator"
)

type Service struct {
	UnimplementedKeyServiceServer

	transactor store.Transactor
}

// NewKeyService constructs the agent-side KeyService.
func NewKeyService(t store.Transactor) *Service {
	return &Service{
		transactor: t,
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
