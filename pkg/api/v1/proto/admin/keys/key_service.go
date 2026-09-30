package keys

import (
	"cmp"
	"context"
	"encoding/json/v2"
	"errors"

	"github.com/openkcm/orbital"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/handler/announcekeyv2"
	"github.com/openkcm/krypton/internal/keyoperator"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	"github.com/openkcm/krypton/pkg/validator"
)

type JobGroupPreparer interface {
	PrepareJobGroup(ctx context.Context, group orbital.JobGroup) (orbital.JobGroup, error)
}

type KeyService struct {
	UnimplementedKeyServiceServer

	transactor      store.Transactor
	keyStore        store.Key
	keyVersionStore store.KeyVersion
	preparer        JobGroupPreparer
	manager         *keyprocessor.Manager

	config config.RootConfig
}

func NewKeyService(cfg config.RootConfig, transactor store.Transactor, keyStore store.Key, keyVersionStore store.KeyVersion, preparer JobGroupPreparer, manager *keyprocessor.Manager) *KeyService {
	return &KeyService{
		transactor:      transactor,
		keyStore:        keyStore,
		keyVersionStore: keyVersionStore,
		preparer:        preparer,
		manager:         manager,
		config:          cfg,
	}
}

func (s *KeyService) AnnounceKey(ctx context.Context, req *AnnounceKeyRequest) (*AnnounceKeyResponse, error) {
	err := validator.ValidateKeyAnnounceRequest(validator.AnnounceInput{
		TenantID:   req.GetTenantId(),
		KeyKind:    req.GetKind(),
		Name:       req.GetName(),
		ParentID:   req.GetParentId(),
		TargetName: req.GetTargetName(),
	}, s.config)
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.InvalidArgument, err.Error()),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	newKey := s.newKey(req)
	err = store.ChainTransaction(ctx, s.transactor,
		validator.ValidateTenant(newKey.TenantID),
		validator.ValidateKeyHierarchy(newKey.TenantID, newKey.ParentID, newKey.Kind, s.config.Hierarchy),
		keyoperator.UpsertKey(&newKey),
		s.prepareAnnounceJobGroup(&newKey),
	)
	if err != nil {
		return nil, mappedOrInternal(err)
	}

	return &AnnounceKeyResponse{Key: KeyToProto(newKey)}, nil
}

func (s *KeyService) ActivateKey(ctx context.Context, req *ActivateKeyRequest) (*ActivateKeyResponse, error) {
	tenantID := req.GetTenantId()
	keyID := req.GetId()

	if err := validator.ValidateActivateRequest(validator.ActivateInput{
		TenantID: tenantID, KeyID: keyID,
	}); err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.InvalidArgument, err.Error()),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	resolve := keyoperator.InitKeyVersion(tenantID, keyID)

	err := store.ChainTransaction(ctx, s.transactor,
		validator.ValidateTenant(tenantID),
		validator.ValidateTransition(tenantID, keyID, model.KeyLifeCycleActive),
		validator.ValidateKeyParents(tenantID, keyID),

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
		return nil, mappedOrInternal(err)
	}

	return &ActivateKeyResponse{}, nil
}

func (s *KeyService) GetKey(ctx context.Context, req *GetKeyRequest) (*GetKeyResponse, error) {
	key, err := s.keyStore.GetKeyByID(ctx, req.GetId(), req.GetTenantId())
	if err != nil {
		if errors.Is(err, store.ErrKeyNotFound) {
			return nil, proto.ErrDetailsWithCode(
				status.New(codes.NotFound, "key not found"),
				proto.Code_ERROR_CODE_ABORT,
			)
		}
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to get key"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	return &GetKeyResponse{Key: KeyToProto(*key)}, nil
}

func (s *KeyService) GetParentKeys(ctx context.Context, req *GetParentKeysRequest) (*GetParentKeysResponse, error) {
	res, err := s.keyStore.GetParentKeys(ctx, store.GetParentKeysQuery{
		KeyID:    req.GetId(),
		TenantID: req.GetTenantId(),
	})
	if err != nil {
		if errors.Is(err, store.ErrKeyNotFound) {
			return nil, proto.ErrDetailsWithCode(
				status.New(codes.NotFound, "key not found"),
				proto.Code_ERROR_CODE_ABORT,
			)
		}
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to get parent keys"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	return &GetParentKeysResponse{
		Keys: KeysToProto(res.Keys),
	}, nil
}

func (s *KeyService) GetDescendantKeys(ctx context.Context, req *GetDescendantKeysRequest) (*GetDescendantKeysResponse, error) {
	res, err := s.keyStore.GetDescendantKeys(ctx, store.GetDescendantKeysQuery{
		KeyID:    req.GetId(),
		TenantID: req.GetTenantId(),
	})
	if err != nil {
		if errors.Is(err, store.ErrKeyNotFound) {
			return nil, proto.ErrDetailsWithCode(
				status.New(codes.NotFound, "key not found"),
				proto.Code_ERROR_CODE_ABORT,
			)
		}
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to get descendant keys"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	return &GetDescendantKeysResponse{
		KeyTree: KeyTreeTraverserToProto(res.KeyTree),
	}, nil
}

func (s *KeyService) ListKeys(ctx context.Context, req *ListKeysRequest) (*ListKeysResponse, error) {
	res, err := s.keyStore.ListKeys(ctx, store.ListKeysQuery{
		TenantID:              req.GetTenantId(),
		Name:                  req.GetName(),
		Kind:                  model.KeyKind(req.GetKind()),
		LifeCycleState:        model.KeyLifeCycleState(req.GetLifeCycleState()),
		ManagedBy:             req.GetManagedBy(),
		Labels:                req.GetLabels(),
		IsOrderByCreatedAtAsc: req.GetIsOrderByCreatedAtAsc(),
		Cursor:                req.GetCursor(),
		Limit:                 int(req.GetLimit()),
	})

	if err != nil {
		if errors.Is(err, store.ErrKeyNotFound) {
			return nil, proto.ErrDetailsWithCode(
				status.New(codes.NotFound, "keys not found"),
				proto.Code_ERROR_CODE_ABORT,
			)
		}
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to list keys"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	return &ListKeysResponse{
		Keys:   KeysToProto(res.Keys),
		Cursor: res.Cursor,
	}, nil
}

func (s *KeyService) newKey(req *AnnounceKeyRequest) model.Key {
	var parentID *string
	if req.GetParentId() != "" {
		parentID = new(req.GetParentId())
	}

	target := cmp.Or(req.GetTargetName(), s.config.Name)

	return model.NewKey(
		req.GetTenantId(),
		req.GetName(),
		req.GetKind(),
		parentID,
		target,
		req.GetLabels(),
	)
}

func (s *KeyService) prepareAnnounceJobGroup(newKey *model.Key) func(ctx context.Context, _ store.Stores) error {
	return func(ctx context.Context, _ store.Stores) error {
		data, err := json.Marshal(newKey)
		if err != nil {
			return err
		}

		job := orbital.NewJob(announcekeyv2.JobType, data).WithExternalID(newKey.Name)
		jobGroup := orbital.NewJobGroup(announcekeyv2.JobGroupType, job)

		_, err = s.preparer.PrepareJobGroup(ctx, jobGroup)
		return err
	}
}

func mappedOrInternal(err error) error {
	if mapped := mapToProtoErr(err); mapped != nil {
		return mapped
	}
	return proto.ErrDetailsWithCode(
		status.New(codes.Internal, "transaction failed"),
		proto.Code_ERROR_CODE_RETRY,
	)
}
