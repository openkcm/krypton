package keys

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"

	"github.com/openkcm/orbital"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/handler/announcekey"
	"github.com/openkcm/krypton/internal/keyoperator"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	"github.com/openkcm/krypton/pkg/validator"
)

const (
	conflictingKeyErrMsg = "a similar key already exists with conflicting values"
)

type JobPreparer interface {
	PrepareJob(ctx context.Context, job orbital.Job) (orbital.Job, error)
}

type KeyService struct {
	UnimplementedKeyServiceServer

	rootName        string
	transactor      store.Transactor
	keyStore        store.Key
	keyVersionStore store.KeyVersion
	jobPreparer     JobPreparer
	validator       validator.KeyValidator
	manager         *keyprocessor.Manager
}

func NewKeyService(rootName string, transactor store.Transactor, keyStore store.Key, keyVersionStore store.KeyVersion, validator validator.KeyValidator, jobPreparer JobPreparer, manager *keyprocessor.Manager) *KeyService {
	return &KeyService{
		rootName:        rootName,
		transactor:      transactor,
		keyStore:        keyStore,
		keyVersionStore: keyVersionStore,
		validator:       validator,
		jobPreparer:     jobPreparer,
		manager:         manager,
	}
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
		if mapped := mapToProtoErr(err); mapped != nil {
			return nil, mapped
		}
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "transaction failed"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	return &ActivateKeyResponse{}, nil
}

// AnnounceKey validates the request and checks for an already esisting key with the same name.
// If the announce operation is for the root we just create it and return it otherwise it creates a job and a new key.
// If there's a key with the same name we return that key or if the key is in a failed or pending state we retry the job.
func (s *KeyService) AnnounceKey(ctx context.Context, req *AnnounceKeyRequest) (*AnnounceKeyResponse, error) {
	vErr := s.validator.ValidateKeyAnnounce(ctx, validator.AnnounceInput{
		TenantID:   req.GetTenantId(),
		KeyKind:    req.GetKind(),
		Name:       req.GetName(),
		ParentID:   req.GetParentId(),
		TargetName: req.GetTargetName(),
	})
	if vErr != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(vErr.ToProtoErrCode(), vErr.Error()),
			vErr.ToProtoDetailCode(),
		)
	}

	// @TODO: Do all this in a database transaction
	existing, err := s.keyStore.GetKeyByName(ctx, store.GetKeyByNameQuery{
		TenantID: req.GetTenantId(),
		Name:     req.GetName(),
	})
	if err != nil && !errors.Is(err, store.ErrKeyNotFound) {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, fmt.Sprintf("failed to look up key: %v", err)),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	var parentID *string
	if req.GetParentId() != "" {
		p := req.GetParentId()
		parentID = &p
	}

	target := s.rootName
	if req.GetTargetName() != "" {
		target = req.GetTargetName()
	}

	newKey := model.NewKey(
		req.GetTenantId(),
		req.GetName(),
		req.GetKind(),
		parentID,
		target,
		req.GetLabels(),
	)
	newKey.KeyProcessingState = model.KeyProcessingState{
		Status: model.KeyProcessingCompleted,
	}

	// case we are announcing a new key
	if errors.Is(err, store.ErrKeyNotFound) {
		// non root case
		if target != s.rootName {
			job, err := s.prepareJob(ctx, &newKey)
			if err != nil {
				return nil, proto.ErrDetailsWithCode(
					status.New(codes.Internal, fmt.Sprintf("failed to create job, err: %v", err)),
					proto.Code_ERROR_CODE_RETRY,
				)
			}

			newKey.KeyProcessingState = model.KeyProcessingState{
				JobID:  job.ID.String(),
				Status: model.KeyProcessingPending,
			}
		}

		// root key or we are announcing a root managed key
		if err := s.keyStore.CreateKey(ctx, newKey); err != nil {
			return nil, proto.ErrDetailsWithCode(
				status.New(codes.Internal, fmt.Sprintf("failed to create key, err : %v", err)),
				proto.Code_ERROR_CODE_RETRY,
			)
		}

		return &AnnounceKeyResponse{Key: KeyToProto(newKey)}, nil
	}

	// key already exists so we retry
	if err := s.retryAnnounce(ctx, existing, &newKey); err != nil {
		return nil, err
	}

	return &AnnounceKeyResponse{Key: KeyToProto(*existing)}, nil
}

func (s *KeyService) retryAnnounce(ctx context.Context, existing, newKey *model.Key) error {
	if !existing.IsSame(newKey) {
		return proto.ErrDetailsWithCode(
			status.New(codes.FailedPrecondition, conflictingKeyErrMsg),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	// idempotent if key is was already announced successfully or still being processed
	if existing.KeyProcessingState.Status.IsOneOf(model.KeyProcessingInProgress, model.KeyProcessingCompleted) {
		return nil
	}

	// we are only here when we had a non root managed key whose job is still pending/failed
	job, err := s.prepareJob(ctx, existing)
	if err != nil {
		// Concurrent retry: another caller already created a job with the same
		// ExternalID (= existing.ID). Return the current key state so the caller
		// can poll; the in-flight retry will update processing state on completion.
		// @TODO: drop this branch once transactions land and Pending is moved
		// into the idempotent short-circuit above.
		if errors.Is(err, orbital.ErrJobAlreadyExists) {
			return nil
		}

		return proto.ErrDetailsWithCode(
			status.New(codes.Internal, fmt.Sprintf("failed to create job, err: %v", err)),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	if err := s.keyStore.UpdateKeyProcessingState(ctx, store.UpdateKeyProcessingStateQuery{
		ID:        existing.ID,
		TenantID:  existing.TenantID,
		NewStatus: model.KeyProcessingPending,
		NewJobID:  job.ID.String(),
	}); err != nil {
		return proto.ErrDetailsWithCode(
			status.New(codes.Internal, fmt.Sprintf("failed to update key with job id, err: %v", err)),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	existing.KeyProcessingState = model.KeyProcessingState{
		Status: model.KeyProcessingPending,
		JobID:  job.ID.String(),
	}

	return nil
}

func (s *KeyService) prepareJob(ctx context.Context, key *model.Key) (orbital.Job, error) {
	taskData := announcekey.TaskData{
		KeyID:    key.ID,
		TenantID: key.TenantID,
		Kind:     string(key.Kind),
		Name:     key.Name,
		Target:   key.ManagedBy,
		Labels:   map[string]string(key.Labels),
	}
	if key.ParentID != nil {
		taskData.ParentID = *key.ParentID
	}

	data, err := json.Marshal(taskData)
	if err != nil {
		return orbital.Job{}, err
	}

	job := orbital.NewJob(announcekey.JobType, data).WithExternalID(key.ID)

	return s.jobPreparer.PrepareJob(ctx, job)
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
