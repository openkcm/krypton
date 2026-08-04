package keys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openkcm/orbital"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/handler/announcekey"
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
	keyStore        store.Key
	keyVersionStore store.KeyVersion
	jobPreparer     JobPreparer
	validator       validator.KeyValidator
	manager         *keyprocessor.Manager
}

func NewKeyService(rootName string, keyStore store.Key, keyVersionStore store.KeyVersion, validator validator.KeyValidator, jobPreparer JobPreparer, manager *keyprocessor.Manager) *KeyService {
	return &KeyService{
		rootName:        rootName,
		keyStore:        keyStore,
		keyVersionStore: keyVersionStore,
		validator:       validator,
		jobPreparer:     jobPreparer,
		manager:         manager,
	}
}

func (s *KeyService) ActivateKey(ctx context.Context, req *ActivateKeyRequest) (*ActivateKeyResponse, error) {
	vErr := s.validator.ValidateKeyActivate(ctx, validator.ActivateInput{
		TenantID: req.GetTenantId(),
		KeyID:    req.GetId(),
	})
	if vErr != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(vErr.ToProtoErrCode(), vErr.Error()),
			vErr.ToProtoDetailCode(),
		)
	}

	// transaction starts here
	// if an error happens inside this needs to be reverted
	key, err := s.keyStore.GetKeyByID(ctx, req.GetId(), req.GetTenantId())
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to get key"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}
	isRoot := key.ParentID == nil

	// make the keys ls=active ks=processing
	err = s.keyStore.UpdateKeyStates(ctx, store.UpdateKeyStatesQuery{
		ID:       key.ID,
		TenantID: key.TenantID,
		FromState: []model.KeyLifeCycleState{
			model.KeyLifeCyclePreActivation,
		},
		ToState: model.KeyLifeCycleActive,
		FromStatus: []model.KeyProcessingStatus{
			model.KeyProcessingCompleted,
		},
		ToStatus: model.KeyProcessingInProgress,
	})
	if err != nil {
		if errors.Is(err, store.ErrKeyNotFound) {
			return nil, proto.ErrDetailsWithCode(
				status.New(codes.NotFound, "key is in wrong processing state or life cycle state"),
				proto.Code_ERROR_CODE_ABORT,
			)
		}
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to update key life cycle and processing state"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	var parentKeyVersion *int
	if !isRoot {
		pkv, err := s.keyVersionStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
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
			return nil, proto.ErrDetailsWithCode(
				status.New(codes.Internal, "failed to get parent key version"),
				proto.Code_ERROR_CODE_RETRY,
			)
		}
		if len(pkv.KeyVersions) == 0 {
			return nil, proto.ErrDetailsWithCode(
				status.New(codes.FailedPrecondition, "parent key has no usable version"),
				proto.Code_ERROR_CODE_ABORT,
			)
		}
		parentKeyVersion = new(pkv.KeyVersions[0].Version)
	}

	kv := model.NewKeyVersion(key.TenantID, key.ID, 1, key.ParentID, parentKeyVersion)
	kv.LifeCycleState = model.KeyLifeCyclePreActivation
	kv.ProcessingState = model.KeyVersionActivating

	// create a kv version with ls=nonactivate ks=processing
	_, err = s.keyVersionStore.CreateKeyVersion(ctx, store.CreateKeyVersionQuery{
		KeyVersion: kv,
	})
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to create key version"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	if !isRoot {
		aad := fmt.Appendf(nil, "%s:%s:%d:%d:%d", key.TenantID, key.ID, kv.Version, kv.Revision, kv.CreatedAt)
		_, err = s.manager.GenerateAndSealSecret(ctx, keyprocessor.GenerateAndSealSecretRequest{
			KeyVersion: kv,
			AAD:        aad,
			KeyKind:    key.Kind,
		})
		if err != nil {
			return nil, proto.ErrDetailsWithCode(
				status.New(codes.Internal, "failed to generate and seal secret"),
				proto.Code_ERROR_CODE_ABORT,
			)
		}
	}

	err = s.keyStore.UpdateKeyStates(ctx, store.UpdateKeyStatesQuery{
		ID:       key.ID,
		TenantID: key.TenantID,
		FromState: []model.KeyLifeCycleState{
			model.KeyLifeCycleActive,
		},
		ToState: model.KeyLifeCycleActive,
		FromStatus: []model.KeyProcessingStatus{
			model.KeyProcessingInProgress,
		},
		ToStatus: model.KeyProcessingCompleted,
	})
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to update key processing state"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	err = s.keyVersionStore.UpdateKeyVersionStates(ctx, store.UpdateKeyVersionStatesQuery{
		TenantID:            kv.TenantID,
		KeyID:               kv.KeyID,
		Version:             kv.Version,
		Revision:            kv.Revision,
		FromProcessingState: []model.KeyVersionProcessingState{model.KeyVersionActivating},
		ToProcessingState:   model.KeyVersionUsable,
		FromLifeCycleState:  []model.KeyLifeCycleState{model.KeyLifeCyclePreActivation},
		ToLifeCycleState:    model.KeyLifeCycleActive,
	})
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to update key version life cycle and processing state"),
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
