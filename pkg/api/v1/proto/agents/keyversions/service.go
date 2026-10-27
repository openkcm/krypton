package keyversions

import (
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	context "context"

	"github.com/openkcm/krypton/internal/clock"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	"github.com/openkcm/krypton/pkg/validator"
)

type Service struct {
	UnimplementedKeyVersionServiceServer

	transactor store.Transactor
	manager    *keyprocessor.Manager
}

func NewService(t store.Transactor, manager *keyprocessor.Manager) *Service {
	return &Service{
		transactor: t,
		manager:    manager,
	}
}

func (s *Service) UpsertKeyVersion(ctx context.Context, req *UpsertKeyVersionRequest) (*UpsertKeyVersionResponse, error) {
	err := validator.ValidateUpsertKeyVersionRequest(validator.UpsertKeyVersionInput{
		TenantID:         req.GetTenantId(),
		KeyID:            req.GetKeyId(),
		Version:          int(req.GetVersion()),
		Revision:         int(req.GetRevision()),
		ParentKeyID:      req.GetParentId(),
		ParentKeyVersion: int(req.GetParentVersion()),
		LifeCycleState:   req.GetLifecycleState(),
		ProcessingState:  req.GetProcessingState(),
	})
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.InvalidArgument, err.Error()),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	rkv := newKeyVersion(req)
	err = store.ChainTransaction(ctx, s.transactor,
		validateTenant(rkv.TenantID),
		func(ctx context.Context, stores store.Stores) error {
			ks := stores.Keys
			kvs := stores.KeyVersions

			k, err := fetchKey(ctx, ks, rkv.KeyID, rkv.TenantID)
			if err != nil {
				return err
			}

			if err := ensureKeyState(k.LifeCycleState, rkv.LifeCycleState); err != nil {
				return err
			}

			fkv, isExist, err := fetchKeyVersion(ctx, kvs, rkv)
			if err != nil {
				return err
			}

			if isExist {
				return updateKeyVersion(ctx, kvs, fkv, rkv)
			}

			if err := createKeyVersion(ctx, kvs, rkv); err != nil {
				return err
			}

			return generateAndSealSecret(ctx, s.manager, rkv, k.Kind)
		},
	)

	return &UpsertKeyVersionResponse{}, err
}

func generateAndSealSecret(ctx context.Context, mgr *keyprocessor.Manager, kv model.KeyVersion, kind model.KeyKind) error {
	aad := fmt.Appendf(nil, "%s:%s:%d:%d", kv.TenantID, kv.KeyID, kv.Version, kv.Revision)
	_, err := mgr.GenerateAndSealSecret(ctx, keyprocessor.GenerateAndSealSecretRequest{
		KeyVersion: kv,
		AAD:        aad,
		KeyKind:    kind,
	})
	if err != nil {
		return codeInternalWithRetry(fmt.Errorf("failed to generate and seal secret: %w", err))
	}
	return nil
}

func createKeyVersion(ctx context.Context, s store.KeyVersion, rkv model.KeyVersion) error {
	_, err := s.CreateKeyVersion(ctx, store.CreateKeyVersionQuery{
		KeyVersion: rkv,
	})
	if err != nil {
		return codeInternalWithRetry(fmt.Errorf("failed to create key version: %w", err))
	}
	return nil
}

func validateTenant(tenantID string) store.TransactionFunc {
	return func(ctx context.Context, stores store.Stores) error {
		err := validator.ValidateTenant(tenantID)(ctx, stores)
		if err == nil {
			return nil
		}
		if errors.Is(err, store.ErrTenantNotFound) {
			return codeFailedWithAbort(fmt.Errorf("tenant not found: %w", err))
		}
		return codeInternalWithRetry(fmt.Errorf("failed to validate tenant: %w", err))
	}
}

func fetchKey(ctx context.Context, s store.Key, keyID, tenantID string) (*model.Key, error) {
	key, err := s.GetKeyByID(ctx, keyID, tenantID)
	if err == nil {
		return key, nil
	}
	if errors.Is(err, store.ErrKeyNotFound) {
		return key, codeFailedWithAbort(fmt.Errorf("key not found: %w", err))
	}
	return nil, codeInternalWithRetry(fmt.Errorf("failed to fetch key: %w", err))
}

func ensureKeyState(key, req model.KeyLifeCycleState) error {
	if key != req {
		return codeFailedWithAbort(fmt.Errorf("key is in %s state, cannot transition to %s state", key, req))
	}
	return nil
}

func newKeyVersion(req *UpsertKeyVersionRequest) model.KeyVersion {
	pkid := new(req.GetParentId())
	if req.GetParentId() == "" {
		pkid = nil
	}

	pv := new(int(req.GetParentVersion()))
	if req.GetParentVersion() == 0 {
		pv = nil
	}

	now := clock.Now()
	return model.KeyVersion{
		TenantID:         req.GetTenantId(),
		KeyID:            req.GetKeyId(),
		Version:          int(req.GetVersion()),
		Revision:         int(req.GetRevision()),
		ParentKeyID:      pkid,
		ParentKeyVersion: pv,
		LifeCycleState:   model.KeyLifeCycleState(req.GetLifecycleState()),
		ProcessingState:  model.KeyVersionProcessingState(req.GetProcessingState()),
		CreatedAt:        now,
		UpdatedAt:        now,
	}
}

func fetchKeyVersion(ctx context.Context, s store.KeyVersion, kv model.KeyVersion) (model.KeyVersion, bool, error) {
	kvres, err := s.GetKeyVersion(ctx, store.GetKeyVersionQuery{
		TenantID: kv.TenantID,
		KeyID:    kv.KeyID,
		Version:  kv.Version,
		Revision: kv.Revision,
	})
	if err != nil {
		if !errors.Is(err, store.ErrKeyVersionNotFound) {
			return model.KeyVersion{}, false,
				codeInternalWithRetry(fmt.Errorf("failed to fetch key version: %w", err))
		}
		return model.KeyVersion{}, false, nil
	}
	return kvres.KeyVersion, true, nil
}

func updateKeyVersion(ctx context.Context, s store.KeyVersion, oldkv, newkv model.KeyVersion) error {
	err := s.UpdateKeyVersionStates(ctx, store.UpdateKeyVersionStatesQuery{
		TenantID:            newkv.TenantID,
		KeyID:               newkv.KeyID,
		Version:             newkv.Version,
		Revision:            newkv.Revision,
		FromProcessingState: []model.KeyVersionProcessingState{oldkv.ProcessingState},
		ToProcessingState:   newkv.ProcessingState,
		FromLifeCycleState:  []model.KeyLifeCycleState{oldkv.LifeCycleState},
		ToLifeCycleState:    newkv.LifeCycleState,
	})
	if err != nil {
		return codeInternalWithRetry(fmt.Errorf("failed to update key version states: %w", err))
	}
	return nil
}

func codeInternalWithRetry(err error) error {
	return proto.ErrDetailsWithCode(
		status.New(codes.Internal, err.Error()),
		proto.Code_ERROR_CODE_RETRY,
	)
}

func codeFailedWithAbort(err error) error {
	return proto.ErrDetailsWithCode(
		status.New(codes.FailedPrecondition, err.Error()),
		proto.Code_ERROR_CODE_ABORT,
	)
}
