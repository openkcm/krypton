package validator

import (
	"errors"

	"github.com/openkcm/krypton/internal/keylifecycle"
	"github.com/openkcm/krypton/pkg/model"
)

type UpsertKeyVersionInput struct {
	TenantID         string
	KeyID            string
	Version          int
	Revision         int
	ParentKeyID      string
	ParentKeyVersion int
	LifeCycleState   string
	ProcessingState  string
}

var (
	ErrInvalidVersion          = errors.New("version must be greater than 0")
	ErrInvalidRevision         = errors.New("revision must be greater than 0")
	ErrInvalidParentKeyID      = errors.New("parentKeyID is invalid")
	ErrInvalidParentKeyVersion = errors.New("parentKeyVersion must be greater than or equal to 0")
	ErrUnknownProcessingState  = errors.New("processing_state is not a known state")
)

func ValidateUpsertKeyVersionRequest(input UpsertKeyVersionInput) error {
	switch {
	case !isValidUUID(input.TenantID):
		return ErrInvalidTenantID
	case !isValidUUID(input.KeyID):
		return ErrInvalidKeyID
	case input.Version <= 0:
		return ErrInvalidVersion
	case input.Revision <= 0:
		return ErrInvalidRevision
	case input.ParentKeyID != "" && !isValidUUID(input.ParentKeyID):
		return ErrInvalidParentKeyID
	case input.ParentKeyVersion < 0:
		return ErrInvalidParentKeyVersion
	case !keylifecycle.IsKnown(model.KeyLifeCycleState(input.LifeCycleState)):
		return ErrUnknownLifecycleState
	case !model.IsKnownKeyVersionState(input.ProcessingState):
		return ErrUnknownProcessingState
	}
	return nil
}
