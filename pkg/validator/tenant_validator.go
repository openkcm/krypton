package validator

import (
	"errors"
	"strings"
)

// ErrEmptyTenantName is returned when the tenant name is empty.
var ErrEmptyTenantName = errors.New("tenant name cannot be empty")

// UpsertTenantInput represents the input for upserting a tenant.
type UpsertTenantInput struct {
	ID   string
	Name string
}

// ValidateUpsertTenant checks the validity of the UpsertTenantInput.
func ValidateUpsertTenant(req UpsertTenantInput) error {
	switch {
	case !isValidUUID(req.ID):
		return ErrInvalidTenantID
	case strings.TrimSpace(req.Name) == "":
		return ErrEmptyTenantName
	}
	return nil
}
