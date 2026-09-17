package validator_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/pkg/validator"
)

func TestValidateUpsertTenant(t *testing.T) {
	tests := []struct {
		name   string // description of this test case
		req    validator.UpsertTenantInput
		expErr error
	}{
		{
			name:   "valid input",
			req:    validator.UpsertTenantInput{ID: "123e4567-e89b-12d3-a456-426614174000", Name: "Tenant A"},
			expErr: nil,
		},
		{
			name:   "invalid UUID",
			req:    validator.UpsertTenantInput{ID: "invalid-uuid", Name: "Tenant B"},
			expErr: validator.ErrInvalidTenantID,
		},
		{
			name:   "empty name",
			req:    validator.UpsertTenantInput{ID: "123e4567-e89b-12d3-a456-426614174000", Name: ""},
			expErr: validator.ErrEmptyTenantName,
		},
		{
			name:   "empty spaces name",
			req:    validator.UpsertTenantInput{ID: "123e4567-e89b-12d3-a456-426614174000", Name: "   "},
			expErr: validator.ErrEmptyTenantName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actErr := validator.ValidateUpsertTenant(tt.req)

			assert.ErrorIs(t, actErr, tt.expErr)
		})
	}
}
