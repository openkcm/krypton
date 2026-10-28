package validator_test

import (
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/validator"
)

func TestValidateUpsertKeyVersionRequest(t *testing.T) {
	baseValid := validator.UpsertKeyVersionInput{
		TenantID:         uuid.New().String(),
		KeyID:            uuid.New().String(),
		Version:          1,
		Revision:         1,
		ParentKeyID:      uuid.New().String(),
		ParentKeyVersion: 1,
		LifeCycleState:   string(model.KeyLifeCycleActive),
		ProcessingState:  string(model.KeyVersionUsable),
	}

	withField := func(mut func(*validator.UpsertKeyVersionInput)) validator.UpsertKeyVersionInput {
		in := baseValid
		mut(&in)
		return in
	}

	tts := []struct {
		name   string
		input  validator.UpsertKeyVersionInput
		expErr error
	}{
		{
			name:   "valid input",
			input:  baseValid,
			expErr: nil,
		},
		{
			name:   "valid input without parent",
			input:  withField(func(in *validator.UpsertKeyVersionInput) { in.ParentKeyID = ""; in.ParentKeyVersion = 0 }),
			expErr: nil,
		},
		{
			name:   "invalid tenantID",
			input:  withField(func(in *validator.UpsertKeyVersionInput) { in.TenantID = "not-a-uuid" }),
			expErr: validator.ErrInvalidTenantID,
		},
		{
			name:   "empty tenantID",
			input:  withField(func(in *validator.UpsertKeyVersionInput) { in.TenantID = "" }),
			expErr: validator.ErrInvalidTenantID,
		},
		{
			name:   "invalid keyID",
			input:  withField(func(in *validator.UpsertKeyVersionInput) { in.KeyID = "not-a-uuid" }),
			expErr: validator.ErrInvalidKeyID,
		},
		{
			name:   "empty keyID",
			input:  withField(func(in *validator.UpsertKeyVersionInput) { in.KeyID = "" }),
			expErr: validator.ErrInvalidKeyID,
		},
		{
			name:   "zero version",
			input:  withField(func(in *validator.UpsertKeyVersionInput) { in.Version = 0 }),
			expErr: validator.ErrInvalidVersion,
		},
		{
			name:   "negative version",
			input:  withField(func(in *validator.UpsertKeyVersionInput) { in.Version = -1 }),
			expErr: validator.ErrInvalidVersion,
		},
		{
			name:   "zero revision",
			input:  withField(func(in *validator.UpsertKeyVersionInput) { in.Revision = 0 }),
			expErr: validator.ErrInvalidRevision,
		},
		{
			name:   "negative revision",
			input:  withField(func(in *validator.UpsertKeyVersionInput) { in.Revision = -1 }),
			expErr: validator.ErrInvalidRevision,
		},
		{
			name:   "invalid parentKeyID format",
			input:  withField(func(in *validator.UpsertKeyVersionInput) { in.ParentKeyID = "not-a-uuid" }),
			expErr: validator.ErrInvalidParentKeyID,
		},
		{
			name:   "negative parentKeyVersion",
			input:  withField(func(in *validator.UpsertKeyVersionInput) { in.ParentKeyVersion = -1 }),
			expErr: validator.ErrInvalidParentKeyVersion,
		},
		{
			name:   "zero parentKeyVersion is valid",
			input:  withField(func(in *validator.UpsertKeyVersionInput) { in.ParentKeyVersion = 0 }),
			expErr: nil,
		},
		{
			name:   "unknown lifecycle state",
			input:  withField(func(in *validator.UpsertKeyVersionInput) { in.LifeCycleState = "bogus" }),
			expErr: validator.ErrUnknownLifecycleState,
		},
		{
			name:   "empty lifecycle state",
			input:  withField(func(in *validator.UpsertKeyVersionInput) { in.LifeCycleState = "" }),
			expErr: validator.ErrUnknownLifecycleState,
		},
		{
			name:   "unknown processing state",
			input:  withField(func(in *validator.UpsertKeyVersionInput) { in.ProcessingState = "bogus" }),
			expErr: validator.ErrUnknownProcessingState,
		},
		{
			name:   "empty processing state",
			input:  withField(func(in *validator.UpsertKeyVersionInput) { in.ProcessingState = "" }),
			expErr: validator.ErrUnknownProcessingState,
		},
		{
			name:   "valid with pre-activation lifecycle",
			input:  withField(func(in *validator.UpsertKeyVersionInput) { in.LifeCycleState = string(model.KeyLifeCyclePreActivation) }),
			expErr: nil,
		},
		{
			name:   "valid with re-wrapping processing state",
			input:  withField(func(in *validator.UpsertKeyVersionInput) { in.ProcessingState = string(model.KeyVersionReWrapping) }),
			expErr: nil,
		},
		{
			name:   "valid with activating processing state",
			input:  withField(func(in *validator.UpsertKeyVersionInput) { in.ProcessingState = string(model.KeyVersionActivating) }),
			expErr: nil,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			err := validator.ValidateUpsertKeyVersionRequest(tt.input)

			// then
			if tt.expErr == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tt.expErr)
		})
	}
}
