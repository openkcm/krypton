package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/config"
)

func TestAddress_Validate(t *testing.T) {
	tests := []struct {
		name    string // description of this test case
		subj    *config.Address
		wantErr error
	}{
		{
			name: "should not return error for valid address",
			subj: &config.Address{
				Type: config.AddressTypeGRPC,
				URL:  "localhost",
			},
			wantErr: nil,
		},
		{
			name: "should return error for empty URL",
			subj: &config.Address{
				Type: config.AddressTypeGRPC,
			},
			wantErr: config.ErrConfigAddressEmpty,
		},
		{
			name: "should return error for empty Type",
			subj: &config.Address{
				Type: "",
				URL:  "localhost",
			},
			wantErr: config.ErrAddressTypeInvalid,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotErr := tt.subj.Validate()

			// then
			assert.ErrorIs(t, gotErr, tt.wantErr)
		})
	}
}
