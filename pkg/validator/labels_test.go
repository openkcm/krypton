package validator_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/validator"
)

func TestValidateUserLabels(t *testing.T) {
	tests := []struct {
		name   string
		labels model.Labels
		expErr error
	}{
		{
			name:   "nil labels",
			labels: nil,
			expErr: nil,
		},
		{
			name: "user labels",
			labels: model.Labels{
				"env": "prod",
			},
			expErr: nil,
		},
		{
			name: "different namespace",
			labels: model.Labels{
				"krypton/action": "value",
			},
			expErr: nil,
		},
		{
			name: "reserved label",
			labels: model.Labels{
				"krypton:origin": "root",
			},
			expErr: validator.ErrReservedLabel,
		},
		{
			name: "reserved prefix",
			labels: model.Labels{
				"krypton:": "value",
			},
			expErr: validator.ErrReservedLabel,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateUserLabels(tt.labels)

			assert.ErrorIs(t, err, tt.expErr)
		})
	}
}
