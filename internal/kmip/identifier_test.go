package kmip_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/kmip"
)

func TestParseKeyIdentifier(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in         string
		wantTenant string
		wantKey    string
		wantErr    error
	}{
		{"tenant-a:dek-1", "tenant-a", "dek-1", nil},
		{"acme-corp:dek-mongodb-001", "acme-corp", "dek-mongodb-001", nil},
		{"tenant:key:with:colons", "tenant", "key:with:colons", nil},
		{"invalid-no-colon", "", "", kmip.ErrInvalidKeyIdentifier},
		{":missing-tenant", "", "", kmip.ErrInvalidKeyIdentifier},
		{"missing-key:", "", "", kmip.ErrInvalidKeyIdentifier},
		{"", "", "", kmip.ErrInvalidKeyIdentifier},
		{":", "", "", kmip.ErrInvalidKeyIdentifier},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			gotTenant, gotKey, err := kmip.ParseKeyIdentifier(tt.in)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantTenant, gotTenant)
			assert.Equal(t, tt.wantKey, gotKey)
		})
	}
}
