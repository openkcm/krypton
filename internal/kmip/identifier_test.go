package kmip

import (
	"errors"
	"testing"
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
		{"invalid-no-colon", "", "", ErrInvalidKeyIdentifier},
		{":missing-tenant", "", "", ErrInvalidKeyIdentifier},
		{"missing-key:", "", "", ErrInvalidKeyIdentifier},
		{"", "", "", ErrInvalidKeyIdentifier},
		{":", "", "", ErrInvalidKeyIdentifier},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			gotTenant, gotKey, err := parseKeyIdentifier(tt.in)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if gotTenant != tt.wantTenant || gotKey != tt.wantKey {
				t.Fatalf("got (%q, %q), want (%q, %q)", gotTenant, gotKey, tt.wantTenant, tt.wantKey)
			}
		})
	}
}
