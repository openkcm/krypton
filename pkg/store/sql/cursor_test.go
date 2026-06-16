package sql_test

import (
	"encoding/base64"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/clock"
	"github.com/openkcm/krypton/pkg/store/sql"
)

func TestCursorEncodeDecode(t *testing.T) {
	// Matches base64url characters only (no padding)
	var b64urlRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

	tests := []struct {
		name      string
		id        string
		createdAt clock.UnixNano
	}{
		{
			name:      "valid cursor with special characters",
			id:        "123e4567-e89b-12d3-a456-426614174000.+/~!@#$%^&*(){}[]|:;'<>,.?",
			createdAt: 1620000000000000000,
		},
		{
			name:      "for zero createdAt",
			id:        "123e4567-e89b-12d3-a456-426614174001",
			createdAt: 0,
		},
		{
			name:      "for empty id",
			id:        "",
			createdAt: 426614174000,
		},
		{
			name:      "for empty id and zero createdAt",
			id:        "",
			createdAt: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			subj := sql.NewCursor(tt.id, tt.createdAt)

			// when
			encoded, err := subj.Encode()

			// then
			require.NoError(t, err)
			assert.True(t, b64urlRe.MatchString(encoded))

			// when
			decoded, err := sql.DecodeCursor(encoded)

			// then
			require.NoError(t, err)
			assert.Equal(t, tt.id, decoded.ID)
			assert.Equal(t, tt.createdAt, decoded.CreatedAt)
		})
	}
}

func TestDecodeCursor_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "invalid base64",
			input: "not-valid-base64!!!",
		},
		{
			name:  "valid base64 but invalid JSON",
			input: base64.RawURLEncoding.EncodeToString([]byte("{not json")),
		},
		{
			name:  "empty string",
			input: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sql.DecodeCursor(tt.input)
			require.Error(t, err)
		})
	}
}
