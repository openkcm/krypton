package output_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/cli/output"
)

func TestFormatLabels(t *testing.T) {
	tests := []struct {
		name     string
		labels   map[string]string
		maxLen   int
		expected string
	}{
		{
			name:     "nil labels returns <none>",
			labels:   nil,
			maxLen:   25,
			expected: "<none>",
		},
		{
			name:     "empty labels returns <none>",
			labels:   map[string]string{},
			maxLen:   25,
			expected: "<none>",
		},
		{
			name:     "single label",
			labels:   map[string]string{"env": "prod"},
			maxLen:   25,
			expected: "env=prod",
		},
		{
			name:     "multiple labels sorted alphabetically",
			labels:   map[string]string{"env": "prod", "app": "web"},
			maxLen:   25,
			expected: "app=web,env=prod",
		},
		{
			name:     "does not truncate when exactly at maxLen",
			labels:   map[string]string{"a": "12345678901234567890123"},
			maxLen:   25,
			expected: "a=12345678901234567890123", // exactly 25 chars, not truncated
		},
		{
			name:     "truncates when one char over maxLen",
			labels:   map[string]string{"a": "123456789012345678901234"},
			maxLen:   25,
			expected: "a=12345678901234567890...", // 26 chars -> truncated to 22 + "..." = 25
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			result := output.FormatLabels(tt.labels, tt.maxLen)

			// then
			assert.Equal(t, tt.expected, result)
		})
	}
}
