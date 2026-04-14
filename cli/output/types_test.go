package output_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/cli/output"
)

func TestRows_Tabular(t *testing.T) {
	tests := []struct {
		name     string
		rows     output.Rows
		expected []string
	}{
		{
			name: "single row all fields",
			rows: output.Rows{
				{{Name: "ID", Value: "123"}, {Name: "Name", Value: "alice"}},
			},
			expected: []string{"123\talice"},
		},
		{
			name: "multiple rows all fields",
			rows: output.Rows{
				{{Name: "ID", Value: "1"}, {Name: "Name", Value: "alice"}},
				{{Name: "ID", Value: "2"}, {Name: "Name", Value: "bob"}},
			},
			expected: []string{"1\talice", "2\tbob"},
		},
		{
			name: "single cell",
			rows: output.Rows{
				{{Name: "Name", Value: "alice"}},
			},
			expected: []string{"alice"},
		},
		{
			name: "handles various types",
			rows: output.Rows{
				{{Name: "String", Value: "hello"}, {Name: "Int", Value: 42}, {Name: "Bool", Value: true}},
			},
			expected: []string{"hello\t42\ttrue"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			result := tt.rows.Tabular()

			// then
			assert.Equal(t, tt.expected, result)
		})
	}
}
