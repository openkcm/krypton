package terminal_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/cli/output"
	"github.com/openkcm/krypton/cli/output/terminal"
)

func TestReadKey_SingleByteKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    byte
		expected terminal.Key
	}{
		{name: "enter CR", input: 13, expected: terminal.KeyEnter},
		{name: "enter LF", input: 10, expected: terminal.KeyEnter},
		{name: "ctrl+c", input: 3, expected: terminal.KeyCtrlC},
		{name: "escape", input: 27, expected: terminal.KeyEsc},
		{name: "vim up k", input: 'k', expected: terminal.KeyUp},
		{name: "vim down j", input: 'j', expected: terminal.KeyDown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			reader := bytes.NewReader([]byte{tt.input})

			// when
			key := terminal.ReadKey(reader)

			// then
			assert.Equal(t, tt.expected, key)
		})
	}
}

func TestReadKey_UnknownSingleByte(t *testing.T) {
	tests := []struct {
		name  string
		input byte
	}{
		{name: "letter a", input: 'a'},
		{name: "letter x", input: 'x'},
		{name: "number 1", input: '1'},
		{name: "space", input: ' '},
		{name: "tab", input: '\t'},
		{name: "null", input: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			reader := bytes.NewReader([]byte{tt.input})

			// when
			key := terminal.ReadKey(reader)

			// then
			assert.Equal(t, terminal.KeyUnknown, key)
		})
	}
}

func TestReadKey_ArrowKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected terminal.Key
	}{
		{name: "arrow up", input: []byte{27, '[', 'A'}, expected: terminal.KeyUp},
		{name: "arrow down", input: []byte{27, '[', 'B'}, expected: terminal.KeyDown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			reader := bytes.NewReader(tt.input)

			// when
			key := terminal.ReadKey(reader)

			// then
			assert.Equal(t, tt.expected, key)
		})
	}
}

func TestReadKey_UnknownEscapeSequences(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{name: "arrow left", input: []byte{27, '[', 'D'}},
		{name: "arrow right", input: []byte{27, '[', 'C'}},
		{name: "malformed escape", input: []byte{27, 'O', 'A'}},
		{name: "two bytes only", input: []byte{27, '['}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			reader := bytes.NewReader(tt.input)

			// when
			key := terminal.ReadKey(reader)

			// then
			assert.Equal(t, terminal.KeyUnknown, key)
		})
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxWidth int
		expected string
	}{
		{
			name:     "no truncation needed",
			input:    "hello",
			maxWidth: 10,
			expected: "hello",
		},
		{
			name:     "exact fit",
			input:    "hello",
			maxWidth: 5,
			expected: "hello",
		},
		{
			name:     "truncates with ellipsis",
			input:    "hello world",
			maxWidth: 8,
			expected: "hello...",
		},
		{
			name:     "very short max width",
			input:    "hello",
			maxWidth: 3,
			expected: "...",
		},
		{
			name:     "handles unicode",
			input:    "café ☃ test",
			maxWidth: 8,
			expected: "café ...",
		},
		{
			name:     "empty string",
			input:    "",
			maxWidth: 10,
			expected: "",
		},
		{
			name:     "zero max width",
			input:    "hello",
			maxWidth: 0,
			expected: "",
		},
		{
			name:     "negative max width",
			input:    "hello",
			maxWidth: -5,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			result := terminal.Truncate(tt.input, tt.maxWidth)

			// then
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSelection_Render(t *testing.T) {
	tests := []struct {
		name         string
		items        []string
		cursor       int
		scrollOffset int
		viewHeight   int
		wantContains []string
	}{
		{
			name:         "single item selected",
			items:        []string{"alice"},
			cursor:       0,
			scrollOffset: 0,
			viewHeight:   5,
			wantContains: []string{"> alice", "[use arrows"},
		},
		{
			name:         "second item selected",
			items:        []string{"alice", "bob", "charlie"},
			cursor:       1,
			scrollOffset: 0,
			viewHeight:   5,
			wantContains: []string{"alice", "> bob", "charlie"},
		},
		{
			name:         "scrolled view",
			items:        []string{"a", "b", "c", "d", "e", "f"},
			cursor:       3,
			scrollOffset: 2,
			viewHeight:   3,
			wantContains: []string{"c", "> d", "e"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			var buf bytes.Buffer
			s := terminal.NewSelection(tt.items, tt.cursor, tt.scrollOffset, tt.viewHeight)

			// when
			s.Render(&buf)

			// then
			output := buf.String()
			for _, want := range tt.wantContains {
				assert.Contains(t, output, want)
			}
		})
	}
}

func TestSelection_Render_HidesCursor(t *testing.T) {
	// given
	var buf bytes.Buffer
	s := terminal.NewSelection([]string{"test"}, 0, 0, 1)

	// when
	s.Render(&buf)

	// then
	output := buf.String()
	assert.True(t, strings.HasPrefix(output, "\033[?25l"),
		"expected output to start with hide cursor sequence")
}

func TestSelection_Render_ShowsPreTruncatedItems(t *testing.T) {
	// given
	var buf bytes.Buffer
	// Items are pre-truncated by renderRows before being passed to selection
	truncatedItem := "this is a very long..."
	s := terminal.NewSelection([]string{truncatedItem}, 0, 0, 1)

	// when
	s.Render(&buf)

	// then
	output := buf.String()
	assert.Contains(t, output, truncatedItem)
}

func TestRenderRows(t *testing.T) {
	tests := []struct {
		name     string
		rows     output.Rows
		maxWidth int
		expected []string
	}{
		{
			name:     "empty rows",
			rows:     output.Rows{},
			maxWidth: 80,
			expected: []string{},
		},
		{
			name: "single row single column",
			rows: output.Rows{
				{{Name: "Name", Value: "alice"}},
			},
			maxWidth: 80,
			expected: []string{"alice"},
		},
		{
			name: "single row multiple columns",
			rows: output.Rows{
				{{Name: "ID", Value: "123"}, {Name: "Name", Value: "alice"}},
			},
			maxWidth: 80,
			expected: []string{"123  alice"},
		},
		{
			name: "multiple rows aligned",
			rows: output.Rows{
				{{Name: "ID", Value: "1"}, {Name: "Name", Value: "alice"}},
				{{Name: "ID", Value: "100"}, {Name: "Name", Value: "bob"}},
			},
			maxWidth: 80,
			expected: []string{"1    alice", "100  bob"},
		},
		{
			name: "truncates long content",
			rows: output.Rows{
				{{Name: "Name", Value: "this is a very long name that exceeds width"}},
			},
			maxWidth: 20,
			expected: []string{"this is a very lo..."},
		},
		{
			name: "handles various types",
			rows: output.Rows{
				{{Name: "String", Value: "hello"}, {Name: "Int", Value: 42}, {Name: "Bool", Value: true}},
			},
			maxWidth: 80,
			expected: []string{"hello  42  true"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			result := terminal.RenderRows(tt.rows, tt.maxWidth)

			// then
			assert.Equal(t, tt.expected, result)
		})
	}
}
