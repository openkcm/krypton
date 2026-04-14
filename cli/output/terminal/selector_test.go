package terminal_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/cli/output"
	"github.com/openkcm/krypton/cli/output/terminal"
)

// keySequenceReader delivers key sequences one at a time.
// Each []byte in the sequence is delivered as a separate read.
type keySequenceReader struct {
	keys [][]byte
	idx  int
}

func newKeySequenceReader(keys ...[]byte) *keySequenceReader {
	return &keySequenceReader{keys: keys}
}

func (r *keySequenceReader) Read(p []byte) (int, error) {
	if r.idx >= len(r.keys) {
		return 0, io.EOF
	}
	n := copy(p, r.keys[r.idx])
	r.idx++
	return n, nil
}

func TestSelector(t *testing.T) {
	// given
	notTerminal, err := os.Create(filepath.Join(t.TempDir(), "not-a-terminal"))
	assert.NoError(t, err)
	t.Cleanup(func() { notTerminal.Close() })

	rows := output.Rows{{{Name: "Name", Value: "alice"}}}

	tests := []struct {
		name   string
		rows   output.Rows
		in     io.Reader
		expIdx int
		expErr error
	}{
		{
			name:   "empty rows returns ErrNoItems",
			rows:   output.Rows{},
			in:     os.Stdin,
			expIdx: -1,
			expErr: terminal.ErrNoItems,
		},
		{
			name:   "non-file reader returns ErrNotFile",
			rows:   rows,
			in:     bytes.NewReader(nil),
			expIdx: -1,
			expErr: terminal.ErrNotFile,
		},
		{
			name:   "non-terminal file returns ErrNotTerminal",
			rows:   rows,
			in:     notTerminal,
			expIdx: -1,
			expErr: terminal.ErrNotTerminal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			var buf bytes.Buffer
			selector := terminal.Selector(&buf, tt.in)

			// when
			idx, err := selector(tt.rows)

			// then
			assert.Equal(t, tt.expIdx, idx)
			assert.Equal(t, tt.expErr, err)
		})
	}
}

func TestReadKey(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expKey terminal.Key
	}{
		{
			name:   "enter CR",
			input:  []byte{13},
			expKey: terminal.KeyEnter,
		},
		{
			name:   "enter LF",
			input:  []byte{10},
			expKey: terminal.KeyEnter,
		},
		{
			name:   "ctrl+c",
			input:  []byte{3},
			expKey: terminal.KeyCtrlC,
		},
		{
			name:   "escape",
			input:  []byte{27},
			expKey: terminal.KeyEsc,
		},
		{
			name:   "vim up k",
			input:  []byte{'k'},
			expKey: terminal.KeyUp,
		},
		{
			name:   "vim down j",
			input:  []byte{'j'},
			expKey: terminal.KeyDown,
		},
		{
			name:   "arrow up",
			input:  []byte{27, '[', 'A'},
			expKey: terminal.KeyUp,
		},
		{
			name:   "arrow down",
			input:  []byte{27, '[', 'B'},
			expKey: terminal.KeyDown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			reader := bytes.NewReader(tt.input)

			// when
			key := terminal.ReadKey(reader)

			// then
			assert.Equal(t, tt.expKey, key)
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

func TestSelection_Render(t *testing.T) {
	tests := []struct {
		name        string
		selection   *terminal.Selection
		expContains []string
	}{
		{
			name:        "single item selected",
			selection:   terminal.NewSelection([]string{"alice"}, 0, 0, 5),
			expContains: []string{"> alice", "[use arrows"},
		},
		{
			name:        "second item selected",
			selection:   terminal.NewSelection([]string{"alice", "bob", "charlie"}, 1, 0, 5),
			expContains: []string{"alice", "> bob", "charlie"},
		},
		{
			name:        "scrolled view",
			selection:   terminal.NewSelection([]string{"a", "b", "c", "d", "e", "f"}, 3, 2, 3),
			expContains: []string{"c", "> d", "e"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			var buf bytes.Buffer

			// when
			tt.selection.Render(&buf)

			// then
			output := buf.String()
			for _, exp := range tt.expContains {
				assert.Contains(t, output, exp)
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
	assert.True(t, strings.HasPrefix(output, "\033[?25l"), "expected output to start with hide cursor sequence")
}

func TestRenderRows(t *testing.T) {
	tests := []struct {
		name     string
		rows     output.Rows
		maxWidth int
		exp      []string
	}{
		{
			name:     "empty rows",
			rows:     output.Rows{},
			maxWidth: 80,
			exp:      []string{},
		},
		{
			name: "single row single column",
			rows: output.Rows{
				{{Name: "Name", Value: "alice"}},
			},
			maxWidth: 80,
			exp:      []string{"alice"},
		},
		{
			name: "single row multiple columns",
			rows: output.Rows{
				{{Name: "ID", Value: "123"}, {Name: "Name", Value: "alice"}},
			},
			maxWidth: 80,
			exp:      []string{"123  alice"},
		},
		{
			name: "multiple rows aligned",
			rows: output.Rows{
				{{Name: "ID", Value: "1"}, {Name: "Name", Value: "alice"}},
				{{Name: "ID", Value: "100"}, {Name: "Name", Value: "bob"}},
			},
			maxWidth: 80,
			exp:      []string{"1    alice", "100  bob"},
		},
		{
			name: "handles various types",
			rows: output.Rows{
				{{Name: "String", Value: "hello"}, {Name: "Int", Value: 42}, {Name: "Bool", Value: true}},
			},
			maxWidth: 80,
			exp:      []string{"hello  42  true"},
		},
		{
			name: "truncates with ellipsis",
			rows: output.Rows{
				{{Name: "Name", Value: "hello world"}},
			},
			maxWidth: 8,
			exp:      []string{"hello..."},
		},
		{
			name: "truncates long content",
			rows: output.Rows{
				{{Name: "Name", Value: "this is a very long name that exceeds width"}},
			},
			maxWidth: 20,
			exp:      []string{"this is a very lo..."},
		},
		{
			name: "very short max width",
			rows: output.Rows{
				{{Name: "Name", Value: "hello"}},
			},
			maxWidth: 3,
			exp:      []string{"..."},
		},
		{
			name: "handles unicode truncation",
			rows: output.Rows{
				{{Name: "Name", Value: "café ☃ test"}},
			},
			maxWidth: 8,
			exp:      []string{"café ..."},
		},
		{
			name: "exact fit no truncation",
			rows: output.Rows{
				{{Name: "Name", Value: "hello"}},
			},
			maxWidth: 5,
			exp:      []string{"hello"},
		},
		{
			name: "zero max width",
			rows: output.Rows{
				{{Name: "Name", Value: "hello"}},
			},
			maxWidth: 0,
			exp:      []string{""},
		},
		{
			name: "negative max width",
			rows: output.Rows{
				{{Name: "Name", Value: "hello"}},
			},
			maxWidth: -5,
			exp:      []string{""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			result := terminal.RenderRows(tt.rows, tt.maxWidth)

			// then
			assert.Equal(t, tt.exp, result)
		})
	}
}

func TestSelection_Run(t *testing.T) {
	items := []string{"alice", "bob", "charlie"}
	enter := []byte{13}
	down := []byte{'j'}
	up := []byte{'k'}
	arrowDown := []byte{27, '[', 'B'}
	ctrlC := []byte{3}
	esc := []byte{27}

	tests := []struct {
		name      string
		keys      [][]byte
		expCursor int
		expErr    error
	}{
		{
			name:      "select first item immediately",
			keys:      [][]byte{enter},
			expCursor: 0,
			expErr:    nil,
		},
		{
			name:      "navigate down and select",
			keys:      [][]byte{down, enter},
			expCursor: 1,
			expErr:    nil,
		},
		{
			name:      "navigate down twice and select",
			keys:      [][]byte{down, down, enter},
			expCursor: 2,
			expErr:    nil,
		},
		{
			name:      "navigate down with arrow and select",
			keys:      [][]byte{arrowDown, enter},
			expCursor: 1,
			expErr:    nil,
		},
		{
			name:      "navigate down and up and select",
			keys:      [][]byte{down, down, up, enter},
			expCursor: 1,
			expErr:    nil,
		},
		{
			name:      "navigate up at top stays at top",
			keys:      [][]byte{up, up, enter},
			expCursor: 0,
			expErr:    nil,
		},
		{
			name:      "navigate down past end stays at end",
			keys:      [][]byte{down, down, down, down, enter},
			expCursor: 2,
			expErr:    nil,
		},
		{
			name:      "ctrl+c interrupts",
			keys:      [][]byte{ctrlC},
			expCursor: -1,
			expErr:    terminal.ErrInterrupt,
		},
		{
			name:      "escape interrupts",
			keys:      [][]byte{esc},
			expCursor: -1,
			expErr:    terminal.ErrInterrupt,
		},
		{
			name:      "navigate then ctrl+c",
			keys:      [][]byte{down, down, ctrlC},
			expCursor: -1,
			expErr:    terminal.ErrInterrupt,
		},
		{
			name:      "unknown keys are ignored",
			keys:      [][]byte{{'x'}, {'a'}, {'1'}, down, enter},
			expCursor: 1,
			expErr:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			var buf bytes.Buffer
			s := terminal.NewSelection(items, 0, 0, 5)

			// when
			cursor, err := s.Run(&buf, newKeySequenceReader(tt.keys...))

			// then
			assert.Equal(t, tt.expCursor, cursor)
			assert.Equal(t, tt.expErr, err)
		})
	}
}

func TestSelection_Run_Scrolling(t *testing.T) {
	// given
	items := []string{"a", "b", "c", "d", "e", "f", "g"}
	var buf bytes.Buffer
	s := terminal.NewSelection(items, 0, 0, 3) // viewHeight=3, so scrolling needed
	down := []byte{'j'}
	enter := []byte{13}

	// when: navigate down to item 4 (index 3), then select
	cursor, err := s.Run(&buf, newKeySequenceReader(down, down, down, enter))

	// then
	assert.NoError(t, err)
	assert.Equal(t, 3, cursor)
}
