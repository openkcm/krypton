package terminal

import (
	"io"

	"github.com/openkcm/krypton/cli/output"
)

// Export key type and constants for testing.
type Key = key

const (
	KeyUnknown = keyUnknown
	KeyUp      = keyUp
	KeyDown    = keyDown
	KeyEnter   = keyEnter
	KeyCtrlC   = keyCtrlC
	KeyEsc     = keyEsc
)

// ReadKey exports readKey for testing.
func ReadKey(in io.Reader) Key {
	return readKey(in)
}

// Truncate exports truncate for testing.
func Truncate(s string, maxWidth int) string {
	return truncate(s, maxWidth)
}

// RenderRows exports renderRows for testing.
func RenderRows(rows output.Rows, maxWidth int) []string {
	return renderRows(rows, maxWidth)
}

// NewSelection creates a selection for testing.
func NewSelection(items []string, cursor, scrollOffset, viewHeight int) *selection {
	return &selection{
		items:        items,
		cursor:       cursor,
		scrollOffset: scrollOffset,
		viewHeight:   viewHeight,
	}
}

// Render exports render for testing.
func (s *selection) Render(out io.Writer) {
	s.render(out)
}
