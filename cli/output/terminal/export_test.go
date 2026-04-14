package terminal

import "io"

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

var (
	ReadKey    = readKey
	RenderRows = renderRows
)

type Selection = selection

// NewSelection creates a selection for testing.
func NewSelection(items []string, cursor, scrollOffset, viewHeight int) *Selection {
	return &Selection{
		items:        items,
		cursor:       cursor,
		scrollOffset: scrollOffset,
		viewHeight:   viewHeight,
	}
}

func (s *Selection) Render(out io.Writer) {
	s.render(out)
}

func (s *Selection) Run(out io.Writer, in io.Reader) (int, error) {
	return s.run(out, in)
}
