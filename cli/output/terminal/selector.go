// Package terminal provides interactive terminal-based selection.
package terminal

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/openkcm/krypton/cli/output"
)

var (
	// ErrInterrupt is returned when the user cancels the selection.
	ErrInterrupt = errors.New("selection interrupted")
	// ErrNoItems is returned when there are no items to select from.
	ErrNoItems = errors.New("no items to select from")
	// ErrNotFile is returned when the input reader is not a file descriptor.
	ErrNotFile = errors.New("input is not a file")
	// ErrNotTerminal is returned when the input is not an interactive terminal.
	ErrNotTerminal = errors.New("input is not a terminal")
)

// ANSI escape sequences for terminal control.
const (
	clearLine  = "\033[2K"
	hideCursor = "\033[?25l"
	showCursor = "\033[?25h"
	invert     = "\033[7m"
	dim        = "\033[2m"
	resetStyle = "\033[0m"
)

// Selection UI layout.
const (
	// itemPrefixLen is the visual width of the prefix before each item.
	// Selected:   "  > " (2 spaces + > + space = 4)
	// Unselected: "    " (4 spaces)
	itemPrefixLen   = 4
	maxVisibleItems = 5
)

// Selector returns a terminal-based selector function for interactive selection.
// Uses arrow keys (or j/k) to navigate and Enter to confirm.
func Selector(out io.Writer, in io.Reader) output.Selector {
	return func(rows output.Rows) (int, error) {
		if len(rows) == 0 {
			return -1, ErrNoItems
		}

		fd, ok := getFd(in)
		if !ok {
			return -1, ErrNotFile
		}

		viewWidth := 80 // fallback
		if w, _, err := term.GetSize(fd); err == nil {
			viewWidth = w
		}

		restore, err := setupRawMode(fd, out)
		if err != nil {
			return -1, err
		}
		defer restore()

		maxItemWidth := viewWidth - itemPrefixLen - 1 // -1 to avoid edge wrapping

		s := &selection{
			items:      renderRows(rows, maxItemWidth),
			viewHeight: min(maxVisibleItems, len(rows)),
		}
		return s.run(out, in)
	}
}

// selection holds the state for interactive selection.
type selection struct {
	items        []string
	cursor       int
	scrollOffset int
	viewHeight   int
}

func (s *selection) run(out io.Writer, in io.Reader) (int, error) {
	for {
		s.render(out)

		switch readKey(in) {
		case keyUp:
			s.moveUp()
		case keyDown:
			s.moveDown()
		case keyEnter:
			s.clear(out)
			return s.cursor, nil
		case keyCtrlC, keyEsc:
			s.clear(out)
			return -1, ErrInterrupt
		}
	}
}

func (s *selection) render(out io.Writer) {
	fmt.Fprint(out, hideCursor)

	end := min(s.scrollOffset+s.viewHeight, len(s.items))
	for i := s.scrollOffset; i < end; i++ {
		fmt.Fprint(out, clearLine)
		if i == s.cursor {
			fmt.Fprintf(out, "  %s> %s%s\r\n", invert, s.items[i], resetStyle)
		} else {
			fmt.Fprintf(out, "    %s\r\n", s.items[i])
		}
	}

	fmt.Fprintf(out, "%s%s[use arrows or j/k to move, enter to select, ctrl+c or esc to cancel]%s",
		clearLine, dim, resetStyle)

	fmt.Fprintf(out, "\r\033[%dA", end-s.scrollOffset)
}

func (s *selection) clear(out io.Writer) {
	for i := 0; i <= s.viewHeight; i++ {
		fmt.Fprintf(out, "%s\r\n", clearLine)
	}
	fmt.Fprintf(out, "\033[%dA", s.viewHeight+1)
}

func (s *selection) moveUp() {
	if s.cursor > 0 {
		s.cursor--
		if s.cursor < s.scrollOffset {
			s.scrollOffset = s.cursor
		}
	}
}

func (s *selection) moveDown() {
	if s.cursor < len(s.items)-1 {
		s.cursor++
		if s.cursor >= s.scrollOffset+s.viewHeight {
			s.scrollOffset = s.cursor - s.viewHeight + 1
		}
	}
}

// renderRows formats rows as aligned, truncated strings for display.
func renderRows(rows output.Rows, maxWidth int) []string {
	if len(rows) == 0 {
		return []string{}
	}

	// Format with tabwriter for alignment
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)

	for _, row := range rows {
		values := make([]string, len(row))
		for j, c := range row {
			values[j] = fmt.Sprintf("%v", c.Value)
		}
		fmt.Fprintln(tw, strings.Join(values, "\t"))
	}
	tw.Flush()

	// Split into lines and truncate each
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	for i, line := range lines {
		lines[i] = truncate(line, maxWidth)
	}

	return lines
}

func truncate(s string, maxWidth int) string {
	if maxWidth < 1 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= maxWidth {
		return s
	}
	if maxWidth <= 3 {
		return "..."
	}
	return string(runes[:maxWidth-3]) + "..."
}

// setupRawMode enables raw terminal mode and returns a restore function.
// It flushes pending input and hides the cursor.
// The restore function re-enables the cursor and restores the original terminal state.
func setupRawMode(fd int, out io.Writer) (restore func(), err error) {
	if !term.IsTerminal(fd) {
		return nil, ErrNotTerminal
	}

	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return nil, err
	}

	flushInput(fd)

	return func() {
		fmt.Fprint(out, showCursor)
		_ = term.Restore(fd, oldState)
	}, nil
}

func getFd(r io.Reader) (int, bool) {
	if f, ok := r.(*os.File); ok {
		return int(f.Fd()), true
	}
	return 0, false
}

// Key handling.
type key int

const (
	keyUnknown key = iota
	keyUp
	keyDown
	keyEnter
	keyCtrlC
	keyEsc
)

func readKey(in io.Reader) key {
	buf := make([]byte, 3)
	n, _ := in.Read(buf)

	if n == 1 {
		switch buf[0] {
		case 13, 10: // Enter (CR or LF)
			return keyEnter
		case 3: // Ctrl+C
			return keyCtrlC
		case 27: // Escape
			return keyEsc
		case 'k': // Vim up
			return keyUp
		case 'j': // Vim down
			return keyDown
		}
		return keyUnknown
	}

	if n == 3 && buf[0] == 27 && buf[1] == '[' { // ESC [ ...
		switch buf[2] {
		case 'A': // Arrow up
			return keyUp
		case 'B': // Arrow down
			return keyDown
		}
	}

	return keyUnknown
}

// flushInput discards pending input from the terminal buffer to prevent
// stale keystrokes from being processed as selection commands.
func flushInput(fd int) {
	buf := make([]byte, 256)
	for {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, 10)
		if err != nil || n == 0 {
			break
		}
		if _, err = unix.Read(fd, buf); err != nil {
			break
		}
	}
}
