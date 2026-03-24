package output

import (
	"io"
	"strings"
	"text/tabwriter"

	"github.com/openkcm/krypton/pkg/api/admin"
)

// Table represents a type that can be displayed in table format.
type Table interface {
	// Header returns the column headers for the table.
	Header() []string
	// Rows returns the rows of data for the table.
	Rows() [][]string
}

// PrintTable writes the given value to the writer in table format.
func PrintTable(w io.Writer, v any) error {
	var table Table

	switch val := v.(type) {
	case admin.CreateTenantResponse:
		table = TenantTable{
			Tenants: []Tenant{fromCreateTenantResponse(val)},
		}
	case admin.GetTenantResponse:
		table = TenantTable{
			Tenants: []Tenant{fromGetTenantResponse(val)},
		}
	case admin.ListTenantsResponse:
		table = TenantTable{
			Tenants: fromListTenantsResponse(val),
		}
	default:
		return ErrUnsupportedResponse
	}

	return printTable(w, table)
}

func printTable(w io.Writer, t Table) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	rows := append([][]string{t.Header()}, t.Rows()...)
	for _, row := range rows {
		for i, cell := range row {
			if i > 0 {
				err := write(tw, "\t")
				if err != nil {
					return err
				}
			}
			err := write(tw, cell)
			if err != nil {
				return err
			}
		}
		err := write(tw, "\n")
		if err != nil {
			return err
		}
	}

	return tw.Flush()
}

func write(w io.Writer, s string) error {
	_, err := w.Write([]byte(s))
	return err
}

// Row represents a parsed table row with column values accessible by header name.
type Row map[string]string

// ParsedTable holds parsed table output with header-keyed row access.
type ParsedTable struct {
	Header []string
	Rows   []Row
}

// ParseTable parses table output bytes into a ParsedTable structure.
// This function is primarily intended for testing purposes,
// allowing tests to verify table output structure and column ordering.
// It assumes column headers do not contain spaces.
func ParseTable(output []byte) ParsedTable {
	lines := strings.Split(string(output), "\n")
	if len(lines) == 0 {
		return ParsedTable{}
	}

	headerLine := lines[0]
	headers := strings.Fields(headerLine)

	if len(lines) == 1 {
		return ParsedTable{
			Header: headers,
		}
	}

	pos := make([]int, len(headers))
	for i, h := range headers {
		pos[i] = strings.Index(headerLine, h)
	}

	rows := make([]Row, 0, len(lines)-1)
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		rows = append(rows, parseRow(line, headers, pos))
	}

	return ParsedTable{
		Header: headers,
		Rows:   rows,
	}
}

// parseRow extracts column values based on header positions and returns a Row keyed by header name.
func parseRow(line string, headers []string, pos []int) Row {
	row := make(Row, len(pos))
	for i, start := range pos {
		end := len(line)
		if i+1 < len(pos) {
			end = pos[i+1]
		}
		value := ""
		if start < len(line) {
			value = strings.TrimSpace(line[start:end])
		}
		row[headers[i]] = value
	}
	return row
}
