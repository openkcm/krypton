package output

import (
	"fmt"
	"strings"
)

// Cell represents a single field in a row.
type Cell struct {
	Name  string
	Value any
}

// Row is a slice of cells representing a single record.
type Row []Cell

// Rows is a slice of rows.
type Rows []Row

// Tabular returns each row as a tab-separated string.
func (r Rows) Tabular() []string {
	result := make([]string, len(r))
	for i, row := range r {
		values := make([]string, len(row))
		for j, c := range row {
			values[j] = fmt.Sprintf("%v", c.Value)
		}
		result[i] = strings.Join(values, "\t")
	}
	return result
}
