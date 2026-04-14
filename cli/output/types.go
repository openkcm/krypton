package output

// Cell represents a single field in a row.
type Cell struct {
	Name  string
	Value any
}

// Row is a slice of cells representing a single record.
type Row []Cell

// Rows is a slice of rows.
type Rows []Row
