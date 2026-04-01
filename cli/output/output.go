package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"text/tabwriter"
)

// ErrUnsupportedType is returned when the input is not a struct or slice of structs.
var ErrUnsupportedType = errors.New("unsupported type for parsing")

// Format specifies the output format for rendering.
type Format int

const (
	Tabular Format = iota // Tab-aligned columns
	JSON                  // JSON array of objects
)

// Formatter receives a field name and value, and returns a formatted value
// and true if it applied, or nil and false if it doesn't apply.
type Formatter func(name string, value any) (any, bool)

// Builder constructs formatted output from structured data.
type Builder struct {
	grid       *grid
	format     Format
	formatters []Formatter
}

// From parses a struct or slice of structs into a Builder for rendering.
func From(v any) (*Builder, error) {
	g, err := parse(v)
	if err != nil {
		return nil, err
	}

	return &Builder{
		grid:   g,
		format: Tabular,
	}, nil
}

// ForName creates a formatter that applies to fields with the given name.
func ForName(name string, fn func(any) any) Formatter {
	return func(n string, value any) (any, bool) {
		if n == name {
			return fn(value), true
		}
		return nil, false
	}
}

// ForType creates a formatter that applies to values of type T.
func ForType[T any](fn func(T) any) Formatter {
	return func(_ string, value any) (any, bool) {
		if v, ok := value.(T); ok {
			return fn(v), true
		}
		return nil, false
	}
}

// Format applies formatters to transform field values before rendering.
func (b *Builder) Format(formatters ...Formatter) *Builder {
	b.formatters = append(b.formatters, formatters...)
	return b
}

// As sets the output format (Tabular or JSON).
func (b *Builder) As(f Format) *Builder {
	b.format = f
	return b
}

// To renders the output to the given writer.
func (b *Builder) To(w io.Writer) error {
	b.applyFormatters()

	switch b.format {
	case JSON:
		return renderJSON(w, b.grid)
	default:
		return renderTabular(w, b.grid)
	}
}

type cell struct {
	name  string
	value any
}

type row []*cell

// grid represents structured data as rows.
// Each row consists of cells, where each cell represents a field of a struct (name and value).
// A single struct becomes one row; a slice of structs becomes multiple rows.
type grid struct {
	rows []row
}

func parse(v any) (*grid, error) {
	val := unwrap(reflect.ValueOf(v))

	if !val.IsValid() {
		return &grid{}, nil
	}

	switch val.Kind() {
	case reflect.Struct:
		return parseStruct(val), nil
	case reflect.Slice:
		return parseSlice(val)
	default:
		return nil, ErrUnsupportedType
	}
}

func unwrap(val reflect.Value) reflect.Value {
	for val.Kind() == reflect.Pointer && !val.IsNil() {
		val = val.Elem()
	}
	return val
}

func parseStruct(val reflect.Value) *grid {
	return &grid{
		rows: []row{parseRow(val)},
	}
}

func parseSlice(val reflect.Value) (*grid, error) {
	if val.Len() == 0 {
		return &grid{}, nil
	}

	first := unwrap(val.Index(0))
	if first.Kind() != reflect.Struct {
		return nil, ErrUnsupportedType
	}

	rows := make([]row, val.Len())
	for i := range val.Len() {
		item := unwrap(val.Index(i))
		rows[i] = parseRow(item)
	}

	return &grid{rows: rows}, nil
}

func parseRow(structVal reflect.Value) row {
	r := make(row, structVal.NumField())
	for i := range structVal.NumField() {
		r[i] = &cell{
			name:  structVal.Type().Field(i).Name,
			value: structVal.Field(i).Interface(),
		}
	}
	return r
}

func (b *Builder) applyFormatters() {
	for _, r := range b.grid.rows {
		for _, c := range r {
			for _, formatter := range b.formatters {
				if value, ok := formatter(c.name, c.value); ok {
					c.value = value
				}
			}
		}
	}
}

func renderTabular(w io.Writer, g *grid) error {
	if len(g.rows) == 0 {
		return nil
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	headers := make([]string, len(g.rows[0]))
	for i, c := range g.rows[0] {
		headers[i] = c.name
	}
	fmt.Fprintln(tw, strings.Join(headers, "\t"))

	for _, r := range g.rows {
		values := make([]string, len(r))
		for i, c := range r {
			values[i] = fmt.Sprintf("%v", c.value)
		}
		fmt.Fprintln(tw, strings.Join(values, "\t"))
	}

	return tw.Flush()
}

func renderJSON(w io.Writer, g *grid) error {
	rows := make([]map[string]any, len(g.rows))

	for i, r := range g.rows {
		obj := make(map[string]any)
		for _, c := range r {
			obj[c.name] = c.value
		}
		rows[i] = obj
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rows)
}
