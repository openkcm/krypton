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

var (
	// ErrUnsupportedType is returned when the input is not a struct or slice of structs.
	ErrUnsupportedType = errors.New("unsupported type for parsing")
	// ErrNoRows is returned when there are no rows to select from.
	ErrNoRows = errors.New("no rows to select from")
)

// Format specifies the output format for rendering.
type Format int

const (
	Tabular Format = iota // Tab-aligned columns
	JSON                  // JSON array of objects
)

// Formatter receives a field name and value, and returns a formatted value
// and true if it applied, or nil and false if it doesn't apply.
type Formatter func(name string, value any) (any, bool)

// Selector is a function that handles selection from rows.
// Returns the selected index or -1 and an error if selection is cancelled or fails.
type Selector func(rows Rows) (int, error)

// Builder constructs formatted output from structured data.
type Builder struct {
	rows       Rows
	format     Format
	formatters []Formatter
}

// From parses a struct or slice of structs into a Builder for rendering.
func From(v any) (*Builder, error) {
	rows, err := parse(v)
	if err != nil {
		return nil, err
	}

	return &Builder{
		rows:   rows,
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
		return b.renderJSON(w)
	default:
		return b.renderTabular(w)
	}
}

// Select uses the provided selector to let the user choose a row.
// Returns ErrNoRows if there are no rows.
func (b *Builder) Select(sel Selector) (int, error) {
	if len(b.rows) == 0 {
		return -1, ErrNoRows
	}

	b.applyFormatters()
	return sel(b.rows)
}

func parse(v any) (Rows, error) {
	val := unwrap(reflect.ValueOf(v))

	if !val.IsValid() {
		return Rows{}, nil
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

func parseStruct(val reflect.Value) Rows {
	return Rows{parseRow(val)}
}

func parseSlice(val reflect.Value) (Rows, error) {
	if val.Len() == 0 {
		return Rows{}, nil
	}

	first := unwrap(val.Index(0))
	if first.Kind() != reflect.Struct {
		return nil, ErrUnsupportedType
	}

	rows := make(Rows, val.Len())
	for i := range val.Len() {
		item := unwrap(val.Index(i))
		rows[i] = parseRow(item)
	}

	return rows, nil
}

func parseRow(structVal reflect.Value) Row {
	r := make(Row, structVal.NumField())
	for i := range structVal.NumField() {
		r[i] = Cell{
			Name:  structVal.Type().Field(i).Name,
			Value: structVal.Field(i).Interface(),
		}
	}
	return r
}

func (b *Builder) applyFormatters() {
	for i := range b.rows {
		for j := range b.rows[i] {
			for _, formatter := range b.formatters {
				if value, ok := formatter(b.rows[i][j].Name, b.rows[i][j].Value); ok {
					b.rows[i][j].Value = value
				}
			}
		}
	}
}

func (b *Builder) renderTabular(w io.Writer) error {
	if len(b.rows) == 0 {
		return nil
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	headers := make([]string, len(b.rows[0]))
	for i, c := range b.rows[0] {
		headers[i] = c.Name
	}
	fmt.Fprintln(tw, strings.Join(headers, "\t"))

	for _, row := range b.rows {
		values := make([]string, len(row))
		for j, c := range row {
			values[j] = fmt.Sprintf("%v", c.Value)
		}
		fmt.Fprintln(tw, strings.Join(values, "\t"))
	}

	return tw.Flush()
}

func (b *Builder) renderJSON(w io.Writer) error {
	rows := make([]map[string]any, len(b.rows))

	for i, r := range b.rows {
		obj := make(map[string]any)
		for _, c := range r {
			obj[c.Name] = c.Value
		}
		rows[i] = obj
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rows)
}
