package output_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/cli/output"
)

type Person struct {
	Name string
	Age  int
}

type MultiType struct {
	String string
	Int    int
	Bool   bool
}

type Nested struct {
	Name  string
	Inner Person
}

func TestFrom_JSON(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected []map[string]any
	}{
		{
			name:  "single struct",
			input: Person{Name: "alice", Age: 30},
			expected: []map[string]any{
				{"Name": "alice", "Age": float64(30)},
			},
		},
		{
			name:  "slice of structs",
			input: []Person{{Name: "alice", Age: 25}, {Name: "bob", Age: 35}},
			expected: []map[string]any{
				{"Name": "alice", "Age": float64(25)},
				{"Name": "bob", "Age": float64(35)},
			},
		},
		{
			name:     "empty slice",
			input:    []Person{},
			expected: []map[string]any{},
		},
		{
			name:  "pointer to struct",
			input: &Person{Name: "ptr", Age: 42},
			expected: []map[string]any{
				{"Name": "ptr", "Age": float64(42)},
			},
		},
		{
			name:  "pointer to slice",
			input: &[]Person{{Name: "a", Age: 1}},
			expected: []map[string]any{
				{"Name": "a", "Age": float64(1)},
			},
		},

		{
			name:  "struct with multiple types",
			input: MultiType{String: "hello", Int: 42, Bool: true},
			expected: []map[string]any{
				{"String": "hello", "Int": float64(42), "Bool": true},
			},
		},
		{
			name:  "zero value struct",
			input: Person{},
			expected: []map[string]any{
				{"Name": "", "Age": float64(0)},
			},
		},
		{
			name:  "nested struct",
			input: Nested{Name: "outer", Inner: Person{Name: "inner", Age: 10}},
			expected: []map[string]any{
				{"Name": "outer", "Inner": map[string]any{"Name": "inner", "Age": float64(10)}},
			},
		},
		{
			name:  "slice with single element",
			input: []Person{{Name: "solo", Age: 99}},
			expected: []map[string]any{
				{"Name": "solo", "Age": float64(99)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			var buf bytes.Buffer

			// when
			builder, err := output.From(tt.input)
			assert.NoError(t, err)

			err = builder.As(output.JSON).To(&buf)

			// then
			assert.NoError(t, err)

			var got []map[string]any
			err = json.Unmarshal(buf.Bytes(), &got)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestFrom_Tabular(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		contains []string
	}{
		{
			name:     "headers present",
			input:    Person{Name: "test", Age: 25},
			contains: []string{"Name", "Age"},
		},
		{
			name:     "values present",
			input:    Person{Name: "alice", Age: 30},
			contains: []string{"alice", "30"},
		},
		{
			name:     "multiple rows",
			input:    []Person{{Name: "first", Age: 1}, {Name: "second", Age: 2}},
			contains: []string{"Name", "Age", "first", "1", "second", "2"},
		},
		{
			name:     "empty slice produces empty output",
			input:    []Person{},
			contains: []string{},
		},
		{
			name:     "struct with multiple types",
			input:    MultiType{String: "text", Int: 123, Bool: true},
			contains: []string{"String", "Int", "Bool", "text", "123", "true"},
		},
		{
			name:     "nested struct shows inner representation",
			input:    Nested{Name: "parent", Inner: Person{Name: "child", Age: 5}},
			contains: []string{"Name", "Inner", "parent", "child"},
		},
		{
			name:     "zero values appear in output",
			input:    Person{Name: "", Age: 0},
			contains: []string{"Name", "Age", "0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			var buf bytes.Buffer

			// when
			builder, err := output.From(tt.input)
			assert.NoError(t, err)

			err = builder.As(output.Tabular).To(&buf)

			// then
			assert.NoError(t, err)
			result := buf.String()
			for _, s := range tt.contains {
				assert.Contains(t, result, s)
			}
		})
	}
}

func TestFrom_Errors(t *testing.T) {
	tests := []struct {
		name  string
		input any
	}{
		{
			name:  "primitive int",
			input: 42,
		},
		{
			name:  "primitive string",
			input: "hello",
		},
		{
			name:  "slice of ints",
			input: []int{1, 2, 3},
		},
		{
			name:  "slice of strings",
			input: []string{"a", "b"},
		},
		{
			name:  "map",
			input: map[string]int{"a": 1},
		},
		{
			name:  "channel",
			input: make(chan int),
		},
		{
			name:  "function",
			input: func() {},
		},
		{
			name:  "nil pointer to struct",
			input: (*Person)(nil),
		},
		{
			name:  "nil pointer to slice",
			input: (*[]Person)(nil),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			_, err := output.From(tt.input)

			// then
			assert.ErrorIs(t, err, output.ErrUnsupportedType)
		})
	}
}

func TestFormat_ForName(t *testing.T) {
	tests := []struct {
		name      string
		input     any
		fieldName string
		formatFn  func(any) any
		expected  []map[string]any
	}{
		{
			name:      "formats matching field",
			input:     Person{Name: "alice", Age: 30},
			fieldName: "Name",
			formatFn: func(v any) any {
				s, _ := v.(string)
				return s + "!"
			},
			expected: []map[string]any{
				{"Name": "alice!", "Age": float64(30)},
			},
		},
		{
			name:      "non-matching field unchanged",
			input:     Person{Name: "alice", Age: 30},
			fieldName: "Other",
			formatFn:  func(v any) any { return "changed" },
			expected: []map[string]any{
				{"Name": "alice", "Age": float64(30)},
			},
		},
		{
			name:      "formats int field",
			input:     Person{Name: "bob", Age: 10},
			fieldName: "Age",
			formatFn: func(v any) any {
				i, _ := v.(int)
				return i * 2
			},
			expected: []map[string]any{
				{"Name": "bob", "Age": float64(20)},
			},
		},
		{
			name:      "formats all rows in slice",
			input:     []Person{{Name: "a", Age: 1}, {Name: "b", Age: 2}},
			fieldName: "Name",
			formatFn: func(v any) any {
				s, _ := v.(string)
				return s + "_suffix"
			},
			expected: []map[string]any{
				{"Name": "a_suffix", "Age": float64(1)},
				{"Name": "b_suffix", "Age": float64(2)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			var buf bytes.Buffer
			formatter := output.ForName(tt.fieldName, tt.formatFn)

			// when
			builder, err := output.From(tt.input)
			assert.NoError(t, err)

			err = builder.Format(formatter).As(output.JSON).To(&buf)

			// then
			assert.NoError(t, err)

			var got []map[string]any
			err = json.Unmarshal(buf.Bytes(), &got)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestFormat_ForType(t *testing.T) {
	t.Run("formats string type", func(t *testing.T) {
		// given
		var buf bytes.Buffer
		input := Person{Name: "test", Age: 25}
		formatter := output.ForType(func(s string) any { return s + "_typed" })

		// when
		builder, err := output.From(input)
		assert.NoError(t, err)

		err = builder.Format(formatter).As(output.JSON).To(&buf)

		// then
		assert.NoError(t, err)

		var got []map[string]any
		err = json.Unmarshal(buf.Bytes(), &got)
		assert.NoError(t, err)
		assert.Equal(t, "test_typed", got[0]["Name"])
		assert.EqualValues(t, 25, got[0]["Age"])
	})

	t.Run("formats int type", func(t *testing.T) {
		// given
		var buf bytes.Buffer
		input := Person{Name: "test", Age: 10}
		formatter := output.ForType(func(i int) any { return i * 3 })

		// when
		builder, err := output.From(input)
		assert.NoError(t, err)

		err = builder.Format(formatter).As(output.JSON).To(&buf)

		// then
		assert.NoError(t, err)

		var got []map[string]any
		err = json.Unmarshal(buf.Bytes(), &got)
		assert.NoError(t, err)
		assert.Equal(t, "test", got[0]["Name"])
		assert.EqualValues(t, 30, got[0]["Age"])
	})

	t.Run("formats bool type", func(t *testing.T) {
		// given
		var buf bytes.Buffer
		input := MultiType{String: "s", Int: 1, Bool: true}
		formatter := output.ForType(func(b bool) any { return !b })

		// when
		builder, err := output.From(input)
		assert.NoError(t, err)

		err = builder.Format(formatter).As(output.JSON).To(&buf)

		// then
		assert.NoError(t, err)

		var got []map[string]any
		err = json.Unmarshal(buf.Bytes(), &got)
		assert.NoError(t, err)
		assert.Equal(t, false, got[0]["Bool"])
	})

	t.Run("non-matching type unchanged", func(t *testing.T) {
		// given
		var buf bytes.Buffer
		input := Person{Name: "test", Age: 42}
		formatter := output.ForType(func(f float64) any { return f * 2 })

		// when
		builder, err := output.From(input)
		assert.NoError(t, err)

		err = builder.Format(formatter).As(output.JSON).To(&buf)

		// then
		assert.NoError(t, err)

		var got []map[string]any
		err = json.Unmarshal(buf.Bytes(), &got)
		assert.NoError(t, err)
		assert.Equal(t, "test", got[0]["Name"])
		assert.EqualValues(t, 42, got[0]["Age"])
	})
}

func TestFormat_MultipleFormatters(t *testing.T) {
	t.Run("applies multiple formatters in order", func(t *testing.T) {
		// given
		var buf bytes.Buffer
		input := Person{Name: "alice", Age: 5}
		nameFormatter := output.ForName("Name", func(v any) any {
			s, _ := v.(string)
			return s + "!"
		})
		ageFormatter := output.ForName("Age", func(v any) any {
			i, _ := v.(int)
			return i * 10
		})

		// when
		builder, err := output.From(input)
		assert.NoError(t, err)

		err = builder.Format(nameFormatter, ageFormatter).As(output.JSON).To(&buf)

		// then
		assert.NoError(t, err)

		var got []map[string]any
		err = json.Unmarshal(buf.Bytes(), &got)
		assert.NoError(t, err)
		assert.Equal(t, "alice!", got[0]["Name"])
		assert.EqualValues(t, 50, got[0]["Age"])
	})

	t.Run("later formatter overrides earlier for same field", func(t *testing.T) {
		// given
		var buf bytes.Buffer
		input := Person{Name: "test", Age: 1}
		first := output.ForName("Name", func(v any) any { return "first" })
		second := output.ForName("Name", func(v any) any { return "second" })

		// when
		builder, err := output.From(input)
		assert.NoError(t, err)

		err = builder.Format(first, second).As(output.JSON).To(&buf)

		// then
		assert.NoError(t, err)

		var got []map[string]any
		err = json.Unmarshal(buf.Bytes(), &got)
		assert.NoError(t, err)
		assert.Equal(t, "second", got[0]["Name"])
	})

	t.Run("chained Format calls accumulate formatters", func(t *testing.T) {
		// given
		var buf bytes.Buffer
		input := Person{Name: "x", Age: 2}
		nameFormatter := output.ForName("Name", func(v any) any { return "changed" })
		ageFormatter := output.ForName("Age", func(v any) any { return 100 })

		// when
		builder, err := output.From(input)
		assert.NoError(t, err)

		err = builder.Format(nameFormatter).Format(ageFormatter).As(output.JSON).To(&buf)

		// then
		assert.NoError(t, err)

		var got []map[string]any
		err = json.Unmarshal(buf.Bytes(), &got)
		assert.NoError(t, err)
		assert.Equal(t, "changed", got[0]["Name"])
		assert.EqualValues(t, 100, got[0]["Age"])
	})
}

func TestBuilder_DefaultFormat(t *testing.T) {
	t.Run("defaults to tabular format", func(t *testing.T) {
		// given
		var buf bytes.Buffer
		input := Person{Name: "test", Age: 25}

		// when
		builder, err := output.From(input)
		assert.NoError(t, err)

		err = builder.To(&buf)

		// then
		assert.NoError(t, err)
		result := buf.String()
		assert.Contains(t, result, "Name")
		assert.Contains(t, result, "Age")
		assert.Contains(t, result, "test")
		assert.Contains(t, result, "25")
		assert.NotContains(t, result, "{")
	})
}

func TestBuilder_Chaining(t *testing.T) {
	t.Run("As returns builder for chaining", func(t *testing.T) {
		// given
		var buf bytes.Buffer
		input := Person{Name: "chain", Age: 1}

		// when
		builder, err := output.From(input)
		assert.NoError(t, err)

		result := builder.As(output.JSON)

		// then
		assert.Same(t, builder, result)
		err = result.To(&buf)
		assert.NoError(t, err)
	})

	t.Run("Format returns builder for chaining", func(t *testing.T) {
		// given
		var buf bytes.Buffer
		input := Person{Name: "chain", Age: 1}
		formatter := output.ForName("Name", func(v any) any { return v })

		// when
		builder, err := output.From(input)
		assert.NoError(t, err)

		result := builder.Format(formatter)

		// then
		assert.Same(t, builder, result)
		err = result.To(&buf)
		assert.NoError(t, err)
	})

	t.Run("full fluent chain works", func(t *testing.T) {
		// given
		var buf bytes.Buffer
		input := Person{Name: "fluent", Age: 99}

		// when
		builder, err := output.From(input)
		assert.NoError(t, err)

		err = builder.
			Format(output.ForName("Name", func(v any) any { return "modified" })).
			Format(output.ForType(func(i int) any { return i + 1 })).
			As(output.JSON).
			To(&buf)

		// then
		assert.NoError(t, err)

		var got []map[string]any
		err = json.Unmarshal(buf.Bytes(), &got)
		assert.NoError(t, err)
		assert.Equal(t, "modified", got[0]["Name"])
		assert.EqualValues(t, 100, got[0]["Age"])
	})
}
