package cmd

import (
	"time"

	"github.com/openkcm/krypton/cli/output"
	"github.com/openkcm/krypton/internal/clock"
	"github.com/openkcm/krypton/pkg/model"
)

var timeFormatter = output.ForType(func(t clock.UnixNano) any {
	return t.Time().Format(time.RFC3339)
})

var labelsFormatter = output.ForType(func(l model.Labels) any {
	return l.String()
})

// formatOutput formats the output based on the asJSON flag.
func formatOutput(builder *output.Builder, asJSON bool) *output.Builder {
	format := output.Tabular
	formatters := []output.Formatter{timeFormatter, labelsFormatter}

	if asJSON {
		format = output.JSON
		formatters = []output.Formatter{timeFormatter}
	}

	return builder.Format(formatters...).As(format)
}
