package output

import (
	"sort"
	"strings"
)

// formatLabels formats labels as "key1=val1,key2=val2" and truncates
// to maxLen with "..." suffix if necessary.
func formatLabels(labels map[string]string, maxLen int) string {
	if len(labels) == 0 {
		return "<none>"
	}

	// Sort keys for consistent output
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build label string
	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(k)
		sb.WriteString("=")
		sb.WriteString(labels[k])
	}

	result := sb.String()
	if len(result) > maxLen {
		return result[:maxLen-3] + "..."
	}
	return result
}
