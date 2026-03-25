package output_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/cli/output"
)

func TestFormatRelativeTime(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{
			name:     "just now for seconds ago",
			duration: 30 * time.Second,
			expected: "just now",
		},
		{
			name:     "1 minute ago",
			duration: 1 * time.Minute,
			expected: "1m ago",
		},
		{
			name:     "5 minutes ago",
			duration: 5 * time.Minute,
			expected: "5m ago",
		},
		{
			name:     "59 minutes ago",
			duration: 59 * time.Minute,
			expected: "59m ago",
		},
		{
			name:     "1 hour ago",
			duration: 1 * time.Hour,
			expected: "1h ago",
		},
		{
			name:     "23 hours ago",
			duration: 23 * time.Hour,
			expected: "23h ago",
		},
		{
			name:     "1 day ago",
			duration: 24 * time.Hour,
			expected: "1d ago",
		},
		{
			name:     "6 days ago",
			duration: 6 * 24 * time.Hour,
			expected: "6d ago",
		},
		{
			name:     "1 week ago",
			duration: 7 * 24 * time.Hour,
			expected: "1w ago",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			timestamp := time.Now().Add(-tt.duration).UnixNano()

			// when
			result := output.FormatRelativeTime(timestamp)

			// then
			assert.Equal(t, tt.expected, result)
		})
	}
}
