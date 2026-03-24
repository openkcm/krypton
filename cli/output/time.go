package output

import (
	"strconv"
	"time"
)

// formatRelativeTime converts a Unix timestamp (seconds) to a human-readable
// relative time string like "2h ago", "3d ago", etc.
func formatRelativeTime(unixTimestamp int64) string {
	t := time.Unix(0, unixTimestamp)
	duration := time.Since(t)

	switch {
	case duration < time.Minute:
		return "just now"
	case duration < time.Hour:
		return formatDuration(int64(duration.Minutes()), "m")
	case duration < 24*time.Hour:
		return formatDuration(int64(duration.Hours()), "h")
	case duration < 7*24*time.Hour:
		return formatDuration(int64(duration.Hours()/(24)), "d")
	default:
		return formatDuration(int64(duration.Hours()/(24*7)), "w")
	}
}

func formatDuration(value int64, unit string) string {
	return strconv.FormatInt(value, 10) + unit + " ago"
}
