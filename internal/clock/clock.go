package clock

import "time"

// NowUnixUTC returns the current time in UTC as Unix nanoseconds.
func NowUnixUTC() int64 {
	return time.Now().UTC().UnixNano()
}
