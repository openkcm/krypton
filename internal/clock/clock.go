package clock

import "time"

// NowUTC returns the current time in UTC as a Unix timestamp.
func NowUTC() float64 {
	return float64(time.Now().UTC().Unix())
}
