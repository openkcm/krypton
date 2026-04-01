package clock

import "time"

// UnixNano is a Unix timestamp in nanoseconds.
type UnixNano int64

// Time converts the UnixNano to a time.Time.
func (t UnixNano) Time() time.Time {
	return time.Unix(0, int64(t))
}

// Now returns the current time as Unix nanoseconds.
func Now() UnixNano {
	return UnixNano(time.Now().UnixNano())
}
