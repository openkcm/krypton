package model

import (
	"maps"
	"slices"
	"strings"
)

type Labels map[string]string

// ReservedLabelPrefix prefixes labels reserved for internal use.
const ReservedLabelPrefix = "krypton:"

// IsReservedKey reports whether k is a reserved label key.
func IsReservedKey(k string) bool {
	return strings.HasPrefix(k, ReservedLabelPrefix)
}

// HasReserved returns an arbitrary reserved label key and whether one exists.
func (l Labels) HasReserved() (string, bool) {
	for k := range l {
		if IsReservedKey(k) {
			return k, true
		}
	}
	return "", false
}

// String returns the labels as a sorted key=value string.
func (l Labels) String() string {
	if len(l) == 0 {
		return ""
	}
	keys := slices.Sorted(maps.Keys(l))
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + l[k]
	}
	return strings.Join(parts, ",")
}
