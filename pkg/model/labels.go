package model

import (
	"maps"
	"slices"
	"strings"
)

type Labels map[string]string

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
