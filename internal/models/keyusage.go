package models

import (
	"fmt"
	"strings"
)

// KeyUsage is a bitmask describing the permitted operations for a key.
type KeyUsage uint

// KeyUsageNone indicates that the key has no permitted operations.
const KeyUsageNone KeyUsage = 0

const (
	// KeyUsageEncrypt allows the key to be used for encryption operations.
	KeyUsageEncrypt KeyUsage = 1 << iota
	// KeyUsageDecrypt allows the key to be used for decryption operations.
	KeyUsageDecrypt
	// KeyUsageWrap allows the key to be used for wrapping (encrypting) other keys.
	KeyUsageWrap
	// KeyUsageUnwrap allows the key to be used for unwrapping (decrypting) other keys.
	KeyUsageUnwrap
)

// validKeyUsages defines the set of valid KeyUsage flags for iteration in the String() method.
var validKeyUsages = []KeyUsage{
	KeyUsageEncrypt,
	KeyUsageDecrypt,
	KeyUsageWrap,
	KeyUsageUnwrap,
}

// validKeyUsageNames maps each KeyUsage flag to its string representation for use in the String() method.
var validKeyUsageNames = map[KeyUsage]string{
	KeyUsageEncrypt: "encrypt",
	KeyUsageDecrypt: "decrypt",
	KeyUsageWrap:    "wrap",
	KeyUsageUnwrap:  "unwrap",
}

// Has reports whether all of the flags in usage are set in ku. Returns false if usage is zero.
func (u KeyUsage) Has(usage KeyUsage) bool {
	if usage == 0 {
		return false
	}
	return u&usage == usage
}

// String returns a string representation of the KeyUsage, listing all set flags separated by
// '|', or "none" if no flags are set.
func (u KeyUsage) String() string {
	if u == KeyUsageNone {
		return "none"
	}

	var allKeyUsage KeyUsage

	var sb strings.Builder
	for _, validUsage := range validKeyUsages {
		allKeyUsage |= validUsage
		hasPermission := u.Has(validUsage)
		if hasPermission {
			if sb.Len() > 0 {
				sb.WriteString("|")
			}
			validUsageName := validKeyUsageNames[validUsage]
			sb.WriteString(validUsageName)
		}
	}

	extraFlags := u &^ allKeyUsage
	if extraFlags != 0 {
		if sb.Len() > 0 {
			sb.WriteString("|")
		}
		fmt.Fprintf(&sb, "unknown(%d)", extraFlags)
	}
	return sb.String()
}
