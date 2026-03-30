package model

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

// Has reports whether all of the flags in usage are set in ku. Returns false if usage is zero.
func (u KeyUsage) Has(usage KeyUsage) bool {
	if usage == 0 {
		return false
	}
	return u&usage == usage
}
