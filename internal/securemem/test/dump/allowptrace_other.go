//go:build !linux

package main

// allowPtrace is a no-op on non-Linux platforms; the dump analysis only runs
// in a Linux container.
func allowPtrace() {}
