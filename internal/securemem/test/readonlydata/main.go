package main

import (
	"log/slog"

	"github.com/openkcm/krypton/internal/securemem"
)

const SecretData = "secret"

// This example demonstrates the usage of the securemem package to create a secure memory region,
// write data to it, mark it as read-only, and attempt to modify it,
// which results in a system termination of the process due to the read-only protection.
func main() {
	defer func() {
		if r := recover(); r != nil {
			slog.Info("PANIC RECOVERED:", "err", r)
		}
	}()

	// create a secure memory region for the secret data
	data, err := securemem.NewData("secret", len(SecretData))
	if err != nil {
		panic(err)
	}

	defer func() {
		err := data.Destroy()
		if err != nil {
			panic(err)
		}
	}()

	// copy the secret data into the secure memory region
	copy(data.SecureBytes(), []byte(SecretData))

	// make the memory region read-only
	err = data.MarkReadOnly()
	if err != nil {
		panic(err)
	}

	// print the secret data
	slog.Info(string(data.SecureBytes()))

	// attempt to modify the read-only memory region, which should cause a panic due to the read-only protection
	data.SecureBytes()[0] = 's' // panic: runtime error: invalid memory address or nil pointer dereference
}
