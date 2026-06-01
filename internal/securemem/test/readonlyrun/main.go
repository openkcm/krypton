package main

import (
	"context"
	"errors"
	"log"

	"github.com/openkcm/krypton/internal/securemem"
)

const SecretData = "MYSECRET1234567890"

// This program demonstrates the use of the securemem package to create a secure memory region,
// store secret data in it, and then attempt to modify it, which should result in a panic due
// to the read-only protection. The program also includes a deferred function to recover from
// any panics and log them, but in this case, we expect the process to be terminated due to the
// read-only protection when trying to modify the secret data.
func main() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC RECOVERED: %v\n", r)
		}
	}()

	// Run the secure memory handler to store the secret data in a secure memory region.
	res, err := securemem.Run(context.Background(), func(ctx context.Context, req *securemem.HandlerRequest) error {
		// Reserve a memory region in the persistent vault for the secret data.
		b, err := req.PersistentVault().Reserve("secret", len(SecretData))
		if err != nil {
			return err
		}

		// Copy the secret data into the reserved memory region.
		copy(b, SecretData)
		return nil
	})
	if err != nil {
		panic(err)
	}

	defer func() {
		err := res.MemVault().DestroyAll()
		if err != nil {
			panic(err)
		}
	}()

	// Attempt to retrieve the secret data from the vault and print it.
	d, ok := res.MemVault().Get("secret")
	if !ok {
		panic(errors.New("secret not found in vault"))
	}

	// Print the secret data. This should work fine.
	log.Println(string(d.SecureBytes()))

	// Attempt to modify the secret data. This should cause a panic due to read-only memory.
	d.SecureBytes()[0] = 'X' // This should cause a panic due to read-only memory
}
