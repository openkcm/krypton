package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/openkcm/krypton/internal/securemem"
)

var (
	triggerName             = os.Getenv("TRIGGER_NAME")
	isDumpProtectionEnabled = os.Getenv("IS_DUMP_PROTECTION_ENABLED")
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("PANIC RECOVERED: %v\n", r)
		}
	}()

	// Enable dump protection before any secrets are loaded into memory
	if isDumpProtectionEnabled == "true" {
		enableDump()
	}
	// Run the secret runner and the exposed secret in parallel to simulate a real-world scenario
	secretRunner()

	// Simulate an exposed secret that is not protected by securemem
	exposedSecret()

	// Create a trigger file to keep the container running for analysis
	createTrigger()
}

func createTrigger() {
	isCreated := false
	for {
		if !isCreated {
			_, err := os.Create("start_" + triggerName)
			if err != nil {
				fmt.Printf("Error creating file: %v\n", err)
				continue
			}
			isCreated = true
		}
		time.Sleep(10 * time.Second)
	}
}

func exposedSecret() {
	exposedSecret := "EXPOSED_SECRET123456789012345678"
	_, err := aes.NewCipher([]byte(exposedSecret))
	if err != nil {
		panic(fmt.Sprintf("Failed to create AES cipher with exposed secret: %v", err))
	}
}

func secretRunner() {
	resp, err := securemem.Run(context.Background(), func(ctx context.Context, hr *securemem.HandlerRequest) error {
		file, err := os.Open("secret_" + triggerName)
		if err != nil {
			return err
		}
		defer file.Close()

		secret, err := hr.PersistentVault().Reserve("secret", 32)
		if err != nil {
			return err
		}

		_, err = bufio.NewReader(file).Read(secret)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}

		_, err = aes.NewCipher(secret)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("Checking for secrets in MemVault...")
	secret, ok := resp.MemVault().Get("secret")
	if !ok {
		fmt.Println("❌ SECRET NOT FOUND IN MEMVAULT")
	} else {
		fmt.Println("✅ SECRET FOUND IN MEMVAULT")
	}

	keepInMem(secret)
}

func enableDump() {
	err := securemem.NoDump()
	if err != nil {
		panic(fmt.Sprintf("Failed to set no dump: %v", err))
	}
}

func keepInMem(b []byte) {
	go func() {
		for {
			// The condition is never true at runtime; the loop just prevents
			// the slice from being optimised away entirely.
			if b[0] == 0xFF {
				panic("keepAlive: unreachable")
			}
		}
	}()
}
