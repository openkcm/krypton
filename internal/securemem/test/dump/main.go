package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/openkcm/krypton/internal/securemem"
)

var (
	triggerID               = os.Getenv("TRIGGER_ID")
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
	handlerResponse := securememRunner()

	// Simulate an un unsecured secret read that is not protected by securemem
	unSecuredSecretReader()

	// Create a trigger file to keep the container running for analysis
	go createTrigger()

	// Wait for SIGINT/SIGTERM
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	err := handlerResponse.MemVault().DestroyAll()
	if err != nil {
		log.Printf("Error destroying secrets: %v\n", err)
	}

	log.Println("Shutting down...")
}

// createTrigger creates a file named "start_<triggerID>" to signal that the process is ready for analysis.
// It retries if there is an error creating the file, which can happen if there are transient filesystem issues.
func createTrigger() {
	for {
		_, err := os.Create("start_" + triggerID)
		if err != nil {
			time.Sleep(10 * time.Second)
			fmt.Printf("Error creating file: %v\n", err)
			continue
		}
		break
	}
}

// unSecuredSecretReader simulates a secret that is not protected by securemem.
// It reads the secret from a file and attempts to create an AES cipher with it,
// which would expose the secret in memory if it is not protected.
func unSecuredSecretReader() {
	exposedSecretBytes := make([]byte, 32)
	err := readSecretBytesFromFile("exposed_"+triggerID, exposedSecretBytes)
	if err != nil {
		panic(err)
	}

	_, err = aes.NewCipher(exposedSecretBytes)
	if err != nil {
		panic(fmt.Sprintf("Failed to create AES cipher with exposed secret: %v", err))
	}
}

// securememRunner runs the securemem handler and checks if the secret is present in the MemVault after execution.
func securememRunner() *securemem.HandlerResponse {
	resp, err := securemem.Run(context.Background(), func(ctx context.Context, hr *securemem.HandlerRequest) error {
		secret, err := hr.PersistentVault().Reserve("secret", 32)
		if err != nil {
			return err
		}

		err = readSecretBytesFromFile("secret_"+triggerID, secret)
		if err != nil {
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
	_, ok := resp.MemVault().Get("secret")
	if !ok {
		fmt.Println("❌ SECRET NOT FOUND IN MEMVAULT")
	} else {
		fmt.Println("✅ SECRET FOUND IN MEMVAULT")
	}

	return resp
}

// enableDump sets the process memory to be non-dumpable, which should prevent secrets from being exposed in core dumps.
func enableDump() {
	err := securemem.NoDump()
	if err != nil {
		panic(fmt.Sprintf("Failed to set no dump: %v", err))
	}
}

// readSecretBytesFromFile reads bytes from a file into the provided byte slice. It returns an error if the file cannot be read.
func readSecretBytesFromFile(filename string, to []byte) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = bufio.NewReader(file).Read(to)
	return err
}
