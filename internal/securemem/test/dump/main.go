package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"errors"
	"fmt"
	"io"
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
	exposedSecretValue      = os.Getenv("EXPOSED_SECRET")
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
	handlerResponse := secretRunner()

	// Simulate an exposed secret that is not protected by securemem
	exposedSecret()

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

func exposedSecret() {
	_, err := aes.NewCipher([]byte(exposedSecretValue))
	if err != nil {
		panic(fmt.Sprintf("Failed to create AES cipher with exposed secret: %v", err))
	}
}

func secretRunner() *securemem.HandlerResponse {
	resp, err := securemem.Run(context.Background(), func(ctx context.Context, hr *securemem.HandlerRequest) error {
		file, err := os.Open("secret_" + triggerID)
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
	_, ok := resp.MemVault().Get("secret")
	if !ok {
		fmt.Println("❌ SECRET NOT FOUND IN MEMVAULT")
	} else {
		fmt.Println("✅ SECRET FOUND IN MEMVAULT")
	}

	return resp
}

func enableDump() {
	err := securemem.NoDump()
	if err != nil {
		panic(fmt.Sprintf("Failed to set no dump: %v", err))
	}
}
