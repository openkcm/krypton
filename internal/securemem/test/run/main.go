package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/openkcm/krypton/internal/securemem"
)

const secret = "MYSECRET1234567890"

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("PANIC RECOVERED: %v\n", r)
		}
	}()

	res, err := securemem.Run(context.Background(), func(ctx context.Context, req *securemem.HandlerRequest) error {
		b, err := req.PersistentVault().Reserve("secret", len(secret))
		if err != nil {
			return err
		}
		copy(b, secret)
		return nil
	})
	if err != nil {
		panic(err)
	}

	b, ok := res.MemVault().Get("secret")
	if !ok {
		panic(errors.New("secret not found in vault"))
	}

	fmt.Println(string(b))
	b[0] = 'X' // This should cause a panic due to read-only memory
}
