package main

import (
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

	data, err := securemem.NewMemVaultData("secret", len(secret))
	if err != nil {
		panic(err)
	}

	defer func() {
		err := data.Destroy()
		if err != nil {
			panic(err)
		}
	}()

	copy(data.Data(), []byte(secret))

	err = data.MarkReadOnly()
	if err != nil {
		panic(err)
	}

	fmt.Println(string(data.Data()))
	data.Data()[0] = 's' // panic: runtime error: invalid memory address or nil pointer dereference
}
