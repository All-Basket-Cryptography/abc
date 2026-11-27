package main

import (
	"crypto/sha256"
	"fmt"
	"os"

	abc "github.com/All-Basket-Cryptography/abc/sdk/go"
)

func require(condition bool, message string) {
	if !condition {
		panic(message)
	}
}

func main() {
	provider, err := abc.Open(os.Args[1])
	require(err == nil, fmt.Sprint(err))
	require(provider.Implementation() == "sha256-abc-rust-portable", "wrong implementation")
	known, err := provider.Digest([]byte("abc"))
	require(err == nil && fmt.Sprintf("%x", known) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "NIST known answer")
	context, err := provider.NewStream()
	require(err == nil, fmt.Sprint(err))
	defer context.Close()
	input := make([]byte, 120)
	for index := range input {
		input[index] = byte(index)
	}
	direct, err := provider.Digest(input)
	require(err == nil && direct == sha256.Sum256(input), "wrong one-shot digest")
	require(context.Update(input[:56]) == nil && context.Update(input[56:]) == nil, "stream update failed")
	streamed, err := context.Finalize()
	require(err == nil && direct == streamed, "wrong streaming digest")
	_, err = context.Finalize()
	require(err != nil && context.Update(input) != nil, "finalized context accepted work")
	require(context.Reset() == nil, "reset failed")
	empty, err := context.Finalize()
	require(err == nil && empty == sha256.Sum256(nil), "wrong reset digest")
	require(context.Close() == nil && context.Close() == nil, "close failed")
	require(context.Update(input) != nil, "released stream accepted work")
	fmt.Println("External Go SHA-256 consumer passed")
}
