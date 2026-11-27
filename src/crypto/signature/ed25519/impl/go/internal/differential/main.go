package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	abc "github.com/All-Basket-Cryptography/abc/src/crypto/signature/ed25519/impl/go"
)

func unhex(raw string) []byte {
	value, err := hex.DecodeString(raw)
	if err != nil {
		panic(err)
	}
	return value
}

func main() {
	input := bufio.NewScanner(os.Stdin)
	for input.Scan() {
		fields := strings.Split(input.Text(), ":")
		if len(fields) != 3 {
			panic("expected seed, message and reference signature")
		}
		seed := [abc.SeedSize]byte(unhex(fields[0]))
		message := unhex(fields[1])
		sigReference := [abc.SignatureSize]byte(unhex(fields[2]))
		public, signature := abc.PublicKey(seed), abc.Sign(seed, message)
		if err := abc.VerifyStrict(public, message, sigReference); err != nil {
			panic(err)
		}
		fmt.Printf("%x:%x\n", public, signature)
	}
	if err := input.Err(); err != nil {
		panic(err)
	}
}
