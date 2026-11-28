package main

import (
	"bufio"
	"crypto/mldsa"
	"crypto/mlkem"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

func unhex(value string) []byte {
	output, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return output
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		row := strings.Split(scanner.Text(), ":")
		switch os.Args[1] {
		case "kem":
			key, err := mlkem.NewDecapsulationKey768(unhex(row[0]))
			if err != nil {
				panic(err)
			}
			secret, ciphertext := key.EncapsulationKey().Encapsulate()
			altered := append([]byte(nil), ciphertext...)
			altered[0] ^= 1
			rejected, err := key.Decapsulate(altered)
			if err != nil {
				panic(err)
			}
			fmt.Printf("%s:%x:%x:%x:%x\n", row[0], key.EncapsulationKey().Bytes(), ciphertext, secret, rejected)
		case "decap":
			key, err := mlkem.NewDecapsulationKey768(unhex(row[0]))
			if err != nil {
				panic(err)
			}
			secret, err := key.Decapsulate(unhex(row[1]))
			if err != nil {
				panic(err)
			}
			fmt.Printf("%x\n", secret)
		case "dsa":
			key, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), unhex(row[0]))
			if err != nil {
				panic(err)
			}
			signature, err := key.SignDeterministic(unhex(row[1]), &mldsa.Options{Context: string(unhex(row[2]))})
			if err != nil {
				panic(err)
			}
			fmt.Printf("%s:%x:%x\n", scanner.Text(), key.PublicKey().Bytes(), signature)
		default:
			panic("unknown test oracle profile")
		}
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}
}
