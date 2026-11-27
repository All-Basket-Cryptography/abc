// Command corpus adapts the Go SDK to the repository's public test corpus.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/All-Basket-Cryptography/abc/src/crypto/kdf/scrypt/impl/go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	lines := bufio.NewScanner(os.Stdin)
	for lines.Scan() {
		fields := strings.Split(lines.Text(), ":")
		if len(fields) != 6 {
			return fmt.Errorf("invalid corpus record")
		}
		password, err := hex.DecodeString(fields[0])
		if err != nil {
			return err
		}
		salt, err := hex.DecodeString(fields[1])
		if err != nil {
			return err
		}
		var parameters [4]int
		for i := range parameters {
			parameters[i], err = strconv.Atoi(fields[i+2])
			if err != nil {
				return err
			}
		}
		p, err := scrypt.NewParameters(parameters[0], parameters[1], parameters[2])
		if err != nil {
			return err
		}
		key, err := scrypt.Derive(password, salt, p, parameters[3], 32<<20)
		if err != nil {
			return err
		}
		fmt.Printf("%x\n", key)
	}
	return lines.Err()
}
