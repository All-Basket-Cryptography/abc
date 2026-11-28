package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	argon2id "github.com/All-Basket-Cryptography/abc/src/crypto/kdf/argon2id/impl/go"
)

func main() {
	input := bufio.NewScanner(os.Stdin)
	for input.Scan() {
		fields := strings.Split(input.Text(), ":")
		if len(fields) != 8 {
			panic("expected eight differential fixture fields")
		}
		var numeric [4]uint32
		for i := range numeric {
			value, err := strconv.ParseUint(fields[i], 10, 32)
			if err != nil {
				panic(err)
			}
			numeric[i] = uint32(value)
		}
		p, err := argon2id.NewParameters(numeric[0], numeric[1], numeric[2])
		if err != nil {
			panic(err)
		}
		var bytes [4][]byte
		for i := range bytes {
			bytes[i], err = hex.DecodeString(fields[i+4])
			if err != nil {
				panic(err)
			}
		}
		tag := make([]byte, numeric[3])
		workspace := make([]argon2id.Block, p.WorkspaceBlocks())
		if err := argon2id.Derive(bytes[0], bytes[1], bytes[2], bytes[3], p, tag, workspace); err != nil {
			panic(err)
		}
		fmt.Println(hex.EncodeToString(tag))
	}
	if err := input.Err(); err != nil {
		panic(err)
	}
}
