package main

import (
	"encoding/hex"
	"fmt"

	"github.com/pbdeuchler/cryptopals/cipher"
)

func main() {
	inputArray := []string{"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"}
	key := []byte("ICE")
	for _, input := range inputArray {
		result := []byte{}
		for idx, word := range input {
			result = append(result, cipher.XORByte(byte(word), key[idx%3]))
		}
		fmt.Println(hex.EncodeToString(result))
	}
}
