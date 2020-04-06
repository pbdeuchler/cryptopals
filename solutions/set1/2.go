package main

import (
	"encoding/hex"
	"fmt"

	"github.com/pbdeuchler/cryptopals/cipher"
)

func main() {
	input1 := "1c0111001f010100061a024b53535009181c"
	input2 := "686974207468652062756c6c277320657965"
	input1Bytes, _ := hex.DecodeString(input1)
	input2Bytes, _ := hex.DecodeString(input2)
	xordBytes := cipher.XOREqualSizedBytes(input1Bytes, input2Bytes)
	fmt.Println(hex.EncodeToString(xordBytes))
}
