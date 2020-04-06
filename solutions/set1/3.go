package main

import (
	"encoding/hex"
	"fmt"

	"github.com/pbdeuchler/cryptopals/analysis"
	"github.com/pbdeuchler/cryptopals/cipher"
)

func main() {
	input1 := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	input1Bytes, _ := hex.DecodeString(input1)
	for i := 0; i < 256; i++ {
		// testCharBytes, _ := hex.DecodeString(testChar)
		xordBytes := cipher.XORSingleByte(input1Bytes, byte(i))
		if analysis.DetectEnglish(string(xordBytes)) {
			fmt.Println(i)
			fmt.Println(string(xordBytes))
		}
	}
}
