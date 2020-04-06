package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/pbdeuchler/cryptopals/analysis"
	"github.com/pbdeuchler/cryptopals/cipher"
)

func main() {
	file, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		input1Bytes, _ := hex.DecodeString(scanner.Text())
		for i := 0; i < 256; i++ {
			// testCharBytes, _ := hex.DecodeString(testChar)
			xordBytes := cipher.XORSingleByte(input1Bytes, byte(i))
			if check, score := analysis.DetectEnglish(string(xordBytes)); check {
				if check2, score2 := analysis.DetectEnglishBySpaces(string(xordBytes)); check2 {
					fmt.Printf("Key: %x, Score1: %D, Score2: %D\n", i, score, score2)
					fmt.Println(string(xordBytes))
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}
