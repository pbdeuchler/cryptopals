package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"sort"

	"github.com/pbdeuchler/cryptopals/analysis"
	"github.com/pbdeuchler/cryptopals/cipher"
)

func main() {
	// pass in data file from cmd line
	fileBytes, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}

	// decode base64
	fileBytes, err = base64.StdEncoding.DecodeString(string(fileBytes))
	if err != nil {
		panic(err)
	}

	// i wonder if it would be faster or take less memory to store this in a datastructure
	distanceToKeySize := map[float64]int{}
	distances := []float64{}
	factor := 4
	// try and find the key size
	for keySize := 2; keySize < 40; keySize++ {
		blockDistances := []float64{}
		// iterate through the ciphertext in blocks of keysize*factor
		// factor needs to be a multiple of two so we can split it and compare hamming distance
		for i := 0; i < len(fileBytes)-(keySize*factor); i += (keySize * factor) {
			buffer := fileBytes[i : i+(keySize*factor)]
			distance := analysis.HammingDistance(buffer[:keySize*(factor/2)], buffer[keySize*(factor/2):])
			// normalize distance by the size of the search space
			normalizedDistance := float64(distance) / float64(keySize)
			blockDistances = append(blockDistances, normalizedDistance)
		}
		// average hamming distances for this keysize
		totalDistanceSum := 0.0
		for _, distance := range blockDistances {
			totalDistanceSum = totalDistanceSum + distance
		}
		avgDistance := totalDistanceSum / float64(len(blockDistances))
		// record so we can sort and then retrieve
		distanceToKeySize[avgDistance] = keySize
		distances = append(distances, avgDistance)
	}
	//sort
	sort.Float64s(distances)
	lowestDistances := []int{}
	for i := 0; i < 3; i++ {
		// retrieve via map
		lowestDistances = append(lowestDistances, distanceToKeySize[distances[i]])
	}

	// now that we have our probable keysize, we brute force since the keysizes
	// are small
	for _, keySize := range lowestDistances {
		probableKeyArray := []byte{}
		// how many blocks of keySize there are in the file
		upperBound := int(math.Ceil(float64(len(fileBytes)) / float64(keySize)))
		// split fileBytes into keySize blocks
		keySizeBlocks := make([][]byte, upperBound)
		for idx, _ := range keySizeBlocks {
			if keySize*(idx+1) >= len(fileBytes) {
				keySizeBlocks[idx] = append(keySizeBlocks[idx], fileBytes[keySize*idx:]...)
			} else {
				keySizeBlocks[idx] = append(keySizeBlocks[idx], fileBytes[keySize*idx:keySize*(idx+1)]...)
			}
		}

		// transpose bytes so we have blocks that contain all the first byte
		// from keySizeBlocks, all the second byte, etc...
		transposedBlocks := make([][]byte, keySize)
		for _, block := range keySizeBlocks {
			for i := 0; i < len(block); i++ {
				transposedBlocks[i] = append(transposedBlocks[i], block[i])
			}
		}

		// Bruteforce, if we get closest to the proper number of ascii letters
		// it's probably english so that's probably the key for that block
		for _, block := range transposedBlocks {
			highestScores := []float64{}
			scoresToKey := map[float64]int{}
			for i := 0; i < 256; i++ {
				xordBytes := cipher.XORSingleByte(block, byte(i))
				score := analysis.CharHistogram(xordBytes)
				highestScores = append(highestScores, score)
				scoresToKey[score] = i
			}
			sort.Float64s(highestScores)
			probableKey := scoresToKey[highestScores[len(highestScores)-1]]
			// append this block's key to what we think the full ciphertext key will be
			probableKeyArray = append(probableKeyArray, byte(probableKey))
		}

		testPlaintext := cipher.XORBytes(fileBytes, probableKeyArray)
		// run through simple filters to ensure we're getting something resembling english
		if check, score := analysis.DetectEnglish(string(testPlaintext)); check {
			if check2, score2 := analysis.DetectEnglishBySpaces(string(testPlaintext)); check2 {
				fmt.Printf("Key: %x, Score1: %f, Score2: %f\n", probableKeyArray, score, score2)
				fmt.Println(string(testPlaintext))
				fmt.Println("---------------------------------------------------------------------------------------")
			}
		}
	}
}
