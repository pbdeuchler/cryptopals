package analysis

import (
	"math/bits"

	"github.com/pbdeuchler/cryptopals/cipher"
)

func HammingDistance(a, b []byte) int {
	xord := cipher.XOREqualSizedBytes(a, b)
	count := 0
	for _, word := range xord {
		count = count + bits.OnesCount(uint(word))
	}
	return count
}
