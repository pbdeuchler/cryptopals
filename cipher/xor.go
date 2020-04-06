package cipher

func XOREqualSizedBytes(a, b []byte) []byte {
	result := []byte{}
	for i := 0; i < len(a); i++ {
		result = append(result, a[i]^b[i])
	}
	return result
}

func XORByte(a, b byte) byte {
	return a ^ b
}

func XORSingleByte(plaintext []byte, single byte) []byte {
	result := []byte{}
	for _, word := range plaintext {
		result = append(result, word^single)
	}
	return result
}

func XORBytes(ciphertext, key []byte) []byte {
	var plaintext []byte
	for idx, _ := range ciphertext {
		plaintext = append(plaintext, ciphertext[idx]^key[idx%len(key)])
	}
	return plaintext
}
