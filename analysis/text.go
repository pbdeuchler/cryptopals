package analysis

import (
	"strings"
	"unicode"
)

// Actually detects english by a percentage of alpha chars
func DetectEnglish(input string) (bool, float64) {
	letterCount := 0
	spaceCount := 0
	for _, char := range input {
		if unicode.IsSpace(char) {
			spaceCount = spaceCount + 1
			continue
		}
		if unicode.IsLetter(char) {
			letterCount = letterCount + 1
		}
	}

	// score := 0.05 * float64(len(input))
	// if (len(input) - spaceCount - letterCount) <= int(score) {
	// 	return true, score
	// }
	// return false, score

	// this percentage is totally made up, but it works
	nonAlphaPercent := 0.05 * float64(len(input))
	score := nonAlphaPercent - float64(len(input)-spaceCount-letterCount)
	if score > 0 {
		return true, score
	}
	return false, score
}

func DetectEnglishBySpaces(input string) (bool, float64) {
	letterCount := 0
	spaceCount := 0
	for _, char := range input {
		if unicode.IsSpace(char) {
			spaceCount = spaceCount + 1
			continue
		}
		if unicode.IsLetter(char) {
			letterCount = letterCount + 1
		}
	}
	words := strings.Split(input, " ")
	cleanedWords := []string{}
	for _, word := range words {
		if word != "" {
			cleanedWords = append(cleanedWords, word)
		}
	}
	amtOfWords := len(cleanedWords)
	spacesScore := float64(amtOfWords-spaceCount) / float64(amtOfWords)
	if spacesScore <= 1.0 && spacesScore >= -1.0 {
		return true, spacesScore
	}
	return false, spacesScore
}

func CharHistogram(input []byte) float64 {
	score := 0.0

	// http://fitaly.com/board/domper3/posts/136.html
	charFrequencies := map[byte]float64{9: 0.0057, 23: 0.0000, 32: 17.1662, 33: 0.0072, 34: 0.2442, 35: 0.0179, 36: 0.0561, 37: 0.0160, 38: 0.0226, 39: 0.2447, 40: 0.2178, 41: 0.2233, 42: 0.0628, 43: 0.0215, 44: 0.7384, 45: 1.3734, 46: 1.5124, 47: 0.1549, 48: 0.5516, 49: 0.4594, 50: 0.3322, 51: 0.1847, 52: 0.1348, 53: 0.1663, 54: 0.1153, 55: 0.1030, 56: 0.1054, 57: 0.1024, 58: 0.4354, 59: 0.1214, 60: 0.1225, 61: 0.0227, 62: 0.1242, 63: 0.1474, 64: 0.0073, 65: 0.3132, 66: 0.2163, 67: 0.3906, 68: 0.3151, 69: 0.2673, 70: 0.1416, 71: 0.1876, 72: 0.2321, 73: 0.3211, 74: 0.1726, 75: 0.0687, 76: 0.1884, 77: 0.3529, 78: 0.2085, 79: 0.1842, 80: 0.2614, 81: 0.0316, 82: 0.2519, 83: 0.4003, 84: 0.3322, 85: 0.0814, 86: 0.0892, 87: 0.2527, 88: 0.0343, 89: 0.0304, 90: 0.0076, 91: 0.0086, 92: 0.0016, 93: 0.0088, 94: 0.0003, 95: 0.1159, 96: 0.0009, 97: 5.1880, 98: 1.0195, 99: 2.1129, 100: 2.5071, 101: 8.5771, 102: 1.3725, 103: 1.5597, 104: 2.7444, 105: 4.9019, 106: 0.0867, 107: 0.6753, 108: 3.1750, 109: 1.6437, 110: 4.9701, 111: 5.7701, 112: 1.5482, 113: 0.0747, 114: 4.2586, 115: 4.3686, 116: 6.3700, 117: 2.0999, 118: 0.8462, 119: 1.3034, 120: 0.1950, 121: 1.1330, 122: 0.0596, 123: 0.0026, 124: 0.0007, 125: 0.0026, 126: 0.0003, 131: 0.0000, 149: 0.6410, 183: 0.0010, 223: 0.0000, 226: 0.0000, 229: 0.0000, 230: 0.0000, 237: 0.0000}
	for _, char := range input {
		if frequency, ok := charFrequencies[char]; ok {
			score = score + frequency
		}
	}
	return score
}
