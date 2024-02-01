package main

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha1"
	"crypto/sha512"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

const SHA256_LEN = 64
const MD5_LEN = 32
const SHA1_LEN = 40
const SHA512_LEN = 128
const SHA384_LEN = 96

const characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

func main() {

	if len(os.Args) != 3 {
		println("Usage: go run Cracker.go <hash> <wordlist>")
		return
	}

	hash := os.Args[1]
	wordlistPath := os.Args[2]
	start := time.Now()
	findMatchingHash(hash, wordlistPath)
	duration := time.Since(start)
	println("Time elapsed: ", duration)
}


func findMatchingHash(hash string, wordlistPath string) {

	// Read the wordlist file
	wordlistBytes, err := ioutil.ReadFile(wordlistPath)
	if err != nil {
		println("Error reading wordlist:", err)
		return
	}

	// Convert the wordlist to a string array
	wordlist := string(wordlistBytes)
	words := strings.Split(wordlist, "\n")

	hashLen := len(hash)

	// Iterate over each word in the wordlist and check if its hash matches the given hash
	for _, word := range words {
		if calculateWordHash(hashLen, word) == hash {
			println("Hash cracked! The original word is:", word)
			return
		}
	}

	// If no match is found, let's iterate over all possible combinations of characters
	shouldReturn := iteratingOverAllCombinations(hashLen, hash)
	if shouldReturn {
		return
	}
	
	// If no match is found, print a message
	println("Unable to crack the hash.")
}


// Calculate the hash of a given word,
// the hash function to be used is based on the length of the hash
func calculateWordHash(hashLen int, word string) string {
	var hashedWord string

	switch hashLen {
	case SHA256_LEN:
		hashedWord = fmt.Sprintf("%x", sha256.Sum256([]byte(word)))
	case MD5_LEN:
		hashedWord = fmt.Sprintf("%x", md5.Sum([]byte(word)))
	case SHA1_LEN:
		hashedWord = fmt.Sprintf("%x", sha1.Sum([]byte(word)))
	case SHA512_LEN:
		hashedWord = fmt.Sprintf("%x", sha512.Sum512([]byte(word)))
	case SHA384_LEN:
		hashedWord = fmt.Sprintf("%x", sha512.Sum384([]byte(word)))
	}
	return hashedWord
}


func iteratingOverAllCombinations(hashLen int, hash string) bool {

	maxLength := 10

	for length := 1; length <= maxLength; length++ {
		for _, character := range generateCombinations(characters, length) {
			hashedGuess := calculateWordHash(hashLen, character)

			if hash == hashedGuess {
				println("Hash cracked! The original word is:", character)
				return true
			}
		}
	}
	return false
}

func generateCombinations(characters string, length int) []string {
	var result []string
	generateCombinationsHelper(characters, length, "", &result)
	return result
}

func generateCombinationsHelper(characters string, length int, current string, result *[]string) {
	if length == 0 {
		*result = append(*result, current)
		return
	}
	for _, char := range characters {
		generateCombinationsHelper(characters, length-1, current+string(char), result)
	}
}