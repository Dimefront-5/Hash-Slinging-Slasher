package main

import (
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

const SHA256_LEN = 64
const MD5_LEN = 32

func main() {
	// Check if the correct number of command-line arguments are provided
	if len(os.Args) != 3 {
		fmt.Println("Usage: go run Cracker.go <hash> <wordlist>")
		return
	}

	// Read the hash and wordlist file paths from command-line arguments
	hash := os.Args[1]
	wordlistPath := os.Args[2]

	// Read the wordlist file
	wordlistBytes, err := ioutil.ReadFile(wordlistPath)
	if err != nil {
		fmt.Println("Error reading wordlist:", err)
		return
	}

	// Convert the wordlist to a string array
	wordlist := string(wordlistBytes)
	words := strings.Split(wordlist, "\n")

	// Get the length of the hash to determine which hash function to use
	hashLen := len(hash)
	// Iterate over each word in the wordlist and check if its hash matches the given hash
	for _, word := range words {

		// Check if the hash matches the given hash
		if calculateWordHash(hashLen, word) == hash {
			fmt.Println("Hash cracked! The original word is:", word)
			return
		}
	}

	// If no match is found, print a message
	fmt.Println("Unable to crack the hash.")
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
	}

	return hashedWord
}
