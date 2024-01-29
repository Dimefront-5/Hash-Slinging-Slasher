package main

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

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

	// Iterate over each word in the wordlist and check if its hash matches the given hash
	for _, word := range words {
		// Calculate the hash of the current word
		hashedWord := fmt.Sprintf("%x", sha256.Sum256([]byte(word)))

		// Check if the hash matches the given hash
		if hashedWord == hash {
			fmt.Println("Hash cracked! The original word is:", word)
			return
		}
	}

	// If no match is found, print a message
	fmt.Println("Unable to crack the hash.")
}
