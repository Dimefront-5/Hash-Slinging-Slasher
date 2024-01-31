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
)

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
