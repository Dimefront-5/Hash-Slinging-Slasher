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
	"flag"
	"bufio"
)

const SHA256_LEN = 64
const MD5_LEN = 32
const SHA1_LEN = 40
const SHA512_LEN = 128
const SHA384_LEN = 96

const characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

//Outward facing function
func main() {

	printAsciiArt()
	// Parse command-line arguments
	// Check if required arguments are provided
	wordlist, salt, hash, hashlist := parseCommandLine()

	start := time.Now()
	determineIfHashfile(hashlist, wordlist, salt, hash)
	
	duration := time.Since(start)
	println("Time elapsed: ", duration.Seconds(), "seconds")
}

// Inward Facing Functions


// Print the ASCII art
func printAsciiArt() {
	asciiArt := `
  ___ ___               .__    _________                       __                 
 /   |   \_____    _____|  |__ \_   ___ \____________    ____ |  | __ ___________ 
/    ~    \__  \  /  ___/  |  \/    \  \/\_  __ \__  \ _/ ___\|  |/ // __ \_  __ \
\    Y    // __ \_\___ \|   Y  \     \____|  | \// __ \\  \___|    <\  ___/|  | \/
 \___|_  /(____  /____  >___|  /\______  /|__|  (____  /\___  >__|_ \\___  >__|   
       \/      \/     \/     \/        \/            \/     \/     \/    \/       
`
	fmt.Println(asciiArt, "\n\n")
}


//Parses our Command Line Arguments
func parseCommandLine() (string, string, string, string) {
	var wordlist string
	var hashlist string
	var salt string
	var hash string

	flag.StringVar(&wordlist, "w", "", "specify a wordlist")
	flag.StringVar(&hashlist, "t", "", "specify a list of hashes")
	flag.StringVar(&salt, "s", "", "specify a salt")
	flag.StringVar(&hash, "hash", "", "specify a hash")
	flag.Parse()


	if wordlist == "" {
		wordlist = "rockyou.txt"
	}

	if hashlist == "" && hash != "" {
		return wordlist, salt, hash, hashlist

	} else if hashlist != "" && hash == "" {
		return wordlist, salt, hash, hashlist

	} else {
		fmt.Println("Usage: go run Cracker.go -t <hashlist.txt> -w <wordlist> -s <salt> -hash <hash>")
		fmt.Println("Must provide a hashlist or a hash to crack.")
		os.Exit(1)
	}

	return wordlist, salt, hash, hashlist
}

//Will determine if there is a file of hashes or just a single hash passed in
func determineIfHashfile(hashlist string, wordlist string, salt string, hash string) {
	if hashlist != "" {
		file, err := os.Open(hashlist)
		if err != nil {
			println("Error opening hashlist:", err)
			os.Exit(1)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			hash := scanner.Text()
			encryptionScheme, salt, hash := determineIfSalted(hash)
			encryptionScheme = detectionOfEncryptionScheme(encryptionScheme)

			if encryptionScheme == "error" {
				println("Error: Hash is not supported by this program - ", hash)
			}else{
				println("Cracking hash:", hash)
				findMatchingHash(hash, wordlist, salt, encryptionScheme)
			}
		}

		if err := scanner.Err(); err != nil {
			println("Error reading hashlist:", err)
			os.Exit(1)
		}

	} else if hash != "" {
		println("Cracking hash:", hash)
		encryptionScheme, salt, hash := determineIfSalted(hash)
		encryptionScheme = detectionOfEncryptionScheme(encryptionScheme)
		findMatchingHash(hash, wordlist, salt, encryptionScheme)
	}
}

func determineIfSalted(hash string) (string, string, string) {
	if strings.Index(hash, "$") != -1 {
		if strings.Split(hash, "$")[1] == "y" {
			return strings.Split(hash, "$")[1], strings.Split(hash, "$")[3], strings.Split((strings.Split(hash, "$")[4]), ":")[0]
		}
		return strings.Split(hash, "$")[1], strings.Split(hash, "$")[2], strings.Split((strings.Split(hash, "$")[3]), ":")[0]
	} else {
		return "", "", hash
	}
}



//Our high level function that will iterate through our wordlist and check if the hash matches then will iterate through all possible combinations
func findMatchingHash(hash string, wordlistPath string, salt string, encryptionScheme string) {

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

	for _, word := range words {
		if calculateWordHash(hashLen, word, salt, encryptionScheme) == hash {
			println("Hash cracked! The original word is:", word, "\n")
			return
		}
	}

	println("No match found in the wordlist. Trying all possible combinations...")

	// If no match is found, let's iterate over all possible combinations of characters
	shouldReturn := iteratingOverAllCombinations(hashLen, hash, salt, encryptionScheme)
	if shouldReturn {
		return
	}
	
	// If no match is found, print a message
	println("Unable to crack the hash.")
}


// Calculate the hash of a given word,
// the hash function to be used is based on the length of the hash
func calculateWordHash(hashLen int, word string, salt string, encryptionScheme string) string {
	var hashedWord string

	
	if salt != "" {
		word = salt + word
	}
	
	if encryptionScheme != "" {
		hashedWord = hashWord(word, encryptionScheme, salt)
		return hashedWord
	}

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

func detectionOfEncryptionScheme(encryptionScheme string) string {
	if encryptionScheme == "1" {
		return "md5"
	}
	if encryptionScheme == "2a" || encryptionScheme == "2y" || encryptionScheme == "2b" {
		return "error"
	}
	if encryptionScheme == "5" {
		return "sha256"
	}
	if encryptionScheme == "6" {
		return "sha512"
	}
	if encryptionScheme == "y"{
		return "error"
	}
	return ""

}

// Calculate the hash of a given word
func hashWord(word string, encryptionScheme string, salt string) string {
	var hashedWord string

	switch encryptionScheme {
	case "md5":
		hashedWord = fmt.Sprintf("%x", md5.Sum([]byte(word)))
	case "sha256":
		hashedWord = fmt.Sprintf("%x", sha256.Sum256([]byte(word)))
	case "sha512":
		hashedWord = fmt.Sprintf("%x", sha512.Sum512([]byte(word)))
	}
	return hashedWord
}

// Iterates over all possible combinations of characters
func iteratingOverAllCombinations(hashLen int, hash string, salt string, encyrptionScheme string) bool {

	maxLength := 10

	for length := 1; length <= maxLength; length++ {
		for _, character := range generateCombinations(characters, length) {
			hashedGuess := calculateWordHash(hashLen, character, salt, encyrptionScheme)

			if hash == hashedGuess {
				println("Hash cracked! The original word is:", character + "\n")
				return true
			}
		}
	}
	return false
}

// Generate all possible combinations of characters
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


// Divide a slice of strings into n parts used for parallel processing of a wordlist
func divideIntoParts(words []string, n int) [][]string {
    var divided [][]string

    size := len(words) / n
    for i := 0; i < n; i++ {
        start := i * size
        end := start + size

        // For the last slice, append the remainder elements
        if i == n-1 {
            end = len(words)
        }

        divided = append(divided, words[start:end])
    }

    return divided
}