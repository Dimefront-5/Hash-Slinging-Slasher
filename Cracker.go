package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"flag"
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
const SHA224_LEN = 56

const characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

// Outward facing function
func main() {
	// Prepare all combinations files
	// maxLength := 4
	// done := make(chan bool)
	// go generateAllSequences(maxLength, done)

	printAsciiArt()

	// Parse command-line arguments
	// Check if required arguments are provided
	wordlist, salt, hash, hashlist := parseCommandLine()

	start := time.Now()

	// Wait for creating the files
	// println("Preparing combinations files...")
	// <-done

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

// Parses our Command Line Arguments
func parseCommandLine() (string, string, string, string) {
	var wordlist string
	var hashlist string
	var salt string
	var hash string
	var maxLength int

	flag.StringVar(&wordlist, "w", "", "specify a wordlist")
	flag.StringVar(&hashlist, "t", "", "specify a list of hashes")
	flag.StringVar(&salt, "s", "", "specify a salt")
	flag.StringVar(&hash, "hash", "", "specify a hash")
	flag.IntVar(&maxLength, "maxLen", 0, "specify the max length of message")
	flag.Parse()

	if wordlist == "" {
		wordlist = "rockyou.txt"
	}

	if maxLength != 0 {
		generateAllSequences(maxLength)
		println("Generating all character sequences...")
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

// Will determine if there is a file of hashes or just a single hash passed in
func determineIfHashfile(hashlist string, wordlist string, salt string, hash string) {
	if hashlist != "" {
		listOfHashes(hashlist, wordlist)

	} else if hash != "" {
		encryptionScheme, salt, hash := determineIfSalted(hash)
		encryptionScheme = detectionOfEncryptionScheme(encryptionScheme)
		schemeChecking(encryptionScheme, hash, wordlist, salt)
	}
}

// If there is a list of hashes this is the approach it takes to cracking them
func listOfHashes(hashlist string, wordlist string) {
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
		schemeChecking(encryptionScheme, hash, wordlist, salt)
	}

	if err := scanner.Err(); err != nil {
		println("Error reading hashlist:", err)
		os.Exit(1)
	}
}

// Will check if the encryption scheme is supported by the program
func schemeChecking(encryptionScheme string, hash string, wordlist string, salt string) {
	if encryptionScheme == "error" {
		println("Error: Hash is not supported by this program - ", hash)
	} else {
		println("Cracking hash:", hash)
		findMatchingHash(hash, wordlist, salt, encryptionScheme)
	}
}

// Will determine the encryption scheme of the hash if it is a shadow file
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
	if encryptionScheme == "y" {
		return "error"
	}
	return ""

}

// Will determine if the hash is salted or not
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

// Our high level function that will iterate through our wordlist and check if the hash matches then will iterate through all possible combinations
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
		hashedWord := calculateWordHash(hashLen, word, salt, encryptionScheme)
		if hashedWord == hash {
			println("Hash cracked! The original word is:", word, "\n")
			return
		}
	}

	println("No match found in the wordlist. Trying all possible combinations...\n")

	// If no match is found, let's iterate over all possible combinations of characters
	hashFound := make(chan bool)

	// Opt #1: Using pre-generated sequence in files
	// for i := range characters {
	// 	fileName := fmt.Sprintf("./sequences/%v.txt", i)
	// 	go readFileAndFindHash(hash, fileName, salt, encryptionScheme, hashFound)
	// }

	// Opt #2: Generate sequences now
	maxLength := 3
	allSequences := generateAllSequences(maxLength)
	for i := range characters {
		go findHashFromSecquence(hash, allSequences[i], salt, encryptionScheme, hashFound)
	}

	// shouldReturn := iteratingOverAllCombinations(hashLen, hash, salt, encryptionScheme)
	if <-hashFound {
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
	case SHA224_LEN:
		hashedWord = fmt.Sprintf("%x", sha256.Sum224([]byte(word)))
	}
	return hashedWord
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
	ticker := time.NewTicker(1 * time.Second) // Create a ticker that ticks every second
	defer ticker.Stop()                       // Stop the ticker when main function exits

	startTime := time.Now()

	maxLength := 10

	for length := 1; length <= maxLength; length++ {

		for _, character := range generateCombinations(characters, length) {
			select {
			case <-ticker.C: // Wait for the ticker to tick
				elapsedTime := time.Since(startTime)
				fmt.Printf("\r\033[KTime Wasted Iterative Cracking: %s", elapsedTime)
			}

			hashedGuess := calculateWordHash(hashLen, character, salt, encyrptionScheme)

			if hash == hashedGuess {
				println("Hash cracked! The original word is:", character+"\n")
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

// Generate all possible combinations of characters
// func generateAllSequences(maxLength int, done chan bool) {
func generateAllSequences(maxLength int) [95][]string {
// func generateAllSequences(maxLength int) {
	var allSequences [95][]string
	for i, char := range characters {
		var sequence []string
		generateSequence(string(char), maxLength, &sequence)
		// println("prefix: ", char)
		// println(sequence[1])
		// fileName := fmt.Sprintf("./sequences/%v.txt", i)
		// writeToFile(fileName, sequence)	// Opt #1
		allSequences[i] = sequence // Opt #2
	}
	return allSequences
}

func generateSequence(prefix string, length int, sequence *[]string) {
	*sequence = append(*sequence, prefix)
	// println(prefix)
	if len(prefix) < length {
		for _, char := range characters {
			generateSequence(prefix+string(char), length, sequence)
		}
	}
}

func writeToFile(fileName string, sequence []string) {
	file, err := os.Create(fileName)
	if err != nil {
		println("Error writing file:", err)
		os.Exit(1)
	}
	for _, str := range sequence {
		_, err := file.WriteString(str + "\n")
		if err != nil {
			println("Error writing content to file:", err)
			os.Exit(1)
		}
	}
	file.Close()
}

func readFileAndFindHash(hash string, fileName string, salt string, encryptionScheme string, hashFound chan bool) bool {
	// Read the file
	wordlistBytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		println("Error reading file:", err)
		return false
	}

	// Convert the wordlist to a string array
	wordlist := string(wordlistBytes)
	words := strings.Split(wordlist, "\n")

	hashLen := len(hash)

	for _, word := range words {
		hashedWord := calculateWordHash(hashLen, word, salt, encryptionScheme)
		if hashedWord == hash {
			println("Hash cracked! The original word is:", word, "\n")
			hashFound <- true
			return true
		}
	}
	return false
}

func findHashFromSecquence(hash string, sequence []string, salt string, encryptionScheme string, hashFound chan bool) bool {
	for _, word := range sequence {
		hashedWord := calculateWordHash(len(hash), word, salt, encryptionScheme)
		if hashedWord == hash {
			println("Hash cracked! The original word is:", word, "\n")
			hashFound <- true
			return true
		}
	}
	return false
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
