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

func main() {

	printAsciiArt()
	// Parse command-line arguments
	// Check if required arguments are provided
	wordlist, salt, hash, hashlist := parseCommandLine()

	start := time.Now()
	determineIfHashfile(hashlist, wordlist, salt, hash)
	
	duration := time.Since(start)
	println("Time elapsed: ", duration)
}

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
			if strings.Index(hash, "$") != -1 {
				salt = strings.Split(hash, "$")[1]
			}
			findMatchingHash(hash, wordlist, salt)
		}

if err := scanner.Err(); err != nil {
    println("Error reading hashlist:", err)
    os.Exit(1)
}

	} else if hash != "" {
		println("Cracking hash:", hash)
		findMatchingHash(hash, wordlist, salt)
	}
}

func printAsciiArt() {
	asciiArt := `
  ___ ___               .__    _________                       __                 
 /   |   \_____    _____|  |__ \_   ___ \____________    ____ |  | __ ___________ 
/    ~    \__  \  /  ___/  |  \/    \  \/\_  __ \__  \ _/ ___\|  |/ // __ \_  __ \
\    Y    // __ \_\___ \|   Y  \     \____|  | \// __ \\  \___|    <\  ___/|  | \/
 \___|_  /(____  /____  >___|  /\______  /|__|  (____  /\___  >__|_ \\___  >__|   
       \/      \/     \/     \/        \/            \/     \/     \/    \/       
`
	fmt.Println(asciiArt)
}

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


func findMatchingHash(hash string, wordlistPath string, salt string) {

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
		if calculateWordHash(hashLen, word, salt) == hash {
			println("Hash cracked! The original word is:", word)
			return
		}
	}

	println("No match found in the wordlist. Trying all possible combinations...")
	// If no match is found, let's iterate over all possible combinations of characters
	shouldReturn := iteratingOverAllCombinations(hashLen, hash, salt)
	if shouldReturn {
		return
	}
	
	// If no match is found, print a message
	println("Unable to crack the hash.")
}


// Calculate the hash of a given word,
// the hash function to be used is based on the length of the hash
func calculateWordHash(hashLen int, word string, salt string) string {
	var hashedWord string

	if salt != "" {
		word = salt + word
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


func iteratingOverAllCombinations(hashLen int, hash string, salt string) bool {

	maxLength := 10

	for length := 1; length <= maxLength; length++ {
		for _, character := range generateCombinations(characters, length) {
			hashedGuess := calculateWordHash(hashLen, character, salt)

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