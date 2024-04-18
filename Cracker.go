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
	// "sync"
	// "syscall"
	// "os/signal"
)

const SHA256_LEN = 64
const MD5_LEN = 32
const SHA1_LEN = 40
const SHA512_LEN = 128
const SHA384_LEN = 96
const SHA224_LEN = 56

const characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

//Outward facing function
func main() {

	printAsciiArt()
	// Parse command-line arguments
	// Check if required arguments are provided
	wordlist, salt, hash, hashlist := parseCommandLine()

	start := time.Now()
	// Determine if the hash is a file or a single hash
 	determineIfHashfile(hashlist, wordlist, salt, hash, "")

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
func determineIfHashfile(hashlist string, wordlist string, salt string, hash string, resumingAtWord string) {

	wordToResumeAt := seeIfResuming(hashlist, wordlist, salt, hash)


	if hashlist != "" {
		listOfHashes(hashlist, wordlist, wordToResumeAt)

	} else if hash != "" {
		encryptionScheme, salt, hash := determineIfSalted(hash, salt)
		encryptionScheme = detectionOfEncryptionScheme(encryptionScheme)
		schemeChecking(encryptionScheme, hash)
		findMatchingHash(hash, wordlist, salt, encryptionScheme, wordToResumeAt)
	}
}


func seeIfResuming(hashlist string, wordlist string, salt string, hash string) string {
	file, err := os.Open("benchmark.txt")
	if err != nil {
		println("Error opening File:", hashlist)
		os.Exit(1)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	scanner.Scan()
	if scanner.Text() == hash {
		scanner.Scan()
		resumingAtWord := scanner.Text()
		resumingAtWord = strings.TrimPrefix(resumingAtWord, "\x00")
		//println("We see that you recently have been running a hashcrack on this hash, here is the last guess we will start from: ", resumingAtWord, "\n\n")
		return resumingAtWord
	}
	return ""

}

//If there is a list of hashes this is the approach it takes to cracking them
func listOfHashes(hashlist string, wordlist string, wordToResumeAt string) {
	file, err := os.Open(hashlist)
	if err != nil {
		println("Error opening File:", hashlist)
		os.Exit(1)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		hash := scanner.Text()
		encryptionScheme, salt, hash := determineIfSalted(hash, "")
		encryptionScheme = detectionOfEncryptionScheme(encryptionScheme)
		schemeChecking(encryptionScheme, hash)
		findMatchingHash(hash, wordlist, salt, encryptionScheme, wordToResumeAt)
	}

	if err := scanner.Err(); err != nil {
		println("Error reading hashlist:", err)
		os.Exit(1)
	}
}


//Will check if the encryption scheme is supported by the program
func schemeChecking(encryptionScheme string, hash string) {
	if encryptionScheme == "error" {
		println("Error: Hash is not supported by this program - ", hash)
	} else {
		println("Cracking hash:", hash)
	}
}


//Will determine the encryption scheme of the hash if it is a shadow file
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

//Will determine if the hash is salted or not
func determineIfSalted(hash string, salt string) (string, string, string) {
	if strings.Index(hash, "$") != -1 {
		if strings.Split(hash, "$")[1] == "y" {
			return strings.Split(hash, "$")[1], strings.Split(hash, "$")[3], strings.Split((strings.Split(hash, "$")[4]), ":")[0]
		}
		return strings.Split(hash, "$")[1], strings.Split(hash, "$")[2], strings.Split((strings.Split(hash, "$")[3]), ":")[0]
	} else {
		return "", salt, hash
	}
}



//Our high level function that will iterate through our wordlist and check if the hash matches then will iterate through all possible combinations
func findMatchingHash(hash string, wordlistPath string, salt string, encryptionScheme string, wordToResumeAt string) {

	hashLen := len(hash)

	// Create channel to signal the hash is found in the wordlist
	hashFound := make(chan bool)

	// Iterate all words in the wordlist to find the hashed word
	iteratingWordList(wordlistPath, hash, salt, encryptionScheme, hashFound)

	if <-hashFound {
		return
	}

	println("No match found in the wordlist. Trying all possible combinations...\n")

	//Create a channel to signal to other go rotuines that the hash has been cracked
	stop := make(chan bool)

	for i := 0; i < len(characters); i++ {
		go func(i int) {
			select {
			case <-stop:
				return // Quit signal received, terminate goroutine
			default:
				iteratingOverAllCombinations(hashLen, hash, salt, encryptionScheme, string(characters[i]), stop)
			}
		}(i)
	}

	go func() {
		timeTracker(stop)
	}()

	// Wait for a signal from one of the goroutines
	<-stop
	
}

func timeTracker(quit chan bool) {
    ticker := time.NewTicker(1 * time.Second)
    defer ticker.Stop()

    startTime := time.Now()

    for {
        select {
        case <-ticker.C:
            elapsedTime := time.Since(startTime)
            fmt.Printf("\r\033[KTime Wasted Iterative Cracking: %s", elapsedTime)
        case <-quit:
            return
        }
    }
}

// Function to iterate over all possible combinations of characters
func iteratingOverAllCombinations(hashLen int, hash string, salt string, encryptionScheme string, startingCharacter string, stop chan bool) {
	maxLength := 10

	for length := 1; length <= maxLength; length++ {
		select {
		case <-stop:
			return // Quit signal received, terminate goroutine
		default:
			for _, character := range generateCombinations(characters, length, startingCharacter) {
				hashedGuess := calculateWordHash(hashLen, character, salt, encryptionScheme)

				if hash == hashedGuess {
					fmt.Println("\n\nHash cracked! The original word is:", character)
					close(stop)  // Signal other goroutines to stop
					return             // Terminate goroutine if hash is cracked
				}
			}
		}
	}
}

// Generate all possible combinations of characters
func generateCombinations(characters string, length int, startingCharacter string) []string {
	var result []string
	generateCombinationsHelper(characters, length, startingCharacter, &result)
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
	default:
		println("Unable to determine the hash function to be used.")
		os.Exit(1)
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

func findHashInParts(words []string, hashFound chan bool, hash string, salt string, encryptionScheme string) {
	for _, word := range words {
		hashedWord := calculateWordHash(len(hash), word, salt, encryptionScheme)
		if hashedWord == hash {
			println("\n\nHash cracked! The original word is:", word, "\n")
			hashFound <- true
			break
		}
	}
}

func iteratingWordList(wordlistPath string, hash string, salt string, encryptionScheme string, hashFound chan bool) {
	// Read the wordlist file
	wordlistBytes, err := ioutil.ReadFile(wordlistPath)
	if err != nil {
		println("Error reading wordlist:", err)
		return
	}

	// Convert the wordlist to a string array
	wordlist := string(wordlistBytes)
	allWords := strings.Split(wordlist, "\n")

	// divide the wordlist into parts and let go routines to 
	numOfParts := 20
	wordsArray := divideIntoParts(allWords, numOfParts)
	for _, words := range wordsArray {
		go findHashInParts(words, hashFound, hash, salt, encryptionScheme)
	}
}