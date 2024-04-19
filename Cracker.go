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
	"os/signal"
	"syscall"
	"sync"
)

var (
	threadInfo0  string
	threadInfo1  string
	threadInfo2  string
	threadInfo3  string
	threadInfo4  string
	threadInfo5  string
	threadInfo6  string
	threadInfo7  string
	threadInfo8  string
	threadInfo9  string
	threadInfo10 string
	threadInfo11 string
	threadInfo12 string
	threadInfo13 string
	threadInfo14 string
	threadInfo15 string
	threadInfo16 string
	threadInfo17 string
	threadInfo18 string
	threadInfo19 string
	threadInfo20 string
	threadInfo21 string
	threadInfo22 string
	threadInfo23 string
	threadInfo24 string
	threadInfo25 string
	threadInfo26 string
	threadInfo27 string
	threadInfo28 string
	threadInfo29 string
	threadInfo30 string
	threadInfo31 string
	threadInfo32 string
	threadInfo33 string
	threadInfo34 string
	threadInfo35 string
	threadInfo36 string
	threadInfo37 string
	threadInfo38 string
	threadInfo39 string
	threadInfo40 string
	threadInfo41 string
	threadInfo42 string
	threadInfo43 string
	threadInfo44 string
	threadInfo45 string
	threadInfo46 string
	threadInfo47 string
	threadInfo48 string
	threadInfo49 string
	threadInfo50 string
	threadInfo51 string
	threadInfo52 string
	threadInfo53 string
	threadInfo54 string
	threadInfo55 string
	threadInfo56 string
	threadInfo57 string
	threadInfo58 string
	threadInfo59 string
	threadInfo60 string
	threadInfo61 string
	threadInfo62 string
	threadInfo63 string
	threadInfo64 string
	threadInfo65 string
	threadInfo66 string
	threadInfo67 string
	threadInfo68 string
	threadInfo69 string
	threadInfo70 string
	threadInfo71 string
	threadInfo72 string
	threadInfo73 string
	threadInfo74 string
	threadInfo75 string
	threadInfo76 string
	threadInfo77 string
	threadInfo78 string
	threadInfo79 string
	threadInfo80 string
	threadInfo81 string
	threadInfo82 string
	threadInfo83 string
	threadInfo84 string
	threadInfo85 string
	threadInfo86 string
	threadInfo87 string
	threadInfo88 string
	threadInfo89 string
	threadInfo90 string
	threadInfo91 string
	threadInfo92 string
	threadInfo93 string
	threadInfo94 string
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

	printAsciiArt()
	// Parse command-line arguments
	// Check if required arguments are provided
	wordlist, salt, hash, hashlist, benchmarking := parseCommandLine()

	start := time.Now()
	// Determine if the hash is a file or a single hash
 	determineIfHashfile(hashlist, wordlist, salt, hash, "", benchmarking)

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
func parseCommandLine() (string, string, string, string, bool) {
	var wordlist string
	var hashlist string
	var salt string
	var hash string

	flag.StringVar(&wordlist, "w", "", "specify a wordlist")
	flag.StringVar(&hashlist, "t", "", "specify a list of hashes")
	flag.StringVar(&salt, "s", "", "specify a salt")
	flag.StringVar(&hash, "hash", "", "specify a hash")
	benchmarking := flag.Bool("b", false, "specify if you want benchmarking")
	flag.Parse()

	if wordlist == "" {
		wordlist = "rockyou.txt"
	}

	if hashlist == "" && hash != "" {
		return wordlist, salt, hash, hashlist, *benchmarking

	} else if hashlist != "" && hash == "" {
		return wordlist, salt, hash, hashlist, *benchmarking

	} else {
		fmt.Println("Usage: go run Cracker.go -t <hashlist.txt> -w <wordlist> -s <salt> -hash <hash>")
		fmt.Println("Must provide a hashlist or a hash to crack.")
		os.Exit(1)
	}

	return wordlist, salt, hash, hashlist, *benchmarking
}

// Will determine if there is a file of hashes or just a single hash passed in
func determineIfHashfile(hashlist string, wordlist string, salt string, hash string, resumingAtWord string, benchmarking bool) {

	if hashlist != "" {
		listOfHashes(hashlist, wordlist, benchmarking)

	} else if hash != "" {
		encryptionScheme, salt, hash := determineIfSalted(hash, salt)
		encryptionScheme = detectionOfEncryptionScheme(encryptionScheme)
		schemeChecking(encryptionScheme, hash)
		findMatchingHash(hash, wordlist, salt, encryptionScheme, benchmarking)
	}
}

// If there is a list of hashes this is the approach it takes to cracking them
func listOfHashes(hashlist string, wordlist string, benchmarking bool) {
	file, err := os.Open(hashlist)
	if err != nil {
		println("Error Opening File:", hashlist)
		os.Exit(1)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		hash := scanner.Text()
		encryptionScheme, salt, hash := determineIfSalted(hash, "")
		encryptionScheme = detectionOfEncryptionScheme(encryptionScheme)
		schemeChecking(encryptionScheme, hash)
		findMatchingHash(hash, wordlist, salt, encryptionScheme, benchmarking)
	}

	if err := scanner.Err(); err != nil {
		println("Error Reading hashlist:", err)
		os.Exit(1)
	}
}

// Will check if the encryption scheme is supported by the program
func schemeChecking(encryptionScheme string, hash string) {
	if encryptionScheme == "error" {
		println("Error: Hash is not supported by this program - ", hash)
	} else {
		println("Cracking hash:", hash)
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

// Our high level function that will iterate through our wordlist and check if the hash matches then will iterate through all possible combinations
func findMatchingHash(hash string, wordlistPath string, salt string, encryptionScheme string, benchmarking bool) {
	hashLen := len(hash)

	// Create channel to signal the hash is found in the wordlist
	hashFound := make(chan bool)

	// Iterate all words in the wordlist to find the hashed word
	cracked := iteratingWordList(wordlistPath, hash, salt, encryptionScheme, hashFound)

	if cracked {
		return
	}

	println("No match found in the wordlist. Trying all possible combinations...\n")


	iterateUsingCharacters(benchmarking, hash, hashLen, salt, encryptionScheme)	
}

func iterateUsingCharacters(benchmarking bool, hash string, hashLen int, salt string, encryptionScheme string) {
	stop := make(chan bool)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	isDirectory := false
	if benchmarking == true {
		if _, err := os.Stat("benchmarking/" + hash); os.IsNotExist(err) {
			isDirectory = false
			os.Mkdir("benchmarking/"+hash, 0777)
		} else {
			isDirectory = true
		}
	}

	shouldReturn := iterateOverCharacters(isDirectory, stop, hash, hashLen, salt, encryptionScheme, benchmarking)
	if shouldReturn {
		return 
	}

	go func() {
		timeTracker(stop)
	}()

	select {
	case <-sig:
		fmt.Println("\n\nReceived termination signal. Quitting...")
		if benchmarking == true {
			writeToFileForAllThreads(hash)
		}
		close(stop)

	case <-stop:
		writeToFileForAllThreads(hash)
	}

	return
}

func iterateOverCharacters(isDirectory bool, stop chan bool, hash string, hashLen int, salt string, encryptionScheme string, benchmarking bool) bool {
	if isDirectory {
		for i := 0; i < len(characters); i++ {
			go func(i int) {
				select {
				case <-stop:
					return 
				default:
					startingCharacters := readInGuess(hash, string(characters[i]))
					if startingCharacters == "" {
						iteratingOverAllCombinations(hashLen, hash, salt, encryptionScheme, string(characters[i]), stop, benchmarking, i, false)
					} else {
						restartBenchmarkForHashes(hash, hashLen, salt, encryptionScheme, startingCharacters, stop, benchmarking, i)
					}
				}
			}(i)
		}
	} else {
		for i := 0; i < len(characters); i++ {
			go func(i int) {
				select {
				case <-stop:
					return 
				default:
					iteratingOverAllCombinations(hashLen, hash, salt, encryptionScheme, string(characters[i]), stop, benchmarking, i, false)
				}
			}(i)
		}
	}
	return false
}


func restartBenchmarkForHashes(hash string, hashLen int, salt string, encryptionScheme string, startingCharacters string, stop chan bool, benchmarking bool, threadID int) {
    
    storeGuessInThreadInfo(threadID, startingCharacters)
    for length := len(startingCharacters); length <= 10; length++ {
        select {
        case <-stop:
            return // Quit signal received, terminate goroutine
        default:
            permutations := generatePermutationsWithFixedFirstLetter(startingCharacters)
            for guess := range permutations {
                hashedGuess := calculateWordHash(hashLen, guess, salt, encryptionScheme)

                if hash == hashedGuess {
                    fmt.Println("\n\nHash cracked! The original word is:", guess)
					writeToFile("answer", hash, guess)
                    close(stop) // Signal other goroutines to stop
                    return      // Terminate goroutine if hash is cracked
                }
                storeGuessInThreadInfo(threadID, guess)
            }
            startingCharacters = string(startingCharacters[0]) + strings.Repeat("a", len(startingCharacters))
        }
    }
}

func generatePermutationsWithFixedFirstLetter(input string) <-chan string {
    firstLetter := string(input[0])
    remaining := input[1:]

    result := make(chan string)
    go func() {
        generatePermutationsHelper(remaining, firstLetter, result)
        close(result)
    }()

    return result
}

func generatePermutationsHelper(input string, current string, result chan<- string) {
    if len(input) == 0 {
        result <- current
        return
    }

    char := input[0]
    remaining := input[1:]

    index := strings.Index(characters, string(char))
    if index == -1 {
        return
    }

    for i := index; i < len(characters); i++ {
        generatePermutationsHelper(remaining, current+string(characters[i]), result)
    }
}


func writeToFile(startingCharacter string, hash string, guess string) {

	if startingCharacter != "answer" {
		startingCharacter = "0x" + fmt.Sprintf("%x", startingCharacter)
		err := os.WriteFile("benchmarking/" + hash +"/benchmarkFor" + startingCharacter + ".txt", []byte(guess), 0644)
		if err != nil {
			println("Error writing to file: ", err)
			os.Exit(1)
		}
	} else {
		err := os.WriteFile("benchmarking/" + hash +"/" + startingCharacter + ".txt", []byte(guess), 0644)
		if err != nil {
			println("Error writing to file: ", err)
			os.Exit(1)
		}
	}

	
}

func checkForInvalidFileLetters(startingCharacter string) bool {
	if startingCharacter == "/" || startingCharacter == ":" || startingCharacter == "*" || startingCharacter == "?" || startingCharacter == "\"" || startingCharacter == "<" || startingCharacter == ">" || startingCharacter == "|" || startingCharacter == "\\" || startingCharacter == " " {
		return true
	}
	return false

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
func iteratingOverAllCombinations(hashLen int, hash string, salt string, encryptionScheme string, startingCharacter string, stop chan bool, benchmarking bool, threadID int, isRestart bool) {

    maxLength := 10
    initialLength := 1
    
    for length := initialLength; length <= maxLength; length++ {
        select {
        case <-stop:
            return // Quit signal received, terminate goroutine
        default:
            for guess := range generateCombinations(characters, length, startingCharacter) {
                hashedGuess := calculateWordHash(hashLen, guess, salt, encryptionScheme)

                if benchmarking == true {
                    storeGuessInThreadInfo(threadID, guess)
                }

                if hash == hashedGuess {
                    fmt.Println("\n\nHash cracked! The original word is:", guess)
                    close(stop) // Signal other goroutines to stop
					writeToFile("answer", hash, guess)
                    return      // Terminate goroutine if hash is cracked
                }
            }
        }
    }
}

func readInGuess(hash string, startingCharacter string) string {
	startingCharacter = "0x" + fmt.Sprintf("%x", startingCharacter)

	file, err := os.Open("benchmarking/" + hash + "/benchmarkFor" + startingCharacter + ".txt")
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	scanner.Scan()
	return scanner.Text()
}

func generateCombinations(characters string, length int, startingCharacter string) <-chan string {
    result := make(chan string)
    go func() {
        defer close(result)
        generateCombinationsHelper(characters, length, startingCharacter, result)
    }()
    return result
}

func generateCombinationsHelper(characters string, length int, current string, result chan<- string) {
    if length == 0 {
        result <- current
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

func findHashInParts(words []string, wg *sync.WaitGroup, hashFound chan bool, hash string, salt string, encryptionScheme string) {
    defer wg.Done()
    for _, word := range words {
        select {
        case <-hashFound:
            return // Stop goroutine
        default:
            hashedWord := calculateWordHash(len(hash), word, salt, encryptionScheme)
            if hashedWord == hash {
                println("\n\nHash cracked! The original word is:", word, "\n")
                hashFound <- true
				os.Exit(0) //If we don't exit here program crashes
            }
        }
    }
}

func iteratingWordList(wordlistPath string, hash string, salt string, encryptionScheme string, hashFound chan bool) bool {
    // Read the wordlist file
    wordlistBytes, err := ioutil.ReadFile(wordlistPath)
    if err != nil {
        println("Error reading wordlist:", err)
        return false
    }

    // Convert the wordlist to a string array
    wordlist := string(wordlistBytes)
    allWords := strings.Split(wordlist, "\n")

    var wg sync.WaitGroup
    numOfParts := 20
    wordsArray := divideIntoParts(allWords, numOfParts)


    // Start goroutines
    for _, words := range wordsArray {
        wg.Add(1)
        go findHashInParts(words, &wg, hashFound, hash, salt, encryptionScheme)
    }

    // Wait for all goroutines to finish or stop signal
   	wg.Wait()
	
	close(hashFound)
	return false
}






// This is where the maddeny of how to efficeintly implment benchmarking with threads comes in


func storeGuessInThreadInfo(threadID int, guess string) {
	switch threadID {
	case 0:
		threadInfo0 = guess
	case 1:
		threadInfo1 = guess
	case 2:
		threadInfo2 = guess
	case 3:
		threadInfo3 = guess
	case 4:
		threadInfo4 = guess
	case 5:
		threadInfo5 = guess
	case 6:
		threadInfo6 = guess
	case 7:
		threadInfo7 = guess
	case 8:
		threadInfo8 = guess
	case 9:
		threadInfo9 = guess
	case 10:
		threadInfo10 = guess
	case 11:
		threadInfo11 = guess
	case 12:
		threadInfo12 = guess
	case 13:
		threadInfo13 = guess
	case 14:
		threadInfo14 = guess
	case 15:
		threadInfo15 = guess
	case 16:
		threadInfo16 = guess
	case 17:
		threadInfo17 = guess
	case 18:
		threadInfo18 = guess
	case 19:
		threadInfo19 = guess
	case 20:
		threadInfo20 = guess
	case 21:
		threadInfo21 = guess
	case 22:
		threadInfo22 = guess
	case 23:
		threadInfo23 = guess
	case 24:
		threadInfo24 = guess
	case 25:
		threadInfo25 = guess
	case 26:
		threadInfo26 = guess
	case 27:
		threadInfo27 = guess
	case 28:
		threadInfo28 = guess
	case 29:
		threadInfo29 = guess
	case 30:
		threadInfo30 = guess
	case 31:
		threadInfo31 = guess
	case 32:
		threadInfo32 = guess
	case 33:
		threadInfo33 = guess
	case 34:
		threadInfo34 = guess
	case 35:
		threadInfo35 = guess
	case 36:
		threadInfo36 = guess
	case 37:
		threadInfo37 = guess
	case 38:
		threadInfo38 = guess
	case 39:
		threadInfo39 = guess
	case 40:
		threadInfo40 = guess
	case 41:
		threadInfo41 = guess
	case 42:
		threadInfo42 = guess
	case 43:
		threadInfo43 = guess
	case 44:
		threadInfo44 = guess
	case 45:
		threadInfo45 = guess
	case 46:
		threadInfo46 = guess
	case 47:
		threadInfo47 = guess
	case 48:
		threadInfo48 = guess
	case 49:
		threadInfo49 = guess
	case 50:
		threadInfo50 = guess
	case 51:
		threadInfo51 = guess
	case 52:
		threadInfo52 = guess
	case 53:
		threadInfo53 = guess
	case 54:
		threadInfo54 = guess
	case 55:
		threadInfo55 = guess
	case 56:
		threadInfo56 = guess
	case 57:
		threadInfo57 = guess
	case 58:
		threadInfo58 = guess
	case 59:
		threadInfo59 = guess
	case 60:
		threadInfo60 = guess
	case 61:
		threadInfo61 = guess
	case 62:
		threadInfo62 = guess
	case 63:
		threadInfo63 = guess
	case 64:
		threadInfo64 = guess
	case 65:
		threadInfo65 = guess
	case 66:
		threadInfo66 = guess
	case 67:
		threadInfo67 = guess
	case 68:
		threadInfo68 = guess
	case 69:
		threadInfo69 = guess
	case 70:
		threadInfo70 = guess
	case 71:
		threadInfo71 = guess
	case 72:
		threadInfo72 = guess
	case 73:
		threadInfo73 = guess
	case 74:
		threadInfo74 = guess
	case 75:
		threadInfo75 = guess
	case 76:
		threadInfo76 = guess
	case 77:
		threadInfo77 = guess
	case 78:
		threadInfo78 = guess
	case 79:
		threadInfo79 = guess
	case 80:
		threadInfo80 = guess
	case 81:
		threadInfo81 = guess
	case 82:
		threadInfo82 = guess
	case 83:
		threadInfo83 = guess
	case 84:
		threadInfo84 = guess
	case 85:
		threadInfo85 = guess
	case 86:
		threadInfo86 = guess
	case 87:
		threadInfo87 = guess
	case 88:
		threadInfo88 = guess
	case 89:
		threadInfo89 = guess
	case 90:
		threadInfo90 = guess
	case 91:
		threadInfo91 = guess
	case 92:
		threadInfo92 = guess
	case 93:
		threadInfo93 = guess
	case 94:
		threadInfo94 = guess
	default:
		fmt.Println("Invalid thread ID:", threadID)
	}
}










func writeToFileForAllThreads(hash string) {
	var characters = []string{
		"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
		"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
		"0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
		" ", "!", "\"", "#", "$", "%", "&", "'", "(", ")", "*", "+", ",", "-", ".", "/", ":", ";", "<", "=", ">", "?", "@",
		"[", "\\", "]", "^", "_", "`", "{", "|", "}", "~",
	}

	writeToFile(characters[0], hash, threadInfo0)
	writeToFile(characters[1], hash, threadInfo1)
	writeToFile(characters[2], hash, threadInfo2)
	writeToFile(characters[3], hash, threadInfo3)
	writeToFile(characters[4], hash, threadInfo4)
	writeToFile(characters[5], hash, threadInfo5)
	writeToFile(characters[6], hash, threadInfo6)
	writeToFile(characters[7], hash, threadInfo7)
	writeToFile(characters[8], hash, threadInfo8)
	writeToFile(characters[9], hash, threadInfo9)
	writeToFile(characters[10], hash, threadInfo10)
	writeToFile(characters[11], hash, threadInfo11)
	writeToFile(characters[12], hash, threadInfo12)
	writeToFile(characters[13], hash, threadInfo13)
	writeToFile(characters[14], hash, threadInfo14)
	writeToFile(characters[15], hash, threadInfo15)
	writeToFile(characters[16], hash, threadInfo16)
	writeToFile(characters[17], hash, threadInfo17)
	writeToFile(characters[18], hash, threadInfo18)
	writeToFile(characters[19], hash, threadInfo19)
	writeToFile(characters[20], hash, threadInfo20)
	writeToFile(characters[21], hash, threadInfo21)
	writeToFile(characters[22], hash, threadInfo22)
	writeToFile(characters[23], hash, threadInfo23)
	writeToFile(characters[24], hash, threadInfo24)
	writeToFile(characters[25], hash, threadInfo25)
	writeToFile(characters[26], hash, threadInfo26)
	writeToFile(characters[27], hash, threadInfo27)
	writeToFile(characters[28], hash, threadInfo28)
	writeToFile(characters[29], hash, threadInfo29)
	writeToFile(characters[30], hash, threadInfo30)
	writeToFile(characters[31], hash, threadInfo31)
	writeToFile(characters[32], hash, threadInfo32)
	writeToFile(characters[33], hash, threadInfo33)
	writeToFile(characters[34], hash, threadInfo34)
	writeToFile(characters[35], hash, threadInfo35)
	writeToFile(characters[36], hash, threadInfo36)
	writeToFile(characters[37], hash, threadInfo37)
	writeToFile(characters[38], hash, threadInfo38)
	writeToFile(characters[39], hash, threadInfo39)
	writeToFile(characters[40], hash, threadInfo40)
	writeToFile(characters[41], hash, threadInfo41)
	writeToFile(characters[42], hash, threadInfo42)
	writeToFile(characters[43], hash, threadInfo43)
	writeToFile(characters[44], hash, threadInfo44)
	writeToFile(characters[45], hash, threadInfo45)
	writeToFile(characters[46], hash, threadInfo46)
	writeToFile(characters[47], hash, threadInfo47)
	writeToFile(characters[48], hash, threadInfo48)
	writeToFile(characters[49], hash, threadInfo49)
	writeToFile(characters[50], hash, threadInfo50)
	writeToFile(characters[51], hash, threadInfo51)
	writeToFile(characters[52], hash, threadInfo52)
	writeToFile(characters[53], hash, threadInfo53)
	writeToFile(characters[54], hash, threadInfo54)
	writeToFile(characters[55], hash, threadInfo55)
	writeToFile(characters[56], hash, threadInfo56)
	writeToFile(characters[57], hash, threadInfo57)
	writeToFile(characters[58], hash, threadInfo58)
	writeToFile(characters[59], hash, threadInfo59)
	writeToFile(characters[60], hash, threadInfo60)
	writeToFile(characters[61], hash, threadInfo61)
	writeToFile(characters[62], hash, threadInfo62)
	writeToFile(characters[63], hash, threadInfo63)
	writeToFile(characters[64], hash, threadInfo64)
	writeToFile(characters[65], hash, threadInfo65)
	writeToFile(characters[66], hash, threadInfo66)
	writeToFile(characters[67], hash, threadInfo67)
	writeToFile(characters[68], hash, threadInfo68)
	writeToFile(characters[69], hash, threadInfo69)
	writeToFile(characters[70], hash, threadInfo70)
	writeToFile(characters[71], hash, threadInfo71)
	writeToFile(characters[72], hash, threadInfo72)
	writeToFile(characters[73], hash, threadInfo73)
	writeToFile(characters[74], hash, threadInfo74)
	writeToFile(characters[75], hash, threadInfo75)
	writeToFile(characters[76], hash, threadInfo76)
	writeToFile(characters[77], hash, threadInfo77)
	writeToFile(characters[78], hash, threadInfo78)
	writeToFile(characters[79], hash, threadInfo79)
	writeToFile(characters[80], hash, threadInfo80)
	writeToFile(characters[81], hash, threadInfo81)
	writeToFile(characters[82], hash, threadInfo82)
	writeToFile(characters[83], hash, threadInfo83)
	writeToFile(characters[84], hash, threadInfo84)
	writeToFile(characters[85], hash, threadInfo85)
	writeToFile(characters[86], hash, threadInfo86)
	writeToFile(characters[87], hash, threadInfo87)
	writeToFile(characters[88], hash, threadInfo88)
	writeToFile(characters[89], hash, threadInfo89)
	writeToFile(characters[90], hash, threadInfo90)
	writeToFile(characters[91], hash, threadInfo91)
	writeToFile(characters[92], hash, threadInfo92)
	writeToFile(characters[93], hash, threadInfo93)
	writeToFile(characters[94], hash, threadInfo94)
}
