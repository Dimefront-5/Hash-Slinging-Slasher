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
	maxLength   *int
	noWordlist  *bool
	noIteration *bool

	lastGuessOfThread0  string
	lastGuessOfThread1  string
	lastGuessOfThread2  string
	lastGuessOfThread3  string
	lastGuessOfThread4  string
	lastGuessOfThread5  string
	lastGuessOfThread6  string
	lastGuessOfThread7  string
	lastGuessOfThread8  string
	lastGuessOfThread9  string
	lastGuessOfThread10 string
	lastGuessOfThread11 string
	lastGuessOfThread12 string
	lastGuessOfThread13 string
	lastGuessOfThread14 string
	lastGuessOfThread15 string
	lastGuessOfThread16 string
	lastGuessOfThread17 string
	lastGuessOfThread18 string
	lastGuessOfThread19 string
	lastGuessOfThread20 string
	lastGuessOfThread21 string
	lastGuessOfThread22 string
	lastGuessOfThread23 string
	lastGuessOfThread24 string
	lastGuessOfThread25 string
	lastGuessOfThread26 string
	lastGuessOfThread27 string
	lastGuessOfThread28 string
	lastGuessOfThread29 string
	lastGuessOfThread30 string
	lastGuessOfThread31 string
	lastGuessOfThread32 string
	lastGuessOfThread33 string
	lastGuessOfThread34 string
	lastGuessOfThread35 string
	lastGuessOfThread36 string
	lastGuessOfThread37 string
	lastGuessOfThread38 string
	lastGuessOfThread39 string
	lastGuessOfThread40 string
	lastGuessOfThread41 string
	lastGuessOfThread42 string
	lastGuessOfThread43 string
	lastGuessOfThread44 string
	lastGuessOfThread45 string
	lastGuessOfThread46 string
	lastGuessOfThread47 string
	lastGuessOfThread48 string
	lastGuessOfThread49 string
	lastGuessOfThread50 string
	lastGuessOfThread51 string
	lastGuessOfThread52 string
	lastGuessOfThread53 string
	lastGuessOfThread54 string
	lastGuessOfThread55 string
	lastGuessOfThread56 string
	lastGuessOfThread57 string
	lastGuessOfThread58 string
	lastGuessOfThread59 string
	lastGuessOfThread60 string
	lastGuessOfThread61 string
	lastGuessOfThread62 string
	lastGuessOfThread63 string
	lastGuessOfThread64 string
	lastGuessOfThread65 string
	lastGuessOfThread66 string
	lastGuessOfThread67 string
	lastGuessOfThread68 string
	lastGuessOfThread69 string
	lastGuessOfThread70 string
	lastGuessOfThread71 string
	lastGuessOfThread72 string
	lastGuessOfThread73 string
	lastGuessOfThread74 string
	lastGuessOfThread75 string
	lastGuessOfThread76 string
	lastGuessOfThread77 string
	lastGuessOfThread78 string
	lastGuessOfThread79 string
	lastGuessOfThread80 string
	lastGuessOfThread81 string
	lastGuessOfThread82 string
	lastGuessOfThread83 string
	lastGuessOfThread84 string
	lastGuessOfThread85 string
	lastGuessOfThread86 string
	lastGuessOfThread87 string
	lastGuessOfThread88 string
	lastGuessOfThread89 string
	lastGuessOfThread90 string
	lastGuessOfThread91 string
	lastGuessOfThread92 string
	lastGuessOfThread93 string
	lastGuessOfThread94 string
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

	flag.StringVar(&wordlist, "w", "", "Allows for a custom wordlist to be used. Default is rockyou.txt")
	flag.StringVar(&hashlist, "t", "", "Allows for a list of hashes to be cracked, one per line.")
	flag.StringVar(&salt, "s", "", "If you are cracking a salted hash not in shadow form or with a haslist file, specify the salt here")
	flag.StringVar(&hash, "hash", "", "user can enter one hash to crack.")
	benchmarking := flag.Bool("b", false, "allows for hashcracker to implment benchmarking where if the user stops the program with ctrl c it will write out the last guess of each thread to a file, \n\t when the program is restarted it will start from where it left off. must use it again when you restart.")
	maxLength = flag.Int("l", 10, "specify the maximum length of each guess in a iteration")
	noWordlist = flag.Bool("nW", false, "specify if you don't want to use a wordlist to crack the hash")
	noIteration = flag.Bool("nI", false, "specify if you don't want to iterate through all possible combinations to crack the hash")

	flag.Parse()

	if wordlist == "" {
		wordlist = "rockyou.txt"
	}

	if hashlist == "" && hash != "" {//Go will look for both flags to be filled so we want to make sure that we return if either are provided, and not if both are
		return wordlist, salt, hash, hashlist, *benchmarking

	} else if hashlist != "" && hash == "" {
		return wordlist, salt, hash, hashlist, *benchmarking

	} else {
		fmt.Println("Usage: go run Cracker.go -hash <hash> | -t <hashlist>")
		fmt.Println("Must provide a hashlist or a hash to crack.")
		os.Exit(1)
	}

	return wordlist, salt, hash, hashlist, *benchmarking //Should never reach this point, but go requires a return
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
}


// Will determine if the hash is salted or not and divide up the hash into its components
func determineIfSalted(hash string, salt string) (string, string, string) {
	encryptionSchemeIndex := 1
	saltIndexWithoutYesCrypt := 2
	saltIndexWithYesCrypt := 3
	hashIndexWithoutYesCrypt := 3
	hashIndexWithYesCrypt := 4



	if strings.Index(hash, "$") != -1 { //If there is no dollar sign then it isn't a shadow file
		
		if strings.Split(hash, "$")[1] == "y" {
			return strings.Split(hash, "$")[encryptionSchemeIndex], strings.Split(hash, "$")[saltIndexWithYesCrypt], strings.Split((strings.Split(hash, "$")[hashIndexWithYesCrypt]), ":")[0]
		}

		return strings.Split(hash, "$")[encryptionSchemeIndex], strings.Split(hash, "$")[saltIndexWithoutYesCrypt], strings.Split((strings.Split(hash, "$")[hashIndexWithoutYesCrypt]), ":")[0]

	} else {
		return "", salt, hash
	}
}

// Will check if the encryption scheme is supported by the program
func schemeChecking(encryptionScheme string, hash string) {
	if encryptionScheme == "error" {
		println("Error: Hash is not supported by this program - ", hash)
	} else {
		println("\nCracking hash:", hash)
	}
}

// Will determine the encryption scheme of the hash if it is a shadow file
func detectionOfEncryptionScheme(encryptionScheme string) string {

	if encryptionScheme == "" { //If the encryption scheme is empty then we know it is not a shadow file
		return ""
	}
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

	return "error"
}

/*
 - This is where we actually start to crack the hash
*/



// Our high level function that will iterate through our wordlist and check if the hash matches then will iterate through all possible combinations
func findMatchingHash(hash string, wordlistPath string, salt string, encryptionScheme string, benchmarking bool) {
	hashLen := len(hash)


	if !*noWordlist {
		// Create channel to signal the hash is found in the wordlist
		hashFound := make(chan bool)

		// Iterate all words in the wordlist to find the hashed word
		cracked := iteratingWordList(wordlistPath, hash, salt, encryptionScheme, hashFound)
	

		if cracked {
			return
		}

		if !*noIteration {
			println("No match found in the wordlist. Trying all possible combinations...\n")
		} else{
			println("No match found in the wordlist.")
			return
		}
	}

	if !*noIteration {
		iterateUsingCharacters(benchmarking, hash, hashLen, salt, encryptionScheme)
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
        go findHashInWordlist(words, &wg, hashFound, hash, salt, encryptionScheme)
    }

    // Wait for all goroutines to finish or stop signal
   	wg.Wait()
	
	select {
	case <-hashFound:
		return true
	default:
		close(hashFound)
		return false
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



func findHashInWordlist(words []string, wg *sync.WaitGroup, hashFound chan bool, hash string, salt string, encryptionScheme string) {
    defer wg.Done()
    for _, word := range words {
        select {
        case <-hashFound:
            return // Stop goroutine
        default:
            hashedWord := calculateWordHash(len(hash), word, salt, encryptionScheme)
            if hashedWord == hash {
                println("\n\nHash cracked! The original word is:", word, "\n")
                close(hashFound)
				return
            }
        }
    }
}

/*
	This section consists of Iterating through all possible combinations of characters
*/


// Will iterate through all possible combinations of characters to find the hash
func iterateUsingCharacters(benchmarking bool, hash string, hashLen int, salt string, encryptionScheme string) {
	
	
	stop := make(chan bool)
	
	//Listens for ctrl c to stop the program and gracefully will stop it
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	
	
	isDirectory := false
	isDirectory = checkingToSeeIfWeHaveTriedToCrackThisHash(benchmarking, hash, isDirectory)

	shouldReturn := iterateOverCharacters(isDirectory, stop, hash, hashLen, salt, encryptionScheme, benchmarking)
	
	if shouldReturn {
		return 
	}

	go func() {
		timeTracker(stop)
	}()

	select {

	case <-sig://if there was a ctrl c signal
		fmt.Println("\n\nReceived termination signal. Quitting...")
		if benchmarking == true {
			writeToFileForAllThreads(hash)
		}
		close(stop)
		os.Exit(0)

	case <-stop:
		if benchmarking == true {
			writeToFileForAllThreads(hash)
		}
	}

	return
}

//A function just used to track the time that has passed since we have started to crack the hash iteratively
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


func checkingToSeeIfWeHaveTriedToCrackThisHash(benchmarking bool, hash string, isDirectory bool) bool {
	
	if benchmarking == true { //We don't care about this if we aren't benchmarking so we won't write out anything and don't need to make the space for it
		if _, err := os.Stat("benchmarking/" + hash); os.IsNotExist(err) {
			isDirectory = false
			os.Mkdir("benchmarking/"+hash, 0777)
		} else {
			isDirectory = true
		}
	}

	return isDirectory
}


func iterateOverCharacters(isDirectory bool, stop chan bool, hash string, hashLen int, salt string, encryptionScheme string, benchmarking bool) bool {
	
	if isDirectory { //If we have already tried to crack this hash then we will start where we left off
		println("we see that there has been progress made on cracking this hash, we will start from where we left off.")
		for i := 0; i < len(characters); i++ {
			IteratingForBenchmark(stop, hash, hashLen, salt, encryptionScheme, benchmarking, i)
		}
	} else {
		for i := 0; i < len(characters); i++ {
			IteratingFromTheBeginning(stop, hashLen, hash, salt, encryptionScheme, benchmarking, i)
		}
	}
	return false
}

func IteratingForBenchmark(stop chan bool, hash string, hashLen int, salt string, encryptionScheme string, benchmarking bool, i int)  {
	go func(i int) {
		select {
		case <-stop:
			return 
		default:
			guessFromBenchmark := readInGuessFromRespectiveBenchmarkFile(hash, string(characters[i]))
			
			if guessFromBenchmark == "" { //If  for some reason the file is empty then we will start from the beginning
				iteratingOverAllCombinations(hashLen, hash, salt, encryptionScheme, string(characters[i]), stop, benchmarking, i, false)
			} else {
				startFromBenchmarkWords(hash, hashLen, salt, encryptionScheme, guessFromBenchmark, stop, benchmarking, i)
			}
		}
	}(i)

}

func readInGuessFromRespectiveBenchmarkFile(hash string, startingCharacter string) string {
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


func startFromBenchmarkWords(hash string, hashLen int, salt string, encryptionScheme string, guessFromBenchmark string, stop chan bool, benchmarking bool, threadID int) {
    
	//In case for some reason the program gets killed before any guesses are made, this will preserve the last guess
    storeGuessInlastGuessOfThread(threadID, guessFromBenchmark)

	startingCharacters := guessFromBenchmark

	for length := len(guessFromBenchmark); length <= *maxLength; length++ {
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
                storeGuessInlastGuessOfThread(threadID, guess)
            }

			//to keep this from running forever we need to add on to the starting characters
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


/*

	This section is about Iterating through all possible combinations of characters

*/

func IteratingFromTheBeginning(stop chan bool, hashLen int, hash string, salt string, encryptionScheme string, benchmarking bool, i int) {
	go func(i int) {
		select {
		case <-stop:
			return 
		default:
			iteratingOverAllCombinations(hashLen, hash, salt, encryptionScheme, string(characters[i]), stop, benchmarking, i, false)
		}
	}(i)
}

// Function to iterate over all possible combinations of characters
func iteratingOverAllCombinations(hashLen int, hash string, salt string, encryptionScheme string, startingCharacter string, stop chan bool, benchmarking bool, threadID int, isRestart bool) {

    initialLength := 1
    
    for length := initialLength; length <= *maxLength; length++ {
        select {
        case <-stop:
            return // Quit signal received, terminate goroutine
        default:
            for guess := range generatePermutationsFromBeginning(characters, length, startingCharacter) {
                hashedGuess := calculateWordHash(hashLen, guess, salt, encryptionScheme)

                if benchmarking == true {
                    storeGuessInlastGuessOfThread(threadID, guess)
                }

                if hash == hashedGuess {
                    fmt.Println("\n\nHash cracked! The original word is:", guess)
                    close(stop) // Signal other goroutines to stop
					os.Mkdir("benchmarking/"+hash, 0777)
					writeToFile("answer", hash, guess)
                    return      // Terminate goroutine if hash is cracked
                }
            }
        }
    }
}

func generatePermutationsFromBeginning(characters string, length int, startingCharacter string) <-chan string {
    result := make(chan string)
    go func() {
        defer close(result)
        generatePermutationsFromBeginningHelper(characters, length, startingCharacter, result)
    }()
    return result
}

func generatePermutationsFromBeginningHelper(characters string, length int, current string, result chan<- string) {
    if length == 0 {
        result <- current
        return
    }
    for _, char := range characters {
        generatePermutationsFromBeginningHelper(characters, length-1, current+string(char), result)
    }
}



/*
	- This section is how we can assume the hash function used based on the length of the hash and where we write out to files our guesses
*/




// Calculate the hash of a given word,
// the hash function to be used is based on the length of the hash
func calculateWordHash(hashLen int, word string, salt string, encryptionScheme string) string {
	var hashedWord string

	if salt != "" {
		word = salt + word
	}

	if encryptionScheme != "" {
		hashedWord = hashWordOnEncryptionScheme(word, encryptionScheme, salt)
		return hashedWord
	}

	hashedWord = detectHashBasedOnLength(hashLen, hashedWord, word)
	return hashedWord
}

func detectHashBasedOnLength(hashLen int, hashedWord string, word string) string {
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

// Calculate the hash of a given word from a encryption scheme
func hashWordOnEncryptionScheme(word string, encryptionScheme string, salt string) string {
	var hashedWord string

	switch encryptionScheme { //we only support certain shadow file encryption schemes
	case "md5":
		hashedWord = fmt.Sprintf("%x", md5.Sum([]byte(word)))
	case "sha256":
		hashedWord = fmt.Sprintf("%x", sha256.Sum256([]byte(word)))
	case "sha512":
		hashedWord = fmt.Sprintf("%x", sha512.Sum512([]byte(word)))
	}
	return hashedWord
}


func writeToFile(startingCharacter string, hash string, guess string) {

	if startingCharacter != "answer" {

		startingCharacter = "0x" + fmt.Sprintf("%x", startingCharacter)
		err := os.WriteFile("benchmarking/" + hash +"/benchmarkFor" + startingCharacter + ".txt", []byte(guess), 0644)
		if err != nil {
			println("Error writing to file: ", err)
			os.Exit(1)
		}

	} else {//do a special file for the answer

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

// This is where the maddeny of how to efficeintly implment benchmarking with threads comes in I made chatGPT do this because of the montotony of it

// This is the function that will be called to write the last guess of each thread to athe global variable
func storeGuessInlastGuessOfThread(threadID int, guess string) {
	switch threadID {
	case 0:
		lastGuessOfThread0 = guess
	case 1:
		lastGuessOfThread1 = guess
	case 2:
		lastGuessOfThread2 = guess
	case 3:
		lastGuessOfThread3 = guess
	case 4:
		lastGuessOfThread4 = guess
	case 5:
		lastGuessOfThread5 = guess
	case 6:
		lastGuessOfThread6 = guess
	case 7:
		lastGuessOfThread7 = guess
	case 8:
		lastGuessOfThread8 = guess
	case 9:
		lastGuessOfThread9 = guess
	case 10:
		lastGuessOfThread10 = guess
	case 11:
		lastGuessOfThread11 = guess
	case 12:
		lastGuessOfThread12 = guess
	case 13:
		lastGuessOfThread13 = guess
	case 14:
		lastGuessOfThread14 = guess
	case 15:
		lastGuessOfThread15 = guess
	case 16:
		lastGuessOfThread16 = guess
	case 17:
		lastGuessOfThread17 = guess
	case 18:
		lastGuessOfThread18 = guess
	case 19:
		lastGuessOfThread19 = guess
	case 20:
		lastGuessOfThread20 = guess
	case 21:
		lastGuessOfThread21 = guess
	case 22:
		lastGuessOfThread22 = guess
	case 23:
		lastGuessOfThread23 = guess
	case 24:
		lastGuessOfThread24 = guess
	case 25:
		lastGuessOfThread25 = guess
	case 26:
		lastGuessOfThread26 = guess
	case 27:
		lastGuessOfThread27 = guess
	case 28:
		lastGuessOfThread28 = guess
	case 29:
		lastGuessOfThread29 = guess
	case 30:
		lastGuessOfThread30 = guess
	case 31:
		lastGuessOfThread31 = guess
	case 32:
		lastGuessOfThread32 = guess
	case 33:
		lastGuessOfThread33 = guess
	case 34:
		lastGuessOfThread34 = guess
	case 35:
		lastGuessOfThread35 = guess
	case 36:
		lastGuessOfThread36 = guess
	case 37:
		lastGuessOfThread37 = guess
	case 38:
		lastGuessOfThread38 = guess
	case 39:
		lastGuessOfThread39 = guess
	case 40:
		lastGuessOfThread40 = guess
	case 41:
		lastGuessOfThread41 = guess
	case 42:
		lastGuessOfThread42 = guess
	case 43:
		lastGuessOfThread43 = guess
	case 44:
		lastGuessOfThread44 = guess
	case 45:
		lastGuessOfThread45 = guess
	case 46:
		lastGuessOfThread46 = guess
	case 47:
		lastGuessOfThread47 = guess
	case 48:
		lastGuessOfThread48 = guess
	case 49:
		lastGuessOfThread49 = guess
	case 50:
		lastGuessOfThread50 = guess
	case 51:
		lastGuessOfThread51 = guess
	case 52:
		lastGuessOfThread52 = guess
	case 53:
		lastGuessOfThread53 = guess
	case 54:
		lastGuessOfThread54 = guess
	case 55:
		lastGuessOfThread55 = guess
	case 56:
		lastGuessOfThread56 = guess
	case 57:
		lastGuessOfThread57 = guess
	case 58:
		lastGuessOfThread58 = guess
	case 59:
		lastGuessOfThread59 = guess
	case 60:
		lastGuessOfThread60 = guess
	case 61:
		lastGuessOfThread61 = guess
	case 62:
		lastGuessOfThread62 = guess
	case 63:
		lastGuessOfThread63 = guess
	case 64:
		lastGuessOfThread64 = guess
	case 65:
		lastGuessOfThread65 = guess
	case 66:
		lastGuessOfThread66 = guess
	case 67:
		lastGuessOfThread67 = guess
	case 68:
		lastGuessOfThread68 = guess
	case 69:
		lastGuessOfThread69 = guess
	case 70:
		lastGuessOfThread70 = guess
	case 71:
		lastGuessOfThread71 = guess
	case 72:
		lastGuessOfThread72 = guess
	case 73:
		lastGuessOfThread73 = guess
	case 74:
		lastGuessOfThread74 = guess
	case 75:
		lastGuessOfThread75 = guess
	case 76:
		lastGuessOfThread76 = guess
	case 77:
		lastGuessOfThread77 = guess
	case 78:
		lastGuessOfThread78 = guess
	case 79:
		lastGuessOfThread79 = guess
	case 80:
		lastGuessOfThread80 = guess
	case 81:
		lastGuessOfThread81 = guess
	case 82:
		lastGuessOfThread82 = guess
	case 83:
		lastGuessOfThread83 = guess
	case 84:
		lastGuessOfThread84 = guess
	case 85:
		lastGuessOfThread85 = guess
	case 86:
		lastGuessOfThread86 = guess
	case 87:
		lastGuessOfThread87 = guess
	case 88:
		lastGuessOfThread88 = guess
	case 89:
		lastGuessOfThread89 = guess
	case 90:
		lastGuessOfThread90 = guess
	case 91:
		lastGuessOfThread91 = guess
	case 92:
		lastGuessOfThread92 = guess
	case 93:
		lastGuessOfThread93 = guess
	case 94:
		lastGuessOfThread94 = guess
	default:
		fmt.Println("Invalid thread ID:", threadID)
	}
}









// This is the function that will be called to write the last guess of each thread to a file
func writeToFileForAllThreads(hash string) {
	var characters = []string{
		"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
		"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
		"0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
		" ", "!", "\"", "#", "$", "%", "&", "'", "(", ")", "*", "+", ",", "-", ".", "/", ":", ";", "<", "=", ">", "?", "@",
		"[", "\\", "]", "^", "_", "`", "{", "|", "}", "~",
	}

	writeToFile(characters[0], hash, lastGuessOfThread0)
	writeToFile(characters[1], hash, lastGuessOfThread1)
	writeToFile(characters[2], hash, lastGuessOfThread2)
	writeToFile(characters[3], hash, lastGuessOfThread3)
	writeToFile(characters[4], hash, lastGuessOfThread4)
	writeToFile(characters[5], hash, lastGuessOfThread5)
	writeToFile(characters[6], hash, lastGuessOfThread6)
	writeToFile(characters[7], hash, lastGuessOfThread7)
	writeToFile(characters[8], hash, lastGuessOfThread8)
	writeToFile(characters[9], hash, lastGuessOfThread9)
	writeToFile(characters[10], hash, lastGuessOfThread10)
	writeToFile(characters[11], hash, lastGuessOfThread11)
	writeToFile(characters[12], hash, lastGuessOfThread12)
	writeToFile(characters[13], hash, lastGuessOfThread13)
	writeToFile(characters[14], hash, lastGuessOfThread14)
	writeToFile(characters[15], hash, lastGuessOfThread15)
	writeToFile(characters[16], hash, lastGuessOfThread16)
	writeToFile(characters[17], hash, lastGuessOfThread17)
	writeToFile(characters[18], hash, lastGuessOfThread18)
	writeToFile(characters[19], hash, lastGuessOfThread19)
	writeToFile(characters[20], hash, lastGuessOfThread20)
	writeToFile(characters[21], hash, lastGuessOfThread21)
	writeToFile(characters[22], hash, lastGuessOfThread22)
	writeToFile(characters[23], hash, lastGuessOfThread23)
	writeToFile(characters[24], hash, lastGuessOfThread24)
	writeToFile(characters[25], hash, lastGuessOfThread25)
	writeToFile(characters[26], hash, lastGuessOfThread26)
	writeToFile(characters[27], hash, lastGuessOfThread27)
	writeToFile(characters[28], hash, lastGuessOfThread28)
	writeToFile(characters[29], hash, lastGuessOfThread29)
	writeToFile(characters[30], hash, lastGuessOfThread30)
	writeToFile(characters[31], hash, lastGuessOfThread31)
	writeToFile(characters[32], hash, lastGuessOfThread32)
	writeToFile(characters[33], hash, lastGuessOfThread33)
	writeToFile(characters[34], hash, lastGuessOfThread34)
	writeToFile(characters[35], hash, lastGuessOfThread35)
	writeToFile(characters[36], hash, lastGuessOfThread36)
	writeToFile(characters[37], hash, lastGuessOfThread37)
	writeToFile(characters[38], hash, lastGuessOfThread38)
	writeToFile(characters[39], hash, lastGuessOfThread39)
	writeToFile(characters[40], hash, lastGuessOfThread40)
	writeToFile(characters[41], hash, lastGuessOfThread41)
	writeToFile(characters[42], hash, lastGuessOfThread42)
	writeToFile(characters[43], hash, lastGuessOfThread43)
	writeToFile(characters[44], hash, lastGuessOfThread44)
	writeToFile(characters[45], hash, lastGuessOfThread45)
	writeToFile(characters[46], hash, lastGuessOfThread46)
	writeToFile(characters[47], hash, lastGuessOfThread47)
	writeToFile(characters[48], hash, lastGuessOfThread48)
	writeToFile(characters[49], hash, lastGuessOfThread49)
	writeToFile(characters[50], hash, lastGuessOfThread50)
	writeToFile(characters[51], hash, lastGuessOfThread51)
	writeToFile(characters[52], hash, lastGuessOfThread52)
	writeToFile(characters[53], hash, lastGuessOfThread53)
	writeToFile(characters[54], hash, lastGuessOfThread54)
	writeToFile(characters[55], hash, lastGuessOfThread55)
	writeToFile(characters[56], hash, lastGuessOfThread56)
	writeToFile(characters[57], hash, lastGuessOfThread57)
	writeToFile(characters[58], hash, lastGuessOfThread58)
	writeToFile(characters[59], hash, lastGuessOfThread59)
	writeToFile(characters[60], hash, lastGuessOfThread60)
	writeToFile(characters[61], hash, lastGuessOfThread61)
	writeToFile(characters[62], hash, lastGuessOfThread62)
	writeToFile(characters[63], hash, lastGuessOfThread63)
	writeToFile(characters[64], hash, lastGuessOfThread64)
	writeToFile(characters[65], hash, lastGuessOfThread65)
	writeToFile(characters[66], hash, lastGuessOfThread66)
	writeToFile(characters[67], hash, lastGuessOfThread67)
	writeToFile(characters[68], hash, lastGuessOfThread68)
	writeToFile(characters[69], hash, lastGuessOfThread69)
	writeToFile(characters[70], hash, lastGuessOfThread70)
	writeToFile(characters[71], hash, lastGuessOfThread71)
	writeToFile(characters[72], hash, lastGuessOfThread72)
	writeToFile(characters[73], hash, lastGuessOfThread73)
	writeToFile(characters[74], hash, lastGuessOfThread74)
	writeToFile(characters[75], hash, lastGuessOfThread75)
	writeToFile(characters[76], hash, lastGuessOfThread76)
	writeToFile(characters[77], hash, lastGuessOfThread77)
	writeToFile(characters[78], hash, lastGuessOfThread78)
	writeToFile(characters[79], hash, lastGuessOfThread79)
	writeToFile(characters[80], hash, lastGuessOfThread80)
	writeToFile(characters[81], hash, lastGuessOfThread81)
	writeToFile(characters[82], hash, lastGuessOfThread82)
	writeToFile(characters[83], hash, lastGuessOfThread83)
	writeToFile(characters[84], hash, lastGuessOfThread84)
	writeToFile(characters[85], hash, lastGuessOfThread85)
	writeToFile(characters[86], hash, lastGuessOfThread86)
	writeToFile(characters[87], hash, lastGuessOfThread87)
	writeToFile(characters[88], hash, lastGuessOfThread88)
	writeToFile(characters[89], hash, lastGuessOfThread89)
	writeToFile(characters[90], hash, lastGuessOfThread90)
	writeToFile(characters[91], hash, lastGuessOfThread91)
	writeToFile(characters[92], hash, lastGuessOfThread92)
	writeToFile(characters[93], hash, lastGuessOfThread93)
	writeToFile(characters[94], hash, lastGuessOfThread94)
}
