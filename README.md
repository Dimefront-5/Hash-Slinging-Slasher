# Cracker

Cracker is a command-line tool written in Go for cracking hashes using a wordlist or through iterative brute force. We utilize go's multithreading along with a custom implementation of benchmarking. We can support salted hashes, shadow files, and hashlists that are delimited by newlines. WE also can detect what hashing algorithim is being used for a small subset of hashes based on the length of the hash and automatically crack it, so if a user has multiple different hash algorithms in a hashlist, it will be able to crack them all if they fall under the subset of hashes that we can detect.


## Setup

Please make sure you have Go installed on your machine. You can download it [here](https://golang.org/dl/).

Download rockyou.txt from [here](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt) and place it in the same directory as the executable.


## Usage

```bash
go run Cracker.go [-w wordlist] [-hash hash] [-s salt] [-hashlist hashlist]

  -b    allows for hashcracker to implment benchmarking where if the user stops the program with ctrl c it will write out the last guess of each thread to a file,
                 when the program is restarted it will start from where it left off. must use it again when you restart.
  -hash string
        user can enter one hash to crack.
  -l int
        specify the maximum length of each guess in a iteration (default 10)
  -nI
        specify if you don't want to iterate through all possible combinations to crack the hash
  -nW
        specify if you don't want to use a wordlist to crack the hash
  -s string
        If you are cracking a salted hash not in shadow form or with a haslist file, specify the salt here
  -t string
        Allows for a list of hashes to be cracked, one per line.
  -w string
        Allows for a custom wordlist to be used. Default is rockyou.txt
```
## Example
```bash    
go run Cracker.go -w wordlist.txt -hash 5f4dcc3b5aa765d61d8327deb882cf99

go run Cracker.go -w wordlist.txt -hashlist hashlist.txt

go run Cracker.go -w wordlist.txt -t hashlist.txt -nI

go run Cracker.go -t hashlist.txt -nW -l 5
```

You must provide a hash or a hashlist. 

If there is no provided wordlist, it will assume rockyou.txt as the default wordlist and that it is in the same directory as the executable.

## Hashes Supported

- MD5
- SHA1
- SHA256
- SHA512
- SHA384
- SHA224


## Benchmarking

Benchmarking is implemented by using the -b flag. When the user stops the program with ctrl c, it will write out the last guess of each thread to a file. When the program is restarted it will start from where it left off. The user must use the -b flag again when they restart the program.

The benchmarking folder will be created in the same directory as the executable. The folder will contain subdirectories named of the hashes, within each hash folder there will be 95 files named benchmarkFor0x20.txt, benchmarkFor0x21.txt, etc. Each file will contain the last guess of each thread respectively where each thread is represented by the hex value of the thread id.

When the program is restarted, it will read the last guess of each thread from the benchmarking folder and start from where it left off.

## Threading


For threading of the wordlist, we split the wordlist into 20 parts and then each thread will take a part of the wordlist to crack the hash. We have a waitgroup that waits for all threads to finish before the program exits. For brute force, we have 95 total threads where each thread has a different starting character from the ASCII password space. Curreently we do not allow for users to specify the number of threads, but we may implement this in the future.