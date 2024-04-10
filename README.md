# Cracker

Cracker is a command-line tool written in Go for cracking hashes using a wordlist.

## Usage

```bash
go run Cracker.go [-w wordlist] [-hash hash] [-s salt] [-hashlist hashlist]

-hash string
    Hash to crack
-hashlist string
    Hashlist to crack
-s string
    Salt
-w string
    Wordlist
```
## Example
```bash    
go run Cracker.go -w wordlist.txt -hash 5f4dcc3b5aa765d61d8327deb882cf99

go run Cracker.go -w wordlist.txt -hashlist hashlist.txt
```

You must provide a hash or a hashlist. 

If there is no provided wordlist, it will assume rockyou.txt as the default wordlist and that it is in the same directory as the executable.