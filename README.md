# go-descrypt

Pure Go implementation of the traditional DES-based Unix crypt(3) password hashing algorithm. Based on https://github.com/dworkin/dgd.git crypt implementation.

## Features

- **Pure Go** - No CGO, no system crypt library dependencies
- **Compatible** - Produces hashes compatible with traditional crypt(3)

## Installation

```bash
go get github.com/andreasfaerber/go-descrypt
```

## Usage

```go
package main

import (
    "fmt"
    "github.com/andreasfaerber/go-descrypt"
)

func main() {
    // Encrypt a password with a given salt
    hash, err := descrypt.Encrypt("hello", "Hi")
    if err != nil {
        panic(err)
    }
    fmt.Println(hash) // HiT9fJN1A8c.2

    // Verify a password against a hash
    valid := descrypt.Verify("hello", "HiT9fJN1A8c.2")
    fmt.Println(valid) // true

    // Generate a random salt
    salt, err := descrypt.GenerateSalt()
    if err != nil {
        panic(err)
    }
    fmt.Println(salt) // e.g., "Xy"
}
```

## API

### `Encrypt(password, salt string) (string, error)`

Generates a DES-based crypt hash of the password with the given salt.
The salt must be exactly 2 characters from the crypt(3) base64 alphabet (`./0-9A-Za-z`).
Returns a 13-character hash in the format: `SS` + 11-char-hash.

### `Verify(password, hash string) bool`

Checks if a password matches a given crypt hash.
Returns `true` if the password is correct, `false` otherwise.

### `GenerateSalt() (string, error)`

Generates a random 2-character salt using `crypto/rand`.

## Algorithm

The traditional DES crypt algorithm:

1. Converts the password to a 56-bit DES key (7 bits per character, 8 characters max)
2. Applies salt modifications to the key schedule
3. Encrypts a zero block 25 times with byte swapping between rounds
4. Encodes the result using the crypt(3) base64 alphabet

## Security Notice

**DES crypt is considered insecure for modern password storage:**

- Limited to 56-bit keys (8 characters, 7 bits each)
- Fast computation makes brute-force attacks feasible
- No configurable cost factor like bcrypt or scrypt

For new applications, use **bcrypt**, **scrypt**, or **argon2** instead.

This implementation is provided for:
- Legacy system compatibility
- Educational purposes
- Historical reference

## License

MIT License - see LICENSE file for details.
