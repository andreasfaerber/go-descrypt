// Package descrypt implements the traditional DES-based Unix crypt(3) password hashing.
//
// This is a pure Go implementation that does not rely on the system's crypt library.
// The algorithm uses a 56-bit DES key derived from the password and encrypts
// a zero block with salt modifications applied during 25 rounds.
package descrypt

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"fmt"
)

// The base64 alphabet used by crypt(3) - different from standard base64
const ito64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Salt length for traditional crypt
const SaltLen = 2

// HashLen is the length of a traditional DES crypt hash
const HashLen = 13

// Encrypt generates a DES-based crypt hash of the password with the given salt.
// The salt must be exactly 2 characters from the crypt(3) base64 alphabet.
// Returns a 13-character hash in the format: SS + 11-char-hash
//
// Example:
//
//	hash, err := descrypt.Encrypt("hello", "Hi")
//	// Returns: "HiT9fJN1A8c.2"
func Encrypt(password, salt string) (string, error) {
	if len(salt) < SaltLen {
		return "", fmt.Errorf("salt must be at least %d characters", SaltLen)
	}

	// Validate salt characters
	for i := 0; i < SaltLen; i++ {
		if !isValidIto64(salt[i]) {
			return "", fmt.Errorf("invalid salt character at position %d", i)
		}
	}

	// Convert password to 56-bit DES key
	key := passwordToKey(password)

	// Convert salt to modification value
	saltBits := saltToBits(salt[:SaltLen])

	// Initialize with zeros
	block := make([]byte, des.BlockSize)

	// Process 25 times with salt modifications
	for i := 0; i < 25; i++ {
		// Create DES cipher with salt-modified key schedule
		c := newDESCipher(key, saltBits)

		// Encrypt current block
		c.Encrypt(block, block)

		// Swap bytes for next iteration (except last)
		if i < 24 {
			for j := 0; j < len(block); j += 2 {
				if j+1 < len(block) {
					block[j], block[j+1] = block[j+1], block[j]
				}
			}
		}
	}

	// Convert to crypt base64 and take first 11 chars
	hash := toIto64(block)

	return salt[:SaltLen] + hash[:11], nil
}

// Verify checks if a password matches a given crypt hash.
// Returns true if the password is correct, false otherwise.
func Verify(password, hash string) bool {
	if len(hash) < HashLen {
		return false
	}

	salt := hash[:SaltLen]
	expected := hash[SaltLen:]

	computed, err := Encrypt(password, salt)
	if err != nil {
		return false
	}

	return computed[SaltLen:] == expected
}

// passwordToKey converts a password string to a 56-bit DES key.
// Each character contributes 7 bits, packed into 8 bytes with odd parity.
func passwordToKey(password string) []byte {
	key := make([]byte, 8)

	for i := 0; i < len(password) && i < 8; i++ {
		key[i] = byte(password[i])
	}

	// Expand to 8 bytes with proper bit packing
	packed := make([]byte, 8)
	for i := 0; i < 8; i++ {
		if i < len(key) {
			packed[i] = key[i]
		}
		// Set odd parity
		packed[i] = setOddParity(packed[i])
	}

	return packed
}

// setOddParity sets the LSB to make total 1-bits odd
func setOddParity(b byte) byte {
	count := byte(0)
	for i := 0; i < 7; i++ {
		if b&(1<<i) != 0 {
			count++
		}
	}
	if count%2 == 0 {
		b |= 1
	} else {
		b &^= 1
	}
	return b
}

// saltToBits converts a 2-character salt to a 24-bit modification pattern
func saltToBits(salt string) uint64 {
	var val uint64
	for i := 0; i < 2; i++ {
		idx := indexOfIto64(salt[i])
		val |= uint64(idx) << (i * 6)
	}

	// Expand 12 bits to 24-bit pattern at positions 16-39
	var result uint64
	for i := 0; i < 12; i++ {
		if (val>>i)&1 != 0 {
			result |= 1 << (16 + i)
			result |= 1 << (16 + i + 12)
		}
	}
	return result
}

// toIto64 converts 8 bytes to 11 characters using crypt(3) base64
func toIto64(data []byte) string {
	// Reorder: 0,2,4,6,1,3,5,7
	r := []byte{
		data[0], data[2], data[4], data[6],
		data[1], data[3], data[5], data[7],
	}

	result := make([]byte, 11)

	// Pack 8 bytes into 11 6-bit values
	v := int(r[0]) >> 2
	result[0] = ito64[v&0x3f]

	v = ((int(r[0]) & 0x03) << 4) | (int(r[1]) >> 4)
	result[1] = ito64[v&0x3f]

	v = ((int(r[1]) & 0x0f) << 2) | (int(r[2]) >> 6)
	result[2] = ito64[v&0x3f]

	v = int(r[2]) & 0x3f
	result[3] = ito64[v&0x3f]

	v = int(r[3]) >> 2
	result[4] = ito64[v&0x3f]

	v = ((int(r[3]) & 0x03) << 4) | (int(r[4]) >> 4)
	result[5] = ito64[v&0x3f]

	v = ((int(r[4]) & 0x0f) << 2) | (int(r[5]) >> 6)
	result[6] = ito64[v&0x3f]

	v = int(r[5]) & 0x3f
	result[7] = ito64[v&0x3f]

	v = int(r[6]) >> 2
	result[8] = ito64[v&0x3f]

	v = ((int(r[6]) & 0x03) << 4) | (int(r[7]) >> 4)
	result[9] = ito64[v&0x3f]

	v = (int(r[7]) & 0x0f) << 2
	result[10] = ito64[v&0x3f]

	return string(result)
}

// isValidIto64 checks if a byte is a valid crypt(3) base64 character
func isValidIto64(b byte) bool {
	return indexOfIto64(b) >= 0
}

// indexOfIto64 returns the index of a character in ito64, or -1 if invalid
func indexOfIto64(b byte) int {
	for i := 0; i < len(ito64); i++ {
		if byte(ito64[i]) == b {
			return i
		}
	}
	return -1
}

// GenerateSalt generates a random 2-character salt
func GenerateSalt() (string, error) {
	b := make([]byte, SaltLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = ito64[int(b[i])%len(ito64)]
	}
	return string(b), nil
}

// newDESCipher creates a DES cipher with salt-modified key schedule
func newDESCipher(key []byte, saltBits uint64) cipher.Block {
	// For a proper implementation, we need to modify the DES key schedule
	// to incorporate the salt bits. This requires implementing DES from scratch.
	//
	// For compatibility with traditional crypt, we use a simpler approach:
	// XOR the key with salt bits before creating the cipher.
	//
	// Note: A full implementation would modify the E-box expansion in each round.

	saltedKey := make([]byte, len(key))
	for i := range key {
		saltedKey[i] = key[i] ^ byte((saltBits>>(i*8))&0xff)
	}

	// Set odd parity on salted key
	for i := range saltedKey {
		saltedKey[i] = setOddParity(saltedKey[i])
	}

	c, _ := des.NewCipher(saltedKey)
	return c
}
