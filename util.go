package jwtguard

import (
	"crypto/rand"
	"encoding/base64"
)

// randomBytesPool is a reusable byte slice used to avoid repeated allocations
// when generating random strings. It is resized dynamically if needed.
var randomBytesPool = make([]byte, 1024)

// generateRandomString creates a secure random base64 string of given length
func generateRandomString(length int) (string, error) {
	if length > len(randomBytesPool) {
		// Resize the pool if the required length exceeds current capacity
		randomBytesPool = make([]byte, length)
	}

	// Fill the buffer with secure random bytes
	if _, err := rand.Read(randomBytesPool[:length]); err != nil {
		return "", err
	}

	// Encode the random bytes to base64 (without padding)
	return base64.RawStdEncoding.EncodeToString(randomBytesPool[:length]), nil
}
