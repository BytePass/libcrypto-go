package libcrypto

import "crypto/rand"

// GenerateSalt returns a random salt.
func GenerateSalt(size int) ([]byte, error) {
	salt := make([]byte, size)

	_, err := rand.Read(salt[:])

	return salt, err
}
