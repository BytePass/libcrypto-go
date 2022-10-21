package libcrypto

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"

	"golang.org/x/crypto/pbkdf2"
)

// HashPassword returns a PBKDF2-SHA256 hash of the given password.
//
//	saltSize := 16
//	salt, err := GenerateSalt(saltSize)
//	if err != nil {
//		panic(err)
//	}
//
//	// compute a 256-bit password hash with salt and 100000 iterations
//	hash := Pbkdf2Hash256("password", salt, 100000)
func Pbkdf2Hash256(password string, salt []byte, iter int) string {
	// convert password string to byte slice
	passwordBytes := []byte(password)

	// compute password hash using PBKDF2-SHA256 algorithm
	dk := pbkdf2.Key(passwordBytes, salt, iter, 32, sha256.New)

	// convert the hashed password to a hex string
	return hex.EncodeToString(dk)
}

// HashPassword returns a PBKDF2-SHA512 hash of the given password.
//
//	saltSize := 16
//	salt, err := GenerateSalt(saltSize)
//	if err != nil {
//		panic(err)
//	}
//
//	// compute a 512-bit password hash with salt and 100000 iterations
//	hash := Pbkdf2Hash512("password", salt, 100000)
func Pbkdf2Hash512(password string, salt []byte, iter int) string {
	// convert password string to byte slice
	passwordBytes := []byte(password)

	// compute password hash using PBKDF2-SHA512 algorithm
	dk := pbkdf2.Key(passwordBytes, salt, iter, 64, sha512.New)

	// convert the hashed password to a hex string
	return hex.EncodeToString(dk)
}
