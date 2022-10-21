package libcrypto_test

import (
	"testing"

	"github.com/bytepass/libcrypto-go"
)

func TestPbkdf2Hash256(t *testing.T) {
	saltSize := 16
	salt, err := libcrypto.GenerateSalt(saltSize)
	if err != nil {
		t.Errorf("Failed to generate salt: %v", err)
	}

	// compute a 256-bit password hash with salt and 100000 iterations
	libcrypto.Pbkdf2Hash256("password", salt, 100000)
}

func TestPbkdf2Hash512(t *testing.T) {
	saltSize := 16
	salt, err := libcrypto.GenerateSalt(saltSize)
	if err != nil {
		t.Errorf("Failed to generate salt: %v", err)
	}

	// compute a 512-bit password hash with salt and 100000 iterations
	libcrypto.Pbkdf2Hash512("password", salt, 100000)
}
