package libcrypto_test

import (
	"testing"

	"github.com/bytepass/libcrypto-go"
)

func TestAesCbc(t *testing.T) {
	plainText := "hello world"

	saltSize := 16
	salt, err := libcrypto.GenerateSalt(saltSize)
	if err != nil {
		t.Errorf("Failed to generate salt: %v", err)
	}

	key := libcrypto.Pbkdf2Hash256("password", salt, 100000)

	cipherText, err := libcrypto.EncryptAesCbc(key, plainText)
	if err != nil {
		t.Errorf("Failed to encrypt using aes cbc: %v", err)
	}

	clearText, err := libcrypto.DecryptAesCbc(key, cipherText)
	if err != nil {
		t.Errorf("Failed to encrypt using aes cbc: %v", err)
	}

	if clearText != plainText {
		t.Error("Decrypted text and input text aren't the same")
	}
}
