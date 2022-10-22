package libcrypto_test

import (
	"testing"

	"github.com/bytepass/libcrypto-go"
)

func TestAesCbc(t *testing.T) {
	plainText := "hello world"

	salt := []byte("salt")

	key := libcrypto.Pbkdf2Hash256("secret passphrase", salt, 1000)

	cipherText, err := libcrypto.EncryptAesCbc(key, plainText)
	if err != nil {
		t.Errorf("Failed to encrypt using aes cbc: %v", err)
	}

	clearText, err := libcrypto.DecryptAesCbc(key, cipherText)
	if err != nil {
		t.Errorf("Failed to decrypt using aes cbc: %v", err)
	}

	if clearText != plainText {
		t.Error("Decrypted text and input text aren't the same")
	}
}

func TestAesCbcDecrypt(t *testing.T) {
	cipherText := "ceb5156163e045c920cea4748ae302c7e210b4d521925bc342c71145aef3952d"

	salt := []byte("salt")
	key := libcrypto.Pbkdf2Hash256("secret passphrase", salt, 1000)

	cipherText, err := libcrypto.DecryptAesCbc(key, cipherText)
	if err != nil {
		t.Errorf("Failed to decrypt using aes cbc: %v", err)
	}

	if cipherText != "hello world" {
		t.Error("Invalid decrypted text")
	}
}
