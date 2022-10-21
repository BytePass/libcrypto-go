package libcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// Encrypt text using AES-CBC
//
//	saltSize := 16
//	salt, err := libcrypto.GenerateSalt(saltSize)
//	if err != nil {
//		t.Errorf("Failed to generate salt: %v", err)
//	}
//
//	// compute a 256-bit password hash with salt and 100000 iterations
//	key := libcrypto.Pbkdf2Hash256("password", salt, 100000)
//
//	clearText := "test to encrypt"
//
//	// encrypt the clear text
//	cipherText, err := EncryptAesCbc(key, clearText)
//	if err != nil {
//		panic(err)
//	}
func EncryptAesCbc(key string, clearText string) (string, error) {
	// decode the key from a hex string
	secretKey, err := hex.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("error decoding key as hex string: %v", err)
	}

	// create a new cipher block
	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return "", err
	}

	// encode the clear text into bytes
	clearTextBytes := []byte(clearText)

	// add padding to the clear text
	clearTextBytes = PKCS5Padding(clearTextBytes, block.BlockSize())

	// allocate space in the heap for the cipher text
	cipherText := make([]byte, aes.BlockSize+len(clearTextBytes))

	// add initialization vector to the cipher text
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", nil
	}

	// returns a BlockMode which encrypts in cipher block chaining mode
	cbc := cipher.NewCBCEncrypter(block, iv)
	// encrypt the clear text
	cbc.CryptBlocks(cipherText[aes.BlockSize:], clearTextBytes)

	// returns the cipher text as a hex string
	return hex.EncodeToString(cipherText), nil
}

// Decrypt the AES-CBC cipher text
//
//	key := "key..."
//	cipherText := "cipher text..."
//
//	// decrypt the cipher text
//	cipherText, err := DecryptAesCbc(key, cipherText)
//	if err != nil {
//		panic(err)
//	}
func DecryptAesCbc(key string, cipherText string) (string, error) {
	// decode the key from a hex string
	secretKey, err := hex.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("error decoding key as hex string: %v", err)
	}

	// decode the cipher text from a hex string
	cipherTextBytes, err := hex.DecodeString(cipherText)
	if err != nil {
		return "", fmt.Errorf("error decoding cipher text as hex string: %v", err)
	}

	// create a new cipher block
	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return "", err
	}

	// get the initialization vector from the cipher key
	iv := cipherTextBytes[:aes.BlockSize]
	// get the cipher key without initialization vector
	cipherTextBytes = cipherTextBytes[aes.BlockSize:]

	// returns a BlockMode which decrypts in cipher block chaining mode
	cbc := cipher.NewCBCDecrypter(block, iv)
	// decrypt all ciphers blocks
	cbc.CryptBlocks(cipherTextBytes, cipherTextBytes)

	// trim padding from the cipher text
	plainText := PKCS5Trimming(cipherTextBytes)

	// returns the plain text as a string
	return string(plainText), nil
}

// Add padding to the cipher text
func PKCS5Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padtext...)
}

// Trim padding from the cipher text
func PKCS5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}
