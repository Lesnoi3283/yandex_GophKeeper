package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// Encryptor has 2 functions - encrypt and decrypt. It doesn`t contain any fields.
// It`s just a functor.
// It was created to make possible to mock encryption functions.
type EncryptorAESGCM struct{}

func NewEncryptorAESGSM() *EncryptorAESGCM {
	return &EncryptorAESGCM{}
}

// EncryptAESGCM encrypts data using AES-GSM.
// key must have 32-byte len for AES-256.
func (e *EncryptorAESGCM) EncryptAESGCM(plaintext []byte, key []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("key length must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes.NewCipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("cipher.NewGCM: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)

	result := append(nonce, ciphertext...)

	resultBase64 := base64.StdEncoding.EncodeToString(result)

	return resultBase64, nil
}

// DecryptAESGCM decrypts data.
func (e *EncryptorAESGCM) DecryptAESGCM(ciphertext string, key []byte) ([]byte, error) {
	ciphertextUnBase64, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("cant decode base64: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cant create New Cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cat create New GCM: %w", err)
	}

	if len(ciphertext) < aesGCM.NonceSize() {
		return nil, errors.New("ciphertext is too short")
	}

	nonce, ciphertextUnBase64 := ciphertextUnBase64[:aesGCM.NonceSize()], ciphertextUnBase64[aesGCM.NonceSize():]

	plaintext, err := aesGCM.Open(nil, nonce, ciphertextUnBase64, nil)
	if err != nil {
		return nil, fmt.Errorf("aesGCM.Open: %w", err)
	}

	return plaintext, nil
}
