package secure

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEncryptorAESGCM(t *testing.T) {
	plainText := []byte("some text 123")
	key := []byte("12345678123456781234567812345678")

	e := EncryptorAESGCM{}

	cipherText, err := e.EncryptAESGCM(plainText, key)
	assert.NoError(t, err, "error while encryption")
	assert.NotEqual(t, plainText, cipherText, "encryption func have`nt made any changes")

	decrypted, err := e.DecryptAESGCM(cipherText, key)
	assert.NoError(t, err, "error while decryption")
	assert.Equal(t, plainText, decrypted, "decrypted and plain text doesn't match")
}
