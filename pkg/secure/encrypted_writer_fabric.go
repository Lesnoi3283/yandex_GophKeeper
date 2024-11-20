package secure

import (
	"GophKeeper/internal/app/requiredInterfaces"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
)

// encryptionFileFabric can create encryption file writers.
type encryptionFileFabric struct{}

// NewEncryptionFileFabric creates new fabric,
func NewEncryptionFileFabric() requiredInterfaces.EncryptionWriterReaderFabric {
	return &encryptionFileFabric{}
}

// CreateNewEncryptedWriter creates new EncryptionWriter.
// Encryption alg - chacha20poly1305.
func (ef *encryptionFileFabric) CreateNewEncryptedWriter(userID string, dataName string) (writer io.WriteCloser, key []byte, err error) {
	filePath := fmt.Sprintf("./usersdata/user_%s/file_%s.bin", userID, dataName)

	key = make([]byte, chacha20poly1305.KeySize)
	_, err = rand.Read(key)
	if err != nil {
		return nil, nil, fmt.Errorf("cant generate random key: %w", err)
	}

	writer, err = NewEncryptionWriter(filePath, key)
	return writer, key, err
}

// CreateNewEncryptedReader creates new EncryptionReader.
// Encryption alg - chacha20poly1305.
func (ef *encryptionFileFabric) CreateNewEncryptedReader(userID string, dataName string, key []byte) (io.ReadCloser, error) {
	filePath := fmt.Sprintf("./usersdata/user_%s/file_%s.bin", userID, dataName)
	return NewEncryptionReader(filePath, key)
}
