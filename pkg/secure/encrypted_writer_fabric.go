package secure

import (
	"GophKeeper/internal/app/requiredInterfaces"
	"fmt"
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
// Key must have chacha20poly1305.KeySize len.
func (ef *encryptionFileFabric) CreateNewEncryptedWriter(userID string, dataName string, key []byte) (writer io.WriteCloser, err error) {
	filePath := fmt.Sprintf("./usersdata/user_%s/file_%s.bin", userID, dataName)

	writer, err = NewEncryptionWriter(filePath, key)
	if err != nil {
		writer.Close()
		return nil, fmt.Errorf("cant create encrypted writer: %w", err)
	}
	return writer, err
}

// CreateNewEncryptedReader creates new EncryptionReader.
// Encryption alg - chacha20poly1305.
func (ef *encryptionFileFabric) CreateNewEncryptedReader(userID string, dataName string, key []byte) (io.ReadCloser, error) {
	filePath := fmt.Sprintf("./usersdata/user_%s/file_%s.bin", userID, dataName)
	return NewEncryptionReader(filePath, key)
}
