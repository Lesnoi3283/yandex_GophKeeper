package secure

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
	"os"
	"path/filepath"
)

const lenOfDataLenInfo = 8

// EncryptionWriter encrypts data and writes it into a file.
// NOTE: Better to use a fabric to create it.
type EncryptionWriter struct {
	file   *os.File
	aead   cipher.AEAD
	nonce  []byte
	buffer []byte
}

// NewEncryptionWriter creates new EncryptionWriter.
// Key have to be 256 bit len.
// Encryption alg - "chacha20poly1305".
// ATTENTION - it creates a file (only if it does not exist), so don`t forget to close it using EncryptionWriter.Close().
func NewEncryptionWriter(filePath string, key []byte) (*EncryptionWriter, error) {
	//create dir
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create directories: %w", err)
	}

	//open or create file
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	//create encryptor
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}

	return &EncryptionWriter{
		file:   file,
		aead:   aead,
		nonce:  make([]byte, aead.NonceSize()),
		buffer: make([]byte, 0),
	}, nil
}

// Write encrypts data and writes it to a file.
// REMEMBER: as much data you will write using Write - as mush data you will read using Read.
// For example:
// Write(<8 bytes>). Write(<16 bytes>).
// The first Read will return you EXACTLY 8 (EIGHT) bytes. Not more!
func (ew *EncryptionWriter) Write(p []byte) (n int, err error) {
	// generate nonce
	if _, err := rand.Read(ew.nonce); err != nil {
		return 0, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// encrypt
	ciphertext := ew.aead.Seal(nil, ew.nonce, p, nil)

	// write data to a file
	totalLength := uint64(len(ew.nonce) + len(ciphertext))
	lengthBuf := make([]byte, lenOfDataLenInfo)
	binary.BigEndian.PutUint64(lengthBuf, totalLength)

	//next firstly will be written len to make possible to read this data in the EncryptionReader.
	//Nonce and different data will be written after it.
	if _, err := ew.file.Write(lengthBuf); err != nil {
		return 0, fmt.Errorf("failed to write length: %w", err)
	}

	if _, err := ew.file.Write(ew.nonce); err != nil {
		return 0, fmt.Errorf("failed to write nonce: %w", err)
	}

	if _, err := ew.file.Write(ciphertext); err != nil {
		return 0, fmt.Errorf("failed to write ciphertext: %w", err)
	}

	return len(p), nil
}

// Close closes file.
func (ew *EncryptionWriter) Close() error {
	return ew.file.Close()
}

// EncryptionReader reads encrypted data from file and returns decrypted bytes.
type EncryptionReader struct {
	file   *os.File
	aead   cipher.AEAD
	buffer []byte
}

// NewEncryptionReader creates new EncryptionReader.
func NewEncryptionReader(filePath string, key []byte) (*EncryptionReader, error) {
	// Open file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	// init AEAD
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}

	return &EncryptionReader{
		file:   file,
		aead:   aead,
		buffer: make([]byte, 0),
	}, nil
}

// Read reads encrypted data, decrypts it, and returns the decrypted bytes.
// Warning: Read will return EXACTLY the same number of bytes that were written using Write. No more.
func (er *EncryptionReader) Read(p []byte) (n int, err error) {
	if len(er.buffer) == 0 {
		// Read data len
		lengthBuf := make([]byte, lenOfDataLenInfo)
		_, err := io.ReadFull(er.file, lengthBuf)
		if err != nil {
			return 0, err
		}
		totalLength := binary.BigEndian.Uint64(lengthBuf)

		if totalLength < uint64(er.aead.NonceSize()) {
			return 0, errors.New("invalid data length")
		}

		// Read nonce and ciphertext
		data := make([]byte, totalLength)
		if _, err := io.ReadFull(er.file, data); err != nil {
			return 0, err
		}

		nonce := data[:er.aead.NonceSize()]
		ciphertext := data[er.aead.NonceSize():]

		// Decrypt
		plaintext, err := er.aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return 0, fmt.Errorf("failed to decrypt data: %w", err)
		}

		er.buffer = plaintext
	}

	// Read from buffer
	n = copy(p, er.buffer)
	er.buffer = er.buffer[n:]
	return n, nil
}

// Close closes file.
func (er *EncryptionReader) Close() error {
	return er.file.Close()
}
