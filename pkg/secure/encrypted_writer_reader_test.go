package secure

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
	"os"
	"testing"
)

func TestEncryptedWriterAndReader_OneWriteOperation(t *testing.T) {

	//prepare test
	plainText := []byte("some plain text")
	tmpFile, err := os.CreateTemp("", "testEncription.bin")
	require.NoError(t, err, "error while preparing test - cant create a temporary file")
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	//test

	//create writer
	key := make([]byte, chacha20poly1305.KeySize)
	for i := 0; i < chacha20poly1305.KeySize; i++ {
		key[i] = byte(i)
	}

	writer, err := NewEncryptionWriter(tmpFile.Name(), key)
	assert.NoError(t, err, "cant create a encryption writer")
	//write
	n, err := writer.Write(plainText)
	assert.NoError(t, err, "cant write to file")
	assert.Equal(t, len(plainText), n, "different amount of bytes were written to file")

	//close
	err = writer.Close()
	assert.NoError(t, err, "cant close writer")

	//create reader
	reader, err := NewEncryptionReader(tmpFile.Name(), key)
	assert.NoError(t, err, "cant create a encryption reader")

	//read
	result := make([]byte, len(plainText))
	reader.Read(result)
	assert.Equal(t, plainText, result, "different plain text")

	//expect eof
	_, err = reader.Read(result)
	assert.ErrorIs(t, err, io.EOF, "expected EOF")
}

func TestEncryptedWriterAndReader_TwoWriteOperations(t *testing.T) {

	//prepare test
	plainText1 := []byte("some plain text")
	plainText2 := []byte("some different plain text")
	tmpFile, err := os.CreateTemp("", "testEncription.bin")
	require.NoError(t, err, "error while preparing test - cant create a temporary file")
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	//test

	//create writer
	key := make([]byte, chacha20poly1305.KeySize)
	for i := 0; i < chacha20poly1305.KeySize; i++ {
		key[i] = byte(i)
	}
	writer, err := NewEncryptionWriter(tmpFile.Name(), key)
	assert.NoError(t, err, "cant create a encryption writer")

	//write
	n, err := writer.Write(plainText1)
	assert.NoError(t, err, "cant write to file")
	assert.Equal(t, len(plainText1), n, "different amount of plaintText1 bytes were written to file")
	n, err = writer.Write(plainText2)
	assert.NoError(t, err, "cant write to file")
	assert.Equal(t, len(plainText2), n, "different amount of plaintText2 bytes were written to file")

	//close
	err = writer.Close()
	assert.NoError(t, err, "cant close writer")

	//create reader
	reader, err := NewEncryptionReader(tmpFile.Name(), key)
	assert.NoError(t, err, "cant create a encryption reader")

	//read
	result1 := make([]byte, len(plainText1))
	bytesRead1, err := reader.Read(result1)
	assert.NoError(t, err, "cant read plainText1")
	assert.Equal(t, len(plainText1), bytesRead1, "different amount of plainText1 bytes were read from file")
	assert.Equal(t, plainText1, result1, "different plainText1")

	result2 := make([]byte, len(plainText2))
	bytesRead2, err := reader.Read(result2)
	assert.NoError(t, err, "cant read plainText2")
	assert.Equal(t, len(plainText2), bytesRead2, "different amount of plainText2 bytes were read from file")
	assert.Equal(t, plainText2, result2, "different plainText2")

	//expect eof
	_, err = reader.Read(result2)
	assert.ErrorIs(t, err, io.EOF, "expected EOF")
}

// TestEncryptedWriterAndReader_WriteAndReadBigData will try to write a big text by 8-byte chunks.
func TestEncryptedWriterAndReader_WriteAndReadBigData(t *testing.T) {

	//prepare test
	plainText := []byte("Some plain text. Actually it not so big, because it hast have to be more then 8 bytes.")
	tmpFile, err := os.CreateTemp("", "testEncription.bin")
	require.NoError(t, err, "error while preparing test - cant create a temporary file")
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	//test

	//create writer
	key := make([]byte, chacha20poly1305.KeySize)
	for i := 0; i < chacha20poly1305.KeySize; i++ {
		key[i] = byte(i)
	}
	writer, err := NewEncryptionWriter(tmpFile.Name(), key)
	assert.NoError(t, err, "cant create a encryption writer")

	//write
	br := bytes.NewReader(plainText)
	bufToWrite := make([]byte, 8)
	for amountToWrite, _ := br.Read(bufToWrite); amountToWrite != 0; amountToWrite, _ = br.Read(bufToWrite) {
		n, err := writer.Write(bufToWrite[:amountToWrite])
		assert.NoError(t, err, "cant write to file")
		assert.Equal(t, amountToWrite, n, "different amount of bytes were written to file")
	}
	//close
	err = writer.Close()
	assert.NoError(t, err, "cant close writer")

	//create reader
	reader, err := NewEncryptionReader(tmpFile.Name(), key)
	assert.NoError(t, err, "cant create a encryption reader")

	//read
	result := make([]byte, 0)
	bufToRead := make([]byte, 8)
	for amountRead, err := reader.Read(bufToRead); err != io.EOF; amountRead, err = reader.Read(bufToRead) {
		assert.NoError(t, err, "cant read plainText")
		result = append(result, bufToRead[:amountRead]...)
	}
	assert.Equal(t, plainText, result, "different plain text")
}
