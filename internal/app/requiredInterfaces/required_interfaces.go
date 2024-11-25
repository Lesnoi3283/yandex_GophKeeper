package requiredInterfaces

import (
	"GophKeeper/internal/app/entities"
	"context"
	"io"
)

//go:generate mockgen -source=required_interfaces.go -destination=./mocks/mocks.go -package=mocks

// KeyKeeper MUST be a secure key storage interface that follows PCI DSS 4.0.
// This interface is specifically used for storing encryption keys.
type KeyKeeper interface {
	SetBankCardKey(userID string, dataID string, key string) error
	GetBankCardKey(userID string, dataID string) (string, error)
	SetTextDataKey(userID string, dataID string, key string) error
	GetTextDataKey(userID string, dataID string) (string, error)
	SetLoginAndPasswordKey(userID string, dataID string, key string) error
	GetLoginAndPasswordKey(userID string, dataID string) (string, error)
	SetBinaryDataKey(userID string, dataName string, key string) error
	GetBinaryDataKey(userID string, dataName string) (string, error)
}

// Storage can save and return data.
// It can, but not have to encrypt your data.
// You have to encrypt it yourself.
// DON`T STORE AN ENCRYPTION KEY HERE!!! Use KeyKeeper! Follow PCI DSS 4.0 rules.
type Storage interface {
	SaveBankCard(ctx context.Context, ownerID int, lastFourDigits int, cardData string) (id int, err error)
	GetBankCard(ctx context.Context, ownerID int, last4Digits int) (data string, dataID int, err error)
	SaveLoginAndPassword(ctx context.Context, ownerID int, login string, password string) (id int, err error)
	GetPasswordByLogin(ctx context.Context, ownerID int, login string) (password string, dataID int, err error)
	SaveText(ctx context.Context, ownerID int, textName string, text string) (id int, err error)
	GetText(ctx context.Context, ownerID int, textName string) (text string, dataID int, err error)
}

// UserManager controls all manipulations with user.
// Such as creation and authentication (by login and password).
type UserManager interface {
	CreateUser(ctx context.Context, user entities.User) (id int, err error)
	AuthUser(ctx context.Context, user entities.User) (id int, err error)
}

// JWTHelper creates new JWT and validates old ones.
type JWTHelper interface {
	BuildNewJWTString(userID int) (string, error)
	GetUserID(token string) (userID int, err error)
}

// Encryptor have to encrypt and decrypt data using AES GCM.
type Encryptor interface {
	EncryptAESGCM(plaintext []byte, key []byte) (string, error)
	DecryptAESGCM(ciphertext string, key []byte) ([]byte, error)
}

// EncryptionWriterReaderFabric is an interface to create EncryptionWriter and EncryptionReader.
// Returns writer and encryption key.
type EncryptionWriterReaderFabric interface {
	CreateNewEncryptedWriter(userID string, dataName string) (writer io.WriteCloser, key []byte, err error)
	CreateNewEncryptedReader(userID string, dataName string, key []byte) (io.ReadCloser, error)
}
