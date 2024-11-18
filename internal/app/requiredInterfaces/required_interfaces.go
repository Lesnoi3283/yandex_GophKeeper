package requiredInterfaces

import (
	"GophKeeper/internal/app/entities"
	"context"
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
	SetBinaryDataKey(userID string, dataID string, key string) error
	GetBinaryDataKey(userID string, dataID string) (string, error)
}

// Storage can save and return bank card data as a bytes slice.
// It can, but not have to encrypt your data.
// You have to encrypt it yourself.
// NOTE: dont forget to check if userID matches with a user who tries to get a card.
type Storage interface {
	SaveBankCard(ctx context.Context, userID int, cardData []byte) (id int, err error)
	GetBankCard(ctx context.Context, last4Digits int, ownerID int) (data []byte, dataID int, err error)
	SaveLoginAndPassword(ctx context.Context, ownerID int, login string, password string) (id int, err error)
	GetPasswordByLogin(ctx context.Context, ownerID int, login string) (password string, dataID int, err error)
	SaveBinaryData(ctx context.Context, ownerID int, dataName string, data []byte) (id int, err error)
	GetBinaryData(ctx context.Context, ownerID int, dataName string) (data []byte, dataID int, err error)
	SaveText(ctx context.Context, ownerID int, textName string, text string) (id int, err error)
	GetText(ctx context.Context, ownerID int, textName string) (text []byte, dataID int, err error)
}

// UserManager controls all manipulations with user.
// Such as creation and authentication (by login and password).
type UserManager interface {
	Create(ctx context.Context, user entities.User) (id int, err error)
	Auth(ctx context.Context, user entities.User) (id int, err error)
}

// JWTHelper creates new JWT and validates old ones.
type JWTHelper interface {
	BuildNewJWTString(userID int) (string, error)
	GetUserID(token string) (userID int, err error)
}

// Encryptor have to encrypt and decrypt data using AES GCM.
type Encryptor interface {
	EncryptAESGCM(plaintext []byte, key []byte) ([]byte, error)
	DecryptAESGCM(ciphertext []byte, key []byte) ([]byte, error)
}
