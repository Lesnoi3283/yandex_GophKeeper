package requiredInterfaces

import (
	"GophKeeper/internal/app/entities"
	"context"
)

//go:generate mockgen -source=required_interfaces.go -destination=./mocks/mocks.go -package=mocks

// KeyKeeper MUST BE a secure key-storage witch follows PCI DSS 4.0.
// This interface can be used to store encryption keys.
type KeyKeeper interface {
	SetKey(dataType string, userID string, dataID string, key string) error
	GetKey(dataType string, userID string, dataID string) (string, error)
	RemoveKey(dataType string, userID string, dataID string) error
}

// Encryptor encrypts and decrypts provided data.
type Encryptor interface {
	Encrypt(key string, data []byte) ([]byte, error)
	Decrypt(key string, data []byte) ([]byte, error)
}

// BankCardStorage can save and return bank card data as a bytes slice.
// It can, but not have to encrypt your data.
// You have to encrypt it yourself. (That`s why Encryptor interface exists).
// NOTE: dont forget to check if userID matches with a user who tries to get a card.
type BankCardStorage interface {
	Save(ctx context.Context, userID int, cardData []byte) (id int, err error)
	Get(ctx context.Context, cardID int) (data []byte, err error)
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
	GetUserID(token string) (userID string, err error)
}

//Todo: хранилища для остальных типов данных (текст, бинарники, логин&пароль)
