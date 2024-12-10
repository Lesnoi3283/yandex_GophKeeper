package secure

import (
	"GophKeeper/pkg/secure/secureerrors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"time"
)

// Claims is a jwt.RegisteredClaims struct with custom field "Claims.UserID".
type Claims struct {
	jwt.RegisteredClaims
	UserID int
}

// JWTHelper helps you to work with JWT tokens. It allows you to create and parse tokens.
type JWTHelper struct {
	Claims    Claims
	secretKey string
	TokenExp  time.Duration
}

// For future updates - don`t forget to add a mutex if your new logic will try to change JWTHelper`s fields.

// NewJWTHelper creates a new JWTHelper.
func NewJWTHelper(secretKey string, tokenTimeoutHours int) *JWTHelper {
	return &JWTHelper{
		secretKey: secretKey,
		TokenExp:  time.Duration(tokenTimeoutHours) * time.Hour,
	}
}

// BuildNewJWTString returns new JWT string with userID inside.
func (j *JWTHelper) BuildNewJWTString(userID int) (string, error) {

	claims := Claims{RegisteredClaims: jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.TokenExp)),
	},
		UserID: userID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	stringToken, err := token.SignedString([]byte(j.secretKey))
	if err != nil {
		return "", fmt.Errorf("building new jwt: %w", err)
	}

	return stringToken, nil
}

// GetUserID parses JWT and returns a userID from it.
func (j *JWTHelper) GetUserID(tokenString string) (int, error) {

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims,
		func(t *jwt.Token) (interface{}, error) {
			return []byte(j.secretKey), nil
		})
	if err != nil {
		return -1, fmt.Errorf("parsing token: %w", err)
	}

	if !token.Valid {
		return -1, secureerrors.NewErrorJWTIsNotValid()
	}

	return claims.UserID, nil
}
