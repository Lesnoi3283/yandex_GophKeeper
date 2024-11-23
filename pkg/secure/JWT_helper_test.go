package secure

import (
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestJWTHelper_Ok(t *testing.T) {
	//prepare data
	secretKey := "secret"
	timeOutHours := 1
	userID := 121

	//create helper
	helper := NewJWTHelper(secretKey, timeOutHours)

	//test

	//build jwt
	jwtString, err := helper.BuildNewJWTString(userID)
	require.NoError(t, err, "cant build a JWT string")

	//get userID
	userIDGot, err := helper.GetUserID(jwtString)
	assert.NoError(t, err, "cant get userID from JWT string")
	assert.Equal(t, userID, userIDGot, "wrong userID")

}

func TestJWTHelper_Timeout(t *testing.T) {
	//prepare data
	secretKey := "secret"
	timeOutHours := 0
	userID := 121

	//create helper
	helper := NewJWTHelper(secretKey, timeOutHours)

	//test

	//build jwt
	jwtString, err := helper.BuildNewJWTString(userID)
	require.NoError(t, err, "cant build a JWT string")

	//get userID
	userIDGot, err := helper.GetUserID(jwtString)
	assert.ErrorIs(t, err, jwt.ErrTokenExpired)
	assert.Equal(t, -1, userIDGot, "userID have to be -1 if token expired")

}
