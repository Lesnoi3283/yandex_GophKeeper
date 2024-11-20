package secureerrors

import "fmt"

var jwtIsNotValid error = fmt.Errorf("JWT is not valid")

func NewErrorJWTIsNotValid() error {
	return jwtIsNotValid
}
