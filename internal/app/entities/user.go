package entities

import "errors"

const (
	MinLoginLen    = 5
	MinPasswordLen = 5
)

// User is struct for a user. Warning - json.Marshal will ignore this field:
// ID.
type User struct {
	ID       int    `json:"-"`
	Login    string `json:"login"`
	Password string `json:"password"`
}

// ValidateUser checks if login and password are empty or too short.
// Returns an error if one or both of them are empty.
// Errors are secure-safe, they don`t contain any user data.
func (u *User) ValidateUser() error {
	if len(u.Password) < MinPasswordLen {
		if len(u.Password) == 0 {
			return errors.New("password is empty")
		} else {
			return errors.New("password is too short")
		}
	}
	if len(u.Login) < MinLoginLen {
		if len(u.Login) == 0 {
			return errors.New("login is empty")
		} else {
			return errors.New("login is too short")
		}
	}
	return nil
}
