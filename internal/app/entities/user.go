package entities

// User is struct for a user. Warning - json.Marshal will ignore this fields:
// ID, PasswordHash, PasswordSalt.
type User struct {
	ID           int    `json:"-"`
	Login        string `json:"login"`
	Password     string `json:"password"`
	PasswordHash string `json:"-"`
	PasswordSalt []byte `json:"-"`
}
