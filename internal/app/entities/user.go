package entities

type User struct {
	ID           int    `json:"id"`
	Login        string `json:"login"`
	Password     string `json:"password"`
	PasswordHash string `json:"-"`
	PasswordSalt []byte `json:"-"`
}
