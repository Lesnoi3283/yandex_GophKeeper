package entities

type LoginAndPassword struct {
	ID       int    `json:"-"`
	OwnerID  int    `json:"-"`
	Login    string `json:"login"`
	Password string `json:"password"`
}
