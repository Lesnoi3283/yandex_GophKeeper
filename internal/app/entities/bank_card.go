package entities

type BankCard struct {
	PAN            string `json:"PAN"`
	ExpiresAt      string `json:"expires_at"`
	OwnerLastname  string `json:"owner_lastname"`
	OwnerFirstname string `json:"owner_firstname"`
}
