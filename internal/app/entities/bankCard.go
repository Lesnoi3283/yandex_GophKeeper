package entities

type BankCard struct {
	PAN            string `json:"PAN"`
	ExpiresAt      string `json:"ExpiresAt"`
	OwnerLastname  string `json:"OwnerLastname"`
	OwnerFirstname string `json:"OwnerFirstname"`
}
