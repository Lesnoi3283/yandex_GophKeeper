package entities

// TextData is a struct for text.
type TextData struct {
	ID       int    `json:"-"`
	OwnerID  int    `json:"-"`
	TextName string `json:"textName"`
	Text     string `json:"text"`
}
