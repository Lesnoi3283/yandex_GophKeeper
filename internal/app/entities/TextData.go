package entities

// TextData is a struct for text.
type TextData struct {
	ID       int    `json:"-"`
	OwnerID  int    `json:"-"`
	TextName string `json:"text_name"`
	Text     string `json:"text"`
}
