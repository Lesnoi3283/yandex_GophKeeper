package httphandlers

import (
	"GophKeeper/internal/app/HTTP/middlewares"
	"GophKeeper/internal/app/entities"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
)

func (h *handlerHTTP) TextDataSave(w http.ResponseWriter, r *http.Request) {
	//get userID from ctx
	userID := r.Context().Value(middlewares.UserIDContextKey)
	userIDInt, ok := userID.(int)
	if !ok || userIDInt <= 0 {
		h.Logger.Warnf("unauthenticated request")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	//parse data
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		h.Logger.Errorf("cannot read body: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
	}

	textData := entities.TextData{}
	err = json.Unmarshal(bodyBytes, &textData)
	if err != nil {
		h.Logger.Warnf("cannot unmarshal body: %s", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	textData.OwnerID = userIDInt
	if len(textData.TextName) == 0 {
		h.Logger.Debug("text name is empty")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	//saving empty text should be possible. If user wants - why not?

	//gen key
	key := make([]byte, 32)
	_, err = rand.Read(key)
	if err != nil {
		h.Logger.Errorf("cannot generate key, err: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//encrypt
	encryptedData, err := h.Encryptor.EncryptAESGCM([]byte(textData.Text), key)
	if err != nil {
		h.Logger.Errorf("cannot encrypt data")
		h.Logger.Debugf("cannot encrypt data, err: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	textData.Text = string(encryptedData)

	//save data
	dataID, err := h.Storage.SaveText(r.Context(), userIDInt, textData.TextName, textData.Text)
	if err != nil {
		h.Logger.Errorf("cannot save text data")
		h.Logger.Debugf("cannot save text data, err: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//save key
	err = h.KeyKeeper.SetTextDataKey(strconv.Itoa(userIDInt), strconv.Itoa(dataID), string(key))
	if err != nil {
		h.Logger.Errorf("cannot save key")
		h.Logger.Debugf("cannot save key, err: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	return
}
