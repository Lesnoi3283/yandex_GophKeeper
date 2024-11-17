package httphandlers

import (
	"GophKeeper/internal/app/HTTP/middlewares"
	"GophKeeper/internal/app/entities"
	"GophKeeper/pkg/secure"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
)

func (h *handlerHTTP) LoginAndPasswordSave(w http.ResponseWriter, r *http.Request) {
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

	loginAndPassword := entities.LoginAndPassword{}
	err = json.Unmarshal(bodyBytes, &loginAndPassword)
	if err != nil {
		h.Logger.Warnf("cannot unmarshal body: %s", err)
		w.WriteHeader(http.StatusBadRequest)
	}
	if len(loginAndPassword.Login) == 0 {
		h.Logger.Debug("login is empty")
		w.WriteHeader(http.StatusBadRequest)
	}
	if len(loginAndPassword.Password) == 0 {
		h.Logger.Debug("password is empty")
		w.WriteHeader(http.StatusBadRequest)
	}

	//encrypt data
	//var gobBuffer bytes.Buffer
	//encoder := gob.NewEncoder(&gobBuffer)
	//err = encoder.Encode(loginAndPassword)
	//if err != nil {
	//	h.Logger.Error("cannot encode body")
	//	h.Logger.Debugf("cannot encode body, err: %v", err)
	//	w.WriteHeader(http.StatusInternalServerError)
	//	return
	//}
	//dataBytes := gobBuffer.Bytes()

	//gen key
	key := make([]byte, 32)
	_, err = rand.Read(key)
	if err != nil {
		h.Logger.Errorf("cannot generate key, err: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	encryptedData, err := secure.EncryptAESGCM([]byte(loginAndPassword.Password), key)
	if err != nil {
		h.Logger.Errorf("cannot encrypt data")
		h.Logger.Debugf("cannot encrypt data, err: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
	loginAndPassword.Password = string(encryptedData)

	//save data
	_, err = h.Storage.SaveLoginAndPassword(r.Context(), userIDInt, loginAndPassword)
	if err != nil {
		h.Logger.Errorf("cannot save login and password")
		h.Logger.Debugf("cannot save login and password, err: %v", err)
	}

	w.WriteHeader(http.StatusCreated)
	return
}

//TODO: tests required!
