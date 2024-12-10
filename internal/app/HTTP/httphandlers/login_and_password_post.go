package httphandlers

import (
	"GophKeeper/internal/app/HTTP/middlewares"
	"GophKeeper/internal/app/entities"
	"GophKeeper/pkg/easylog"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
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
		return
	}
	if len(loginAndPassword.Login) == 0 {
		h.Logger.Debug("login is empty")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if len(loginAndPassword.Password) == 0 {
		h.Logger.Debug("password is empty")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//gen key
	key := make([]byte, 32)
	_, err = rand.Read(key)
	if err != nil {
		h.Logger.Errorf("cannot generate key, err: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//encrypt
	encryptedData, err := h.Encryptor.EncryptAESGCM([]byte(loginAndPassword.Password), key)
	if err != nil {
		easylog.SecureErrLog("cant encrypt login and password", err, h.Logger)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	loginAndPassword.Password = string(encryptedData)

	//save data
	dataID, err := h.Storage.SaveLoginAndPassword(r.Context(), userIDInt, loginAndPassword.Login, loginAndPassword.Password)
	if err != nil {
		easylog.SecureErrLog("cant save login and password", err, h.Logger)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//save key
	err = h.KeyKeeper.SetLoginAndPasswordKey(strconv.Itoa(userIDInt), strconv.Itoa(dataID), string(key))
	if err != nil {
		easylog.SecureErrLog("cant save login and password key", err, h.Logger)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	return
}
