package handlers

import (
	"GophKeeper/internal/app/HTTP/middlewares"
	"GophKeeper/pkg/easylog"
	"GophKeeper/pkg/storages/storageerrors"
	"errors"
	"io"
	"net/http"
	"strconv"
)

func (h *handlerHTTP) GetText(w http.ResponseWriter, r *http.Request) {
	//get userID from ctx
	userID := r.Context().Value(middlewares.UserIDContextKey)
	userIDInt, ok := userID.(int)
	if !ok || userIDInt <= 0 {
		h.Logger.Warnf("unauthenticated request")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	//parse text name from request
	login, err := io.ReadAll(r.Body)
	if err != nil {
		h.Logger.Errorf("cannot read body: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	textNameStr := string(login)
	if len(textNameStr) == 0 {
		h.Logger.Debug("textNameStr is empty")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//get encrypted text
	encryptedText, dataID, err := h.Storage.GetText(r.Context(), userIDInt, textNameStr)
	if errors.Is(err, storageerrors.NewErrNotExists()) {
		h.Logger.Debugf("text not found, err: %v", err)
		w.WriteHeader(http.StatusNotFound)
		return
	} else if err != nil {
		easylog.SecureErrLog("cant get encrypted text", err, h.Logger)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//read encryption key
	key, err := h.KeyKeeper.GetTextDataKey(strconv.Itoa(userIDInt), strconv.Itoa(dataID))
	if err != nil {
		easylog.SecureErrLog("cant get encryption key from key storage", err, h.Logger)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//decrypt
	decryptedText, err := h.Encryptor.DecryptAESGCM(encryptedText, []byte(key))
	if err != nil {
		easylog.SecureErrLog("cant decrypt text", err, h.Logger)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//return encryptedPassword
	w.WriteHeader(http.StatusOK)
	w.Write(decryptedText)
}
