package httphandlers

import (
	"GophKeeper/internal/app/HTTP/middlewares"
	"GophKeeper/pkg/easylog"
	"io"
	"net/http"
	"strconv"
)

//todo: везде заменить двойное логирование на:
//	if h.Logger.Level() != zap.DebugLevel {
//	} else {
//	}

func (h *handlerHTTP) PasswordGet(w http.ResponseWriter, r *http.Request) {
	//get userID from ctx
	userID := r.Context().Value(middlewares.UserIDContextKey)
	userIDInt, ok := userID.(int)
	if !ok || userIDInt <= 0 {
		h.Logger.Warnf("unauthenticated request")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	//parse data
	login, err := io.ReadAll(r.Body)
	if err != nil {
		h.Logger.Errorf("cannot read body: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	loginStr := string(login)

	if len(loginStr) == 0 {
		h.Logger.Debug("login is empty")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//get login and encryptedPassword
	encryptedPassword, dataID, err := h.Storage.GetPasswordByLogin(r.Context(), userIDInt, loginStr)
	if err != nil {
		easylog.SecureErrLog("cant get password from db", err, h.Logger)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//read encryption key
	key, err := h.KeyKeeper.GetLoginAndPasswordKey(strconv.Itoa(userIDInt), strconv.Itoa(dataID))
	if err != nil {
		h.Logger.Errorf("cant get encryption key from key storage")
		easylog.SecureErrLog("cant get encryption key from key storage", err, h.Logger)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//decrypt
	passwordBytes, err := h.Encryptor.DecryptAESGCM(encryptedPassword, []byte(key))
	if err != nil {
		easylog.SecureErrLog("cant decrypt password", err, h.Logger)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//return encryptedPassword
	w.WriteHeader(http.StatusOK)
	w.Write(passwordBytes)
}
