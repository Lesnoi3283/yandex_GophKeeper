package httphandlers

import (
	"GophKeeper/internal/app/HTTP/middlewares"
	"GophKeeper/internal/app/entities"
	"GophKeeper/pkg/storages/storageerrors"
	"encoding/json"
	"errors"
	"go.uber.org/zap"
	"io"
	"net/http"
	"time"
)

func (h *handlerHTTP) Login(w http.ResponseWriter, r *http.Request) {
	//read data
	bytes, err := io.ReadAll(r.Body)
	if err != nil {
		h.Logger.Debugf("cant read request body, err: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	user := entities.User{}
	err = json.Unmarshal(bytes, &user)
	if err != nil {
		h.Logger.Warnf("cant unmrushal request, err: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if len(user.Password) == 0 {
		h.Logger.Debugf("password is empty")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if len(user.Login) == 0 {
		h.Logger.Debugf("login is empty")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//Login
	user.ID, err = h.UserManager.AuthUser(r.Context(), user)
	if errors.Is(err, storageerrors.NewErrNotExists()) {
		h.Logger.Debugf("user not exists, err: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	} else if err != nil {
		if h.Logger.Level() != zap.DebugLevel {
			h.Logger.Errorf("cant auth")
		} else {
			h.Logger.Debugf("cant auth, err: %v", err)
		}

		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//create JWT string
	JWTString, err := h.JWTHelper.BuildNewJWTString(user.ID)
	if err != nil {
		h.Logger.Errorf("cant create JWT, err: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	cookie := &http.Cookie{
		Name:    middlewares.JWTCookieName,
		Value:   JWTString,
		Expires: time.Now().Add(time.Duration(h.Conf.JWTTimeoutHours) * time.Hour),
	}
	http.SetCookie(w, cookie)

	//return a response
	w.WriteHeader(http.StatusOK)
}
