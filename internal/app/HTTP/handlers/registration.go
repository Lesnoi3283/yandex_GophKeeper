package handlers

import (
	"GophKeeper/internal/app/HTTP/middlewares"
	"GophKeeper/internal/app/entities"
	"GophKeeper/pkg/storages/storageerrors"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

// RegisterUser creates a new user in database and return a new JWT.
func (h *handlerHTTP) RegisterUser(w http.ResponseWriter, req *http.Request) {
	//read data
	bytes, err := io.ReadAll(req.Body)
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
	if user.ValidateUser() != nil {
		h.Logger.Warnf("user is not valid: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//CreateUser new user
	user.ID, err = h.UserManager.CreateUser(req.Context(), user)
	if errors.Is(err, storageerrors.NewErrAlreadyExists()) {
		h.Logger.Debugf("user already exists")
		w.WriteHeader(http.StatusConflict)
		return
	} else if err != nil {
		h.Logger.Errorf("cant create user, err: %v", err)
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

	//make a cookie
	cookie := &http.Cookie{
		Name:    middlewares.JWTCookieName,
		Value:   JWTString,
		Expires: time.Now().Add(time.Duration(h.Conf.JWTTimeoutHours) * time.Hour),
	}
	http.SetCookie(w, cookie)

	//return a response
	w.WriteHeader(http.StatusCreated)
}
