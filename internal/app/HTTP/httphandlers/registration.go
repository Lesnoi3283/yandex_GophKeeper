package httphandlers

import (
	"GophKeeper/internal/app/entities"
	"GophKeeper/pkg/secure"
	"GophKeeper/pkg/storages/storageerrors"
	"encoding/json"
	"errors"
	"io"
	"net/http"
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

	//hash password
	user.PasswordHash, user.PasswordSalt, err = secure.HashPassword([]byte(user.Password))
	if err != nil {
		h.Logger.Errorf("cant hash password, err: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//Create new user
	user.ID, err = h.UserManager.Create(req.Context(), user)
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

	//return a response
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(JWTString))
}
