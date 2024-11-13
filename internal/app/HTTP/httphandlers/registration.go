package httphandlers

import (
	"GophKeeper/internal/app/entities"
	"GophKeeper/pkg/secure"
	"encoding/json"
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
	}

	user := entities.User{}
	err = json.Unmarshal(bytes, &user)
	if err != nil {
		h.Logger.Warnf("cant unmrushal request, err: %v", err)
		w.WriteHeader(http.StatusBadRequest)
	}
	if len(user.Password) == 0 {
		h.Logger.Debugf("password is empty")
		w.WriteHeader(http.StatusBadRequest)
	}
	if len(user.Login) == 0 {
		h.Logger.Debugf("login is empty")
		w.WriteHeader(http.StatusBadRequest)
	}

	//hash password)
	user.PasswordHash, user.PasswordSalt, err = secure.HashPassword([]byte(user.Password))
	if err != nil {
		h.Logger.Errorf("cant hash password, err: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}

	//Create new user
	user.ID, err = h.UserManager.Create(req.Context(), user)
	if err != nil {
		h.Logger.Errorf("cant create user, err: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}

	//create JWT string
	jwtResp := struct {
		JWT string `json:"jwt"`
	}{}
	jwtResp.JWT, err = h.JWTHelper.BuildNewJWTString(user.ID)
	if err != nil {
		h.Logger.Errorf("cant create JWT, err: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}

	//return a response
	JWTJson, err := json.Marshal(jwtResp)
	if err != nil {
		h.Logger.Errorf("cant marshal JWT, err: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	w.Write(JWTJson)
}
