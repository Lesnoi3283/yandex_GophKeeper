package httphandlers

import (
	"GophKeeper/internal/app/HTTP/middlewares"
	"GophKeeper/internal/app/entities"
	"bytes"
	"encoding/gob"
	"encoding/json"
	"go.uber.org/zap"
	"io"
	"net/http"
	"strconv"
)

func (h *handlerHTTP) BankCardGet(w http.ResponseWriter, r *http.Request) {
	//get userID from ctx
	userID := r.Context().Value(middlewares.UserIDContextKey)
	userIDInt, ok := userID.(int)
	if !ok || userIDInt <= 0 {
		h.Logger.Warnf("unauthenticated request")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	//parse data
	lastFourDigits, err := io.ReadAll(r.Body)
	if err != nil {
		h.Logger.Errorf("cannot read body: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if len(lastFourDigits) == 0 {
		h.Logger.Debug("no last four digits found")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	lastFourDigitsInt, err := strconv.Atoi(string(lastFourDigits))
	if err != nil {
		h.Logger.Errorf("cannot parse last four digits, err: %s", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//get login and encryptedPassword
	encryptedCardData, dataID, err := h.Storage.GetBankCard(r.Context(), userIDInt, lastFourDigitsInt)
	if err != nil {
		if h.Logger.Level() != zap.DebugLevel {
			h.Logger.Errorf("cannot get encrypted card data")
		} else {
			h.Logger.Debugf("cannot get encrypted card data, err: %v", err)
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//read encryption key
	key, err := h.KeyKeeper.GetBankCardKey(strconv.Itoa(userIDInt), strconv.Itoa(dataID))
	if err != nil {
		if h.Logger.Level() != zap.DebugLevel {
			h.Logger.Errorf("cant get encryption key from key storage")
		} else {
			h.Logger.Debugf("cant get encryption key from key storage, err: %v", err)
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//decrypt
	bankCardBytes, err := h.Encryptor.DecryptAESGCM(encryptedCardData, []byte(key))
	if err != nil {
		if h.Logger.Level() != zap.DebugLevel {
			h.Logger.Errorf("cannot decrypt password")
		} else {
			h.Logger.Debugf("cannot decrypt password, err: %v", err)
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//decode
	reader := bytes.NewReader(bankCardBytes)
	decoder := gob.NewDecoder(reader)
	bankCard := &entities.BankCard{}
	err = decoder.Decode(bankCard)
	if err != nil {
		if h.Logger.Level() != zap.DebugLevel {
			h.Logger.Errorf("cannot decode bank card")
		} else {
			h.Logger.Debugf("cannot decode bank card, err: %v", err)
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//decode to JSON
	bankCardJSON, err := json.Marshal(bankCard)
	if err != nil {
		if h.Logger.Level() != zap.DebugLevel {
			h.Logger.Errorf("cannot marshal bank card")
		} else {
			h.Logger.Debugf("cannot marshal bank card, err: %v", err)
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//return encryptedPassword
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(bankCardJSON)
}
