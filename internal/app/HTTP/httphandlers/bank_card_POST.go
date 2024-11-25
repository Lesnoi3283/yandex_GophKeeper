package httphandlers

import (
	"GophKeeper/internal/app/HTTP/middlewares"
	"GophKeeper/internal/app/entities"
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"encoding/json"
	"go.uber.org/zap"
	"io"
	"net/http"
	"strconv"
)

func (h *handlerHTTP) BankCardSave(w http.ResponseWriter, r *http.Request) {
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
		return
	}

	bankCard := entities.BankCard{}
	err = json.Unmarshal(bodyBytes, &bankCard)
	if err != nil {
		h.Logger.Warnf("cannot unmarshal body: %s", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if len(bankCard.PAN) == 0 {
		h.Logger.Debug("PAN is empty")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if len(bankCard.ExpiresAt) == 0 {
		h.Logger.Debug("ExpiresAT is empty")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if len(bankCard.OwnerFirstname) == 0 {
		h.Logger.Debug("OwnerFirstName is empty")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if len(bankCard.OwnerLastname) == 0 {
		h.Logger.Debug("OwnerLastName is empty")
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

	//Marshal to gob
	var bankCardDataBuf bytes.Buffer
	encoder := gob.NewEncoder(&bankCardDataBuf)
	err = encoder.Encode(bankCard)
	if err != nil {
		if h.Logger.Level() != zap.DebugLevel {
			h.Logger.Errorf("cannot encode bank card")
		} else {
			h.Logger.Debugf("cannot encode bank card, err: %v", err)
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//encrypt
	encryptedData, err := h.Encryptor.EncryptAESGCM(bankCardDataBuf.Bytes(), key)
	if err != nil {
		if h.Logger.Level() != zap.DebugLevel {
			h.Logger.Errorf("cannot encrypt data")
		} else {
			h.Logger.Debugf("cannot encrypt data, err: %v", err)
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//save data
	lastFourDigits, err := strconv.Atoi(bankCard.PAN[len(bankCard.PAN)-4:])
	dataID, err := h.Storage.SaveBankCard(r.Context(), userIDInt, lastFourDigits, encryptedData)
	if err != nil {
		if h.Logger.Level() != zap.DebugLevel {
			h.Logger.Errorf("cannot save bank card")
		} else {
			h.Logger.Debugf("cannot save bank card, err: %v", err)
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//save key
	err = h.KeyKeeper.SetBankCardKey(strconv.Itoa(userIDInt), strconv.Itoa(dataID), string(key))
	if err != nil {
		if h.Logger.Level() != zap.DebugLevel {
			h.Logger.Errorf("cannot save key")
		} else {
			h.Logger.Debugf("cannot save key, err: %v", err)
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	return
}
