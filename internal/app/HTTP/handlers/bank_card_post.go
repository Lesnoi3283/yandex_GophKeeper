package handlers

import (
	"GophKeeper/internal/app/HTTP/middlewares"
	"GophKeeper/internal/app/entities"
	"GophKeeper/pkg/easylog"
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"encoding/json"
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
		easylog.SecureErrLog("cannot encode bank card", err, h.Logger)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//encrypt
	encryptedData, err := h.Encryptor.EncryptAESGCM(bankCardDataBuf.Bytes(), key)
	if err != nil {
		easylog.SecureErrLog("cannot encrypt bank card", err, h.Logger)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//save data
	lastFourDigits, err := strconv.Atoi(bankCard.PAN[len(bankCard.PAN)-4:])
	dataID, err := h.Storage.SaveBankCard(r.Context(), userIDInt, lastFourDigits, encryptedData)
	if err != nil {
		easylog.SecureErrLog("cannot save bank card", err, h.Logger)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//save key
	err = h.KeyKeeper.SetBankCardKey(strconv.Itoa(userIDInt), strconv.Itoa(dataID), string(key))
	if err != nil {
		easylog.SecureErrLog("cannot save bank card key", err, h.Logger)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	return
}
