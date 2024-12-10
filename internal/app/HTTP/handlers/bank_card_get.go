package handlers

import (
	"GophKeeper/internal/app/HTTP/middlewares"
	"GophKeeper/internal/app/entities"
	"GophKeeper/internal/app/required_interfaces"
	"GophKeeper/pkg/easylog"
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
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

	//get encrypted data
	encryptedCardData, dataID, err := h.Storage.GetBankCard(r.Context(), userIDInt, lastFourDigitsInt)
	if err != nil {
		easylog.SecureErrLog("cannot get encrypted bank card", err, h.Logger)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	bankCardBytes, err := decryptCard(encryptedCardData, userIDInt, dataID, h.KeyKeeper, h.Encryptor)
	if err != nil {
		easylog.SecureErrLog("cannot decrypt card data", err, h.Logger)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//decode
	reader := bytes.NewReader(bankCardBytes)
	decoder := gob.NewDecoder(reader)
	bankCard := &entities.BankCard{}
	err = decoder.Decode(bankCard)
	if err != nil {
		easylog.SecureErrLog("cannot decode bank card", err, h.Logger)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//decode to JSON
	bankCardJSON, err := json.Marshal(bankCard)
	if err != nil {
		easylog.SecureErrLog("cannot marshal bank card", err, h.Logger)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//return encryptedPassword
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(bankCardJSON)
}

func decryptCard(encryptedCardData string, userID int, dataID int, keyKeeper required_interfaces.KeyKeeper, encryptor required_interfaces.Encryptor) ([]byte, error) {
	//read encryption key
	key, err := keyKeeper.GetBankCardKey(strconv.Itoa(userID), strconv.Itoa(dataID))
	if err != nil {
		return nil, fmt.Errorf("cant get bank card key: %w", err)
	}

	//decrypt
	bankCardBytes, err := encryptor.DecryptAESGCM(encryptedCardData, []byte(key))
	if err != nil {
		return nil, fmt.Errorf("cant decrypt card: %w", err)
	}
	return bankCardBytes, nil
}
