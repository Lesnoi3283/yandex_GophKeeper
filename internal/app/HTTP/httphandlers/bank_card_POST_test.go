package httphandlers

import (
	"GophKeeper/internal/app/requiredInterfaces"
	"net/http"
	"testing"
)

func Test_handlerHTTP_BankCardSave(t *testing.T) {
	type fields struct {
		Logger      *zap.SugaredLogger
		Storage     requiredInterfaces.Storage
		UserManager requiredInterfaces.UserManager
		JWTHelper   requiredInterfaces.JWTHelper
		KeyKeeper   requiredInterfaces.KeyKeeper
		Encryptor   requiredInterfaces.Encryptor
	}
	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &handlerHTTP{
				Logger:      tt.fields.Logger,
				Storage:     tt.fields.Storage,
				UserManager: tt.fields.UserManager,
				JWTHelper:   tt.fields.JWTHelper,
				KeyKeeper:   tt.fields.KeyKeeper,
				Encryptor:   tt.fields.Encryptor,
			}
			h.BankCardSave(tt.args.w, tt.args.r)
		})
	}
}