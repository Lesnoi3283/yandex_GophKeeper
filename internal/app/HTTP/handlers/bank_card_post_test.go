package handlers

import (
	"GophKeeper/internal/app/HTTP/middlewares"
	"GophKeeper/internal/app/required_interfaces"
	"GophKeeper/internal/app/required_interfaces/mocks"
	"bytes"
	"context"
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_handlerHTTP_BankCardSave(t *testing.T) {
	//set data
	url := "/api/bank-card"

	//set logger
	logger := zaptest.NewLogger(t)
	sugar := logger.Sugar()

	type fields struct {
		Storage   func(c *gomock.Controller) required_interfaces.Storage
		KeyKeeper func(c *gomock.Controller) required_interfaces.KeyKeeper
		Encryptor func(c *gomock.Controller) required_interfaces.Encryptor
	}
	type args struct {
		w   *httptest.ResponseRecorder
		req *http.Request
	}
	tests := []struct {
		name           string
		fields         fields
		args           args
		expectedAnswer []byte
		expectedStatus int
	}{
		{
			name: "Ok",
			fields: fields{
				Storage: func(c *gomock.Controller) required_interfaces.Storage {
					st := mocks.NewMockStorage(c)
					st.EXPECT().SaveBankCard(gomock.Any(), 1, 1234, gomock.Any()).Return(100, nil)
					return st
				},
				KeyKeeper: func(c *gomock.Controller) required_interfaces.KeyKeeper {
					kk := mocks.NewMockKeyKeeper(c)
					kk.EXPECT().SetBankCardKey("1", "100", gomock.Any()).Return(nil)
					return kk
				},
				Encryptor: func(c *gomock.Controller) required_interfaces.Encryptor {
					en := mocks.NewMockEncryptor(c)
					en.EXPECT().EncryptAESGCM(gomock.Any(), gomock.Any()).Return("encryptedData", nil)
					return en
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"PAN":"1234567890121234","expires_at":"12/24","owner_firstname":"IVAN","owner_lastname":"IVANOV"}`))
					r = r.WithContext(context.WithValue(r.Context(), middlewares.UserIDContextKey, 1))
					return r
				}(),
			},
			expectedAnswer: nil,
			expectedStatus: http.StatusCreated,
		},
		{
			name: "Unauthorized request",
			args: args{
				w:   httptest.NewRecorder(),
				req: httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"PAN":"1234567890121234","expires_at":"12/24","owner_firstname":"IVAN","owner_lastname":"IVANOV"}`)),
			},
			expectedAnswer: nil,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "Empty PAN",
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"PAN":"","expires_at":"12/24","owner_firstname":"IVAN","owner_lastname":"IVANOV"}`))
					r = r.WithContext(context.WithValue(r.Context(), middlewares.UserIDContextKey, 1))
					return r
				}(),
			},
			expectedAnswer: nil,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Empty ExpiresAt",
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"PAN":"1234567890121234","expires_at":"","owner_firstname":"IVAN","owner_lastname":"IVANOV"}`))
					r = r.WithContext(context.WithValue(r.Context(), middlewares.UserIDContextKey, 1))
					return r
				}(),
			},
			expectedAnswer: nil,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Empty OwnerFirstname",
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"PAN":"1234567890121234","expires_at":"12/24","owner_firstname":"","owner_lastname":"IVANOV"}`))
					r = r.WithContext(context.WithValue(r.Context(), middlewares.UserIDContextKey, 1))
					return r
				}(),
			},
			expectedAnswer: nil,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Empty OwnerLastname",
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"PAN":"1234567890121234","expires_at":"12/24","owner_firstname":"IVAN","owner_lastname":""}`))
					r = r.WithContext(context.WithValue(r.Context(), middlewares.UserIDContextKey, 1))
					return r
				}(),
			},
			expectedAnswer: nil,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Empty JSON",
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{}`))
					r = r.WithContext(context.WithValue(r.Context(), middlewares.UserIDContextKey, 1))
					return r
				}(),
			},
			expectedAnswer: nil,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Empty request",
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, nil)
					r = r.WithContext(context.WithValue(r.Context(), middlewares.UserIDContextKey, 1))
					return r
				}(),
			},
			expectedAnswer: nil,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Encryption error",
			fields: fields{
				Encryptor: func(c *gomock.Controller) required_interfaces.Encryptor {
					en := mocks.NewMockEncryptor(c)
					en.EXPECT().EncryptAESGCM(gomock.Any(), gomock.Any()).Return("", fmt.Errorf("encryption error"))
					return en
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"PAN":"1234567890121234","expires_at":"12/24","owner_firstname":"IVAN","owner_lastname":"IVANOV"}`))
					r = r.WithContext(context.WithValue(r.Context(), middlewares.UserIDContextKey, 1))
					return r
				}(),
			},
			expectedAnswer: nil,
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "Storage error",
			fields: fields{
				Storage: func(c *gomock.Controller) required_interfaces.Storage {
					st := mocks.NewMockStorage(c)
					st.EXPECT().SaveBankCard(gomock.Any(), 1, 1234, gomock.Any()).Return(0, fmt.Errorf("storage error"))
					return st
				},
				Encryptor: func(c *gomock.Controller) required_interfaces.Encryptor {
					en := mocks.NewMockEncryptor(c)
					en.EXPECT().EncryptAESGCM(gomock.Any(), gomock.Any()).Return("encryptedData", nil)
					return en
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"PAN":"1234567890121234","expires_at":"12/24","owner_firstname":"IVAN","owner_lastname":"IVANOV"}`))
					r = r.WithContext(context.WithValue(r.Context(), middlewares.UserIDContextKey, 1))
					return r
				}(),
			},
			expectedAnswer: nil,
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "Key keeper error",
			fields: fields{
				Storage: func(c *gomock.Controller) required_interfaces.Storage {
					st := mocks.NewMockStorage(c)
					st.EXPECT().SaveBankCard(gomock.Any(), 1, 1234, gomock.Any()).Return(100, nil)
					return st
				},
				KeyKeeper: func(c *gomock.Controller) required_interfaces.KeyKeeper {
					kk := mocks.NewMockKeyKeeper(c)
					kk.EXPECT().SetBankCardKey("1", "100", gomock.Any()).Return(fmt.Errorf("key keeper error"))
					return kk
				},
				Encryptor: func(c *gomock.Controller) required_interfaces.Encryptor {
					en := mocks.NewMockEncryptor(c)
					en.EXPECT().EncryptAESGCM(gomock.Any(), gomock.Any()).Return("encryptedData", nil)
					return en
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"PAN":"1234567890121234","expires_at":"12/24","owner_firstname":"IVAN","owner_lastname":"IVANOV"}`))
					r = r.WithContext(context.WithValue(r.Context(), middlewares.UserIDContextKey, 1))
					return r
				}(),
			},
			expectedAnswer: nil,
			expectedStatus: http.StatusInternalServerError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &handlerHTTP{
				Logger: sugar,
			}

			//set mocks
			c := gomock.NewController(t)
			if tt.fields.Storage != nil {
				h.Storage = tt.fields.Storage(c)
			}
			if tt.fields.KeyKeeper != nil {
				h.KeyKeeper = tt.fields.KeyKeeper(c)
			}
			if tt.fields.Encryptor != nil {
				h.Encryptor = tt.fields.Encryptor(c)
			}

			h.BankCardSave(tt.args.w, tt.args.req)
			assert.Equal(t, tt.expectedStatus, tt.args.w.Code)
			assert.Equal(t, tt.expectedAnswer, tt.args.w.Body.Bytes())
		})
	}
}
