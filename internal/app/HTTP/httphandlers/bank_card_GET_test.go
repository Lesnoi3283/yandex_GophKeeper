package httphandlers

import (
	"GophKeeper/internal/app/HTTP/middlewares"
	"GophKeeper/internal/app/entities"
	"GophKeeper/internal/app/requiredInterfaces"
	"GophKeeper/internal/app/requiredInterfaces/mocks"
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_handlerHTTP_BankCardGet(t *testing.T) {
	//set data
	url := "/api/bank-card"

	//set logger
	logger := zaptest.NewLogger(t)
	sugar := logger.Sugar()

	type fields struct {
		Storage   func(c *gomock.Controller) requiredInterfaces.Storage
		KeyKeeper func(c *gomock.Controller) requiredInterfaces.KeyKeeper
		Encryptor func(c *gomock.Controller) requiredInterfaces.Encryptor
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
				Storage: func(c *gomock.Controller) requiredInterfaces.Storage {
					st := mocks.NewMockStorage(c)
					st.EXPECT().GetBankCard(gomock.Any(), 1, 1234).Return("encryptedCardData", 100, nil)
					return st
				},
				KeyKeeper: func(c *gomock.Controller) requiredInterfaces.KeyKeeper {
					kk := mocks.NewMockKeyKeeper(c)
					kk.EXPECT().GetBankCardKey("1", "100").Return("encryptionKey", nil)
					return kk
				},
				Encryptor: func(c *gomock.Controller) requiredInterfaces.Encryptor {
					en := mocks.NewMockEncryptor(c)
					buf := bytes.NewBuffer(nil)
					encoder := gob.NewEncoder(buf)
					err := encoder.Encode(entities.BankCard{
						PAN:            "1234567890121234",
						ExpiresAt:      "12/24",
						OwnerLastname:  "IVANOV",
						OwnerFirstname: "IVAN",
					})
					require.NoError(t, err, "error while preparing tests. Cant encode a bank card data")
					en.EXPECT().DecryptAESGCM("encryptedCardData", []byte("encryptionKey")).Return(buf.Bytes(), nil)
					return en
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(`1234`)))
					r = r.WithContext(context.WithValue(r.Context(), middlewares.UserIDContextKey, 1))
					return r
				}(),
			},
			expectedAnswer: []byte(`{"PAN":"1234567890121234","expires_at":"12/24","owner_firstname":"IVAN","owner_lastname":"IVANOV"}`),
			expectedStatus: http.StatusOK,
		},
		{
			name: "Unauthorized request",
			args: args{
				w:   httptest.NewRecorder(),
				req: httptest.NewRequest(http.MethodPost, url, bytes.NewBuffer([]byte{1, 2, 3, 4})),
			},
			expectedAnswer: nil,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "Empty body",
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
			name: "Storage error",
			fields: fields{
				Storage: func(c *gomock.Controller) requiredInterfaces.Storage {
					st := mocks.NewMockStorage(c)
					st.EXPECT().GetBankCard(gomock.Any(), 1, 1234).Return("", 0, fmt.Errorf("storage error"))
					return st
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(`1234`)))
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
				Storage: func(c *gomock.Controller) requiredInterfaces.Storage {
					st := mocks.NewMockStorage(c)
					st.EXPECT().GetBankCard(gomock.Any(), 1, 1234).Return("encryptedCardData", 100, nil)
					return st
				},
				KeyKeeper: func(c *gomock.Controller) requiredInterfaces.KeyKeeper {
					kk := mocks.NewMockKeyKeeper(c)
					kk.EXPECT().GetBankCardKey("1", "100").Return("", fmt.Errorf("key keeper error"))
					return kk
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(`1234`)))
					r = r.WithContext(context.WithValue(r.Context(), middlewares.UserIDContextKey, 1))
					return r
				}(),
			},
			expectedAnswer: nil,
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "Decryption error",
			fields: fields{
				Storage: func(c *gomock.Controller) requiredInterfaces.Storage {
					st := mocks.NewMockStorage(c)
					st.EXPECT().GetBankCard(gomock.Any(), 1, 1234).Return("encryptedCardData", 100, nil)
					return st
				},
				KeyKeeper: func(c *gomock.Controller) requiredInterfaces.KeyKeeper {
					kk := mocks.NewMockKeyKeeper(c)
					kk.EXPECT().GetBankCardKey("1", "100").Return("encryptionKey", nil)
					return kk
				},
				Encryptor: func(c *gomock.Controller) requiredInterfaces.Encryptor {
					en := mocks.NewMockEncryptor(c)
					en.EXPECT().DecryptAESGCM("encryptedCardData", []byte("encryptionKey")).Return(nil, fmt.Errorf("decryption error"))
					return en
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(`1234`)))
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

			h.BankCardGet(tt.args.w, tt.args.req)
			assert.Equal(t, tt.expectedStatus, tt.args.w.Code)
			if tt.expectedAnswer != nil {
				assert.JSONEq(t, string(tt.expectedAnswer), tt.args.w.Body.String())
			}
		})
	}
}
