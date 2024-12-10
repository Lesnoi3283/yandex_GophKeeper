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

func Test_handlerHTTP_PasswordGet(t *testing.T) {
	//set data
	url := "/api/password"

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
					st.EXPECT().GetPasswordByLogin(gomock.Any(), 1, "example").Return("encryptedPassword", 100, nil)
					return st
				},
				KeyKeeper: func(c *gomock.Controller) required_interfaces.KeyKeeper {
					kk := mocks.NewMockKeyKeeper(c)
					kk.EXPECT().GetLoginAndPasswordKey("1", "100").Return("encryptionKey", nil)
					return kk
				},
				Encryptor: func(c *gomock.Controller) required_interfaces.Encryptor {
					e := mocks.NewMockEncryptor(c)
					e.EXPECT().DecryptAESGCM("encryptedPassword", []byte("encryptionKey")).Return([]byte("decryptedPassword"), nil)
					return e
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString("example"))
					r = r.WithContext(context.WithValue(r.Context(), middlewares.UserIDContextKey, 1))
					return r
				}(),
			},
			expectedAnswer: []byte("decryptedPassword"),
			expectedStatus: http.StatusOK,
		},
		{
			name: "Unauthorized request",
			args: args{
				w:   httptest.NewRecorder(),
				req: httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString("example")),
			},
			expectedAnswer: nil,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "Empty login",
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(""))
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
				Storage: func(c *gomock.Controller) required_interfaces.Storage {
					st := mocks.NewMockStorage(c)
					st.EXPECT().GetPasswordByLogin(gomock.Any(), 1, "example").Return("", 0, fmt.Errorf("some storage error"))
					return st
				},
				KeyKeeper: nil,
			},
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString("example"))
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
					st.EXPECT().GetPasswordByLogin(gomock.Any(), 1, "example").Return("encryptedPassword", 100, nil)
					return st
				},
				KeyKeeper: func(c *gomock.Controller) required_interfaces.KeyKeeper {
					kk := mocks.NewMockKeyKeeper(c)
					kk.EXPECT().GetLoginAndPasswordKey("1", "100").Return("", fmt.Errorf("key keeper error"))
					return kk
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString("example"))
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
				Storage: func(c *gomock.Controller) required_interfaces.Storage {
					st := mocks.NewMockStorage(c)
					st.EXPECT().GetPasswordByLogin(gomock.Any(), 1, "example").Return("encryptedPassword", 100, nil)
					return st
				},
				KeyKeeper: func(c *gomock.Controller) required_interfaces.KeyKeeper {
					kk := mocks.NewMockKeyKeeper(c)
					kk.EXPECT().GetLoginAndPasswordKey("1", "100").Return("encryptionKey", nil)
					return kk
				},
				Encryptor: func(c *gomock.Controller) required_interfaces.Encryptor {
					e := mocks.NewMockEncryptor(c)
					e.EXPECT().DecryptAESGCM(gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("some test error"))
					return e
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString("example"))
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

			h.PasswordGet(tt.args.w, tt.args.req)
			assert.Equal(t, tt.expectedStatus, tt.args.w.Code)
			assert.Equal(t, tt.expectedAnswer, tt.args.w.Body.Bytes())
		})
	}
}
