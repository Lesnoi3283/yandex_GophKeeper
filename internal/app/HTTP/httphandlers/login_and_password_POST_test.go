package httphandlers

import (
	"GophKeeper/internal/app/HTTP/middlewares"
	"GophKeeper/internal/app/requiredInterfaces"
	"GophKeeper/internal/app/requiredInterfaces/mocks"
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

func Test_handlerHTTP_LoginAndPasswordSave(t *testing.T) {
	//set data
	url := "/api/login-password"

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
					st.EXPECT().SaveLoginAndPassword(gomock.Any(), 1, "example", "encryptedPassword").Return(100, nil)
					return st
				},
				KeyKeeper: func(c *gomock.Controller) requiredInterfaces.KeyKeeper {
					kk := mocks.NewMockKeyKeeper(c)
					kk.EXPECT().SetLoginAndPasswordKey("1", "100", gomock.Any()).Return(nil)
					return kk
				},
				Encryptor: func(c *gomock.Controller) requiredInterfaces.Encryptor {
					e := mocks.NewMockEncryptor(c)
					e.EXPECT().EncryptAESGCM([]byte("12345"), gomock.Any()).Return("encryptedPassword", nil)
					return e
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"login":"example","password":"12345"}`))
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
				req: httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"login":"example","password":"12345"}`)),
			},
			expectedAnswer: nil,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "Empty login",
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"login":"","password":"12345"}`))
					r = r.WithContext(context.WithValue(r.Context(), middlewares.UserIDContextKey, 1))
					return r
				}(),
			},
			expectedAnswer: nil,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Empty password",
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"login":"example","password":""}`))
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
			name: "Encryptor error",
			fields: fields{
				Encryptor: func(c *gomock.Controller) requiredInterfaces.Encryptor {
					e := mocks.NewMockEncryptor(c)
					e.EXPECT().EncryptAESGCM(gomock.Any(), gomock.Any()).Return("", fmt.Errorf("some test error"))
					return e
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"login":"example","password":"12345"}`))
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
				Storage: func(c *gomock.Controller) requiredInterfaces.Storage {
					st := mocks.NewMockStorage(c)
					st.EXPECT().SaveLoginAndPassword(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(0, fmt.Errorf("some test storage error"))
					return st
				},
				KeyKeeper: nil,
				Encryptor: func(c *gomock.Controller) requiredInterfaces.Encryptor {
					e := mocks.NewMockEncryptor(c)
					e.EXPECT().EncryptAESGCM(gomock.Any(), gomock.Any()).Return("encryptedPassword", nil)
					return e
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"login":"example","password":"12345"}`))
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
					st.EXPECT().SaveLoginAndPassword(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(100, nil)
					return st
				},
				KeyKeeper: func(c *gomock.Controller) requiredInterfaces.KeyKeeper {
					kk := mocks.NewMockKeyKeeper(c)
					kk.EXPECT().SetLoginAndPasswordKey(gomock.Any(), gomock.Any(), gomock.Any()).Return(fmt.Errorf("some keykeeper error"))
					return kk
				},
				Encryptor: func(c *gomock.Controller) requiredInterfaces.Encryptor {
					e := mocks.NewMockEncryptor(c)
					e.EXPECT().EncryptAESGCM(gomock.Any(), gomock.Any()).Return("encryptedPassword", nil)
					return e
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"login":"example","password":"12345"}`))
					r = r.WithContext(context.WithValue(r.Context(), middlewares.UserIDContextKey, 1))
					return r
				}()},
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

			h.LoginAndPasswordSave(tt.args.w, tt.args.req)
			assert.Equal(t, tt.expectedStatus, tt.args.w.Code)
			assert.Equal(t, tt.expectedAnswer, tt.args.w.Body.Bytes())
		})
	}
}
