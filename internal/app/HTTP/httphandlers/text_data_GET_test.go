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

func Test_handlerHTTP_TextDataGet(t *testing.T) {
	//set data
	url := "/api/text"

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
					st.EXPECT().GetText(gomock.Any(), 1, "SomeTextName").Return([]byte("encryptedText"), 100, nil)
					return st
				},
				KeyKeeper: func(c *gomock.Controller) requiredInterfaces.KeyKeeper {
					kk := mocks.NewMockKeyKeeper(c)
					kk.EXPECT().GetTextDataKey("1", "100").Return("encryptionKey", nil)
					return kk
				},
				Encryptor: func(c *gomock.Controller) requiredInterfaces.Encryptor {
					en := mocks.NewMockEncryptor(c)
					en.EXPECT().DecryptAESGCM([]byte("encryptedText"), []byte("encryptionKey")).Return([]byte("decryptedText"), nil)
					return en
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString("SomeTextName"))
					r = r.WithContext(context.WithValue(r.Context(), middlewares.UserIDContextKey, 1))
					return r
				}(),
			},
			expectedAnswer: []byte("decryptedText"),
			expectedStatus: http.StatusOK,
		},
		{
			name: "Unauthorized request",
			args: args{
				w:   httptest.NewRecorder(),
				req: httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString("SomeTextName")),
			},
			expectedAnswer: nil,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "Empty text name",
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
				Storage: func(c *gomock.Controller) requiredInterfaces.Storage {
					st := mocks.NewMockStorage(c)
					st.EXPECT().GetText(gomock.Any(), 1, "SomeTextName").Return(nil, 0, fmt.Errorf("storage error"))
					return st
				},
				KeyKeeper: nil,
				Encryptor: nil,
			},
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString("SomeTextName"))
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
					st.EXPECT().GetText(gomock.Any(), 1, "SomeTextName").Return([]byte("encryptedText"), 100, nil)
					return st
				},
				KeyKeeper: func(c *gomock.Controller) requiredInterfaces.KeyKeeper {
					kk := mocks.NewMockKeyKeeper(c)
					kk.EXPECT().GetTextDataKey("1", "100").Return("", fmt.Errorf("key keeper error"))
					return kk
				},
				Encryptor: nil,
			},
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString("SomeTextName"))
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
					st.EXPECT().GetText(gomock.Any(), 1, "SomeTextName").Return([]byte("encryptedText"), 100, nil)
					return st
				},
				KeyKeeper: func(c *gomock.Controller) requiredInterfaces.KeyKeeper {
					kk := mocks.NewMockKeyKeeper(c)
					kk.EXPECT().GetTextDataKey("1", "100").Return("encryptionKey", nil)
					return kk
				},
				Encryptor: func(c *gomock.Controller) requiredInterfaces.Encryptor {
					en := mocks.NewMockEncryptor(c)
					en.EXPECT().DecryptAESGCM([]byte("encryptedText"), []byte("encryptionKey")).Return(nil, fmt.Errorf("decryption error"))
					return en
				},
			},
			args: args{
				w: httptest.NewRecorder(),
				req: func() *http.Request {
					r := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString("SomeTextName"))
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

			h.TextDataGet(tt.args.w, tt.args.req)
			assert.Equal(t, tt.expectedStatus, tt.args.w.Code)
			assert.Equal(t, tt.expectedAnswer, tt.args.w.Body.Bytes())
		})
	}
}
