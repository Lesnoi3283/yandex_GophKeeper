package httphandlers

import (
	"GophKeeper/internal/app/HTTP/middlewares"
	"GophKeeper/internal/app/entities"
	"GophKeeper/internal/app/requiredInterfaces"
	"GophKeeper/internal/app/requiredInterfaces/mocks"
	"GophKeeper/pkg/storages/storageerrors"
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

func Test_handlerHTTP_RegisterUser(t *testing.T) {
	// set data
	url := "/api/register"

	// set logger
	logger := zaptest.NewLogger(t)
	sugar := logger.Sugar()

	type fields struct {
		UserManager func(c *gomock.Controller) requiredInterfaces.UserManager
		JWTHelper   func(c *gomock.Controller) requiredInterfaces.JWTHelper
	}
	type args struct {
		w   *httptest.ResponseRecorder
		req *http.Request
	}
	tests := []struct {
		name           string
		fields         fields
		args           args
		expectedCookie string
		expectedStatus int
	}{
		{
			name: "Ok",
			fields: fields{
				UserManager: func(c *gomock.Controller) requiredInterfaces.UserManager {
					um := mocks.NewMockUserManager(c)
					um.EXPECT().CreateUser(gomock.Any(), gomock.AssignableToTypeOf(entities.User{})).DoAndReturn(func(_ context.Context, u entities.User) (int, error) {
						assert.Equal(t, "qwerty@example.ru", u.Login)
						assert.Equal(t, "123qwerty!", u.Password)
						return 1, nil
					})
					return um
				},
				JWTHelper: func(c *gomock.Controller) requiredInterfaces.JWTHelper {
					jh := mocks.NewMockJWTHelper(c)
					jh.EXPECT().BuildNewJWTString(1).Return("very.secret.jwt", nil)
					return jh
				},
			},
			args: args{
				w:   httptest.NewRecorder(),
				req: httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"login":"qwerty@example.ru","password":"123qwerty!"}`)),
			},
			expectedCookie: "very.secret.jwt",
			expectedStatus: http.StatusCreated,
		},
		{
			name: "Empty JSON in request",
			args: args{
				w:   httptest.NewRecorder(),
				req: httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{}`)),
			},
			expectedCookie: "",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "No password",
			args: args{
				w:   httptest.NewRecorder(),
				req: httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"login":"qwerty@example.ru","password":""}`)),
			},
			expectedCookie: "",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "No login",
			args: args{
				w:   httptest.NewRecorder(),
				req: httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"login":"","password":"12345"}`)),
			},
			expectedCookie: "",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "User already exists",
			fields: fields{
				UserManager: func(c *gomock.Controller) requiredInterfaces.UserManager {
					um := mocks.NewMockUserManager(c)
					um.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(0, storageerrors.NewErrAlreadyExists())
					return um
				},
				JWTHelper: nil,
			},
			args: args{
				w:   httptest.NewRecorder(),
				req: httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"login":"qwerty@example.ru","password":"123qwerty!"}`)),
			},
			expectedCookie: "",
			expectedStatus: http.StatusConflict,
		},
		{
			name: "database error",
			fields: fields{
				UserManager: func(c *gomock.Controller) requiredInterfaces.UserManager {
					um := mocks.NewMockUserManager(c)
					um.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(0, fmt.Errorf("some test error"))
					return um
				},
				JWTHelper: nil,
			},
			args: args{
				w:   httptest.NewRecorder(),
				req: httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"login":"qwerty@example.ru","password":"123qwerty!"}`)),
			},
			expectedCookie: "",
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "jwt helper error",
			fields: fields{
				UserManager: func(c *gomock.Controller) requiredInterfaces.UserManager {
					um := mocks.NewMockUserManager(c)
					um.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(1, nil)
					return um
				},
				JWTHelper: func(c *gomock.Controller) requiredInterfaces.JWTHelper {
					jh := mocks.NewMockJWTHelper(c)
					jh.EXPECT().BuildNewJWTString(gomock.Any()).Return("", fmt.Errorf("some test error"))
					return jh
				},
			},
			args: args{
				w:   httptest.NewRecorder(),
				req: httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"login":"qwerty@example.ru","password":"123qwerty!"}`)),
			},
			expectedCookie: "",
			expectedStatus: http.StatusInternalServerError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &handlerHTTP{
				Logger: sugar,
			}

			// set gomock controller
			c := gomock.NewController(t)
			if tt.fields.UserManager != nil {
				h.UserManager = tt.fields.UserManager(c)
			}
			if tt.fields.JWTHelper != nil {
				h.JWTHelper = tt.fields.JWTHelper(c)
			}

			h.RegisterUser(tt.args.w, tt.args.req)

			// check response status
			assert.Equal(t, tt.expectedStatus, tt.args.w.Code)

			// check JWT in cookies
			if tt.expectedCookie != "" {
				cookies := tt.args.w.Result().Cookies()
				var foundCookie *http.Cookie
				for _, cookie := range cookies {
					if cookie.Name == middlewares.JWTCookieName {
						foundCookie = cookie
						break
					}
				}
				assert.NotNil(t, foundCookie, "JWT cookie not found")
				assert.Equal(t, tt.expectedCookie, foundCookie.Value)
			}
		})
	}
}
