package handlers

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

func Test_handlerHTTP_LogIn(t *testing.T) {
	// set data
	url := "/api/login"

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
			name: "ok",
			fields: fields{
				UserManager: func(c *gomock.Controller) requiredInterfaces.UserManager {
					um := mocks.NewMockUserManager(c)
					um.EXPECT().AuthUser(gomock.Any(), gomock.AssignableToTypeOf(entities.User{})).DoAndReturn(func(_ context.Context, u entities.User) (int, error) {
						assert.Equal(t, "qwerty@example.ru", u.Login)
						assert.Equal(t, "123qwerty!", u.Password)
						return 1, nil
					})
					return um
				},
				JWTHelper: func(c *gomock.Controller) requiredInterfaces.JWTHelper {
					jh := mocks.NewMockJWTHelper(c)
					jh.EXPECT().BuildNewJWTString(1).Return("some.test.jwt", nil)
					return jh
				},
			},
			args: args{
				w:   httptest.NewRecorder(),
				req: httptest.NewRequest(http.MethodGet, url, bytes.NewBufferString(`{"login":"qwerty@example.ru","password":"123qwerty!"}`)),
			},
			expectedCookie: "some.test.jwt",
			expectedStatus: http.StatusOK,
		},
		{
			name: "user not exists",
			fields: fields{
				UserManager: func(c *gomock.Controller) requiredInterfaces.UserManager {
					um := mocks.NewMockUserManager(c)
					um.EXPECT().AuthUser(gomock.Any(), gomock.Any()).Return(0, storageerrors.NewErrNotExists())
					return um
				},
				JWTHelper: nil,
			},
			args: args{
				w:   httptest.NewRecorder(),
				req: httptest.NewRequest(http.MethodGet, url, bytes.NewBufferString(`{"login":"qwerty@example.ru","password":"123qwerty!"}`)),
			},
			expectedCookie: "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "some db error",
			fields: fields{
				UserManager: func(c *gomock.Controller) requiredInterfaces.UserManager {
					um := mocks.NewMockUserManager(c)
					um.EXPECT().AuthUser(gomock.Any(), gomock.Any()).Return(0, fmt.Errorf("some test db error"))
					return um
				},
				JWTHelper: nil,
			},
			args: args{
				w:   httptest.NewRecorder(),
				req: httptest.NewRequest(http.MethodGet, url, bytes.NewBufferString(`{"login":"qwerty@example.ru","password":"123qwerty!"}`)),
			},
			expectedCookie: "",
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "empty json",
			fields: fields{
				UserManager: nil,
				JWTHelper:   nil,
			},
			args: args{
				w:   httptest.NewRecorder(),
				req: httptest.NewRequest(http.MethodGet, url, bytes.NewBufferString(`{}`)),
			},
			expectedCookie: "",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "not valid json",
			fields: fields{
				UserManager: nil,
				JWTHelper:   nil,
			},
			args: args{
				w:   httptest.NewRecorder(),
				req: httptest.NewRequest(http.MethodGet, url, bytes.NewBufferString(`{"login":"qwerty@examp`)),
			},
			expectedCookie: "",
			expectedStatus: http.StatusBadRequest,
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

			h.Login(tt.args.w, tt.args.req)

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
