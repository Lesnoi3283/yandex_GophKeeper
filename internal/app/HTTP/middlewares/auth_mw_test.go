package middlewares

import (
	"GophKeeper/internal/app/requiredInterfaces"
	"GophKeeper/internal/app/requiredInterfaces/mocks"
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_AuthMW(t *testing.T) {
	//prepare
	logger := zaptest.NewLogger(t)
	sugar := logger.Sugar()
	c := gomock.NewController(t)
	defer c.Finish()

	type fields struct {
		jh requiredInterfaces.JWTHelper
	}
	type args struct {
		w    *httptest.ResponseRecorder
		r    *http.Request
		next http.Handler
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		statusWant int
	}{
		{
			name: "ok",
			fields: fields{
				jh: func() requiredInterfaces.JWTHelper {
					jh := mocks.NewMockJWTHelper(c)
					jh.EXPECT().GetUserID("some.jwt.token").Return(1, nil)
					return jh
				}(),
			},
			args: args{
				w: httptest.NewRecorder(),
				r: func() *http.Request {
					r := httptest.NewRequest(http.MethodGet, "/some/target", nil)
					r.AddCookie(&http.Cookie{
						Name:  JWTCookieName,
						Value: "some.jwt.token",
					})
					return r
				}(),
				next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					userID := r.Context().Value(UserIDContextKey)
					userIDInt, ok := userID.(string)
					assert.True(t, ok, "userID is not an int")
					assert.Equal(t, 1, userIDInt, "wrong userID")

					w.WriteHeader(http.StatusOK)
				}),
			},
			statusWant: http.StatusOK,
		},
		{
			name: "allowed without auth",
			fields: fields{
				jh: nil,
			},
			args: args{
				w: httptest.NewRecorder(),
				r: httptest.NewRequest(http.MethodGet, "/api/login", nil),
				next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				}),
			},
			statusWant: http.StatusOK,
		},
		{
			name: "Bad JWT",
			fields: fields{
				jh: func() requiredInterfaces.JWTHelper {
					jh := mocks.NewMockJWTHelper(c)
					jh.EXPECT().GetUserID("some.bad.JWTToken").Return(0, fmt.Errorf("some jwt error"))
					return jh
				}(),
			},
			args: args{
				w: httptest.NewRecorder(),
				r: func() *http.Request {
					r := httptest.NewRequest(http.MethodGet, "/some/target", nil)
					r.AddCookie(&http.Cookie{
						Name:  JWTCookieName,
						Value: "some.bad.JWTToken",
					})
					return r
				}(),
				next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				}),
			},
			statusWant: http.StatusUnauthorized,
		},
		{
			name: "No JWT, but auth is required",
			fields: fields{
				jh: nil,
			},
			args: args{
				w: httptest.NewRecorder(),
				r: httptest.NewRequest(http.MethodGet, "/some/target", nil),
				next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				}),
			},
			statusWant: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := GetAuthMW(sugar, tt.fields.jh)
			handler := mw(tt.args.next)
			handler.ServeHTTP(tt.args.w, tt.args.r)
			assert.Equal(t, tt.statusWant, tt.args.w.Code, "wrong status code")
		})
	}
}
