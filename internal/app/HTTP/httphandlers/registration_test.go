package httphandlers

import (
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
	//set data
	url := "/api/register"

	//set logger
	logger := zaptest.NewLogger(t)
	sugar := logger.Sugar()

	//set gomock controller
	c := gomock.NewController(t)

	type fields struct {
		UserManager requiredInterfaces.UserManager
		JWTHelper   requiredInterfaces.JWTHelper
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
				UserManager: func() requiredInterfaces.UserManager {
					um := mocks.NewMockUserManager(c)
					um.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(entities.User{})).DoAndReturn(func(_ context.Context, u entities.User) (int, error) {
						assert.Equal(t, "qwerty@example.ru", u.Login)
						assert.NotEmpty(t, u.PasswordHash, "Password hash is empty")
						return 1, nil
					})
					return um
				}(),
				JWTHelper: func() requiredInterfaces.JWTHelper {
					jh := mocks.NewMockJWTHelper(c)
					jh.EXPECT().BuildNewJWTString(1).Return("very.secret.jwt", nil)
					return jh
				}(),
			},
			args: args{
				w:   httptest.NewRecorder(),
				req: httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"login":"qwerty@example.ru","password":"123qwerty!"}`)),
			},
			expectedAnswer: []byte("very.secret.jwt"),
			expectedStatus: http.StatusCreated,
		},
		{
			name: "Empty JSON in request",
			args: args{
				w:   httptest.NewRecorder(),
				req: httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{}`)),
			},
			expectedAnswer: nil,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "No password",
			args: args{
				w:   httptest.NewRecorder(),
				req: httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"login":"qwerty@example.ru","password":""}`)),
			},
			expectedAnswer: nil,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "User already exists",
			fields: fields{
				UserManager: func() requiredInterfaces.UserManager {
					um := mocks.NewMockUserManager(c)
					um.EXPECT().Create(gomock.Any(), gomock.Any()).Return(0, storageerrors.NewErrAlreadyExists())
					return um
				}(),
				JWTHelper: nil,
			},
			args: args{
				w:   httptest.NewRecorder(),
				req: httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"login":"qwerty@example.ru","password":"123qwerty!"}`)),
			},
			expectedAnswer: nil,
			expectedStatus: http.StatusConflict,
		},
		{
			name: "database error",
			fields: fields{
				UserManager: func() requiredInterfaces.UserManager {
					um := mocks.NewMockUserManager(c)
					um.EXPECT().Create(gomock.Any(), gomock.Any()).Return(0, fmt.Errorf("some test error"))
					return um
				}(),
				JWTHelper: nil,
			},
			args: args{
				w:   httptest.NewRecorder(),
				req: httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"login":"qwerty@example.ru","password":"123qwerty!"}`)),
			},
			expectedAnswer: nil,
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "jwt helper error",
			fields: fields{
				UserManager: func() requiredInterfaces.UserManager {
					um := mocks.NewMockUserManager(c)
					um.EXPECT().Create(gomock.Any(), gomock.Any()).Return(1, nil)
					return um
				}(),
				JWTHelper: func() requiredInterfaces.JWTHelper {
					jh := mocks.NewMockJWTHelper(c)
					jh.EXPECT().BuildNewJWTString(gomock.Any()).Return("", fmt.Errorf("some test error"))
					return jh
				}(),
			},
			args: args{
				w:   httptest.NewRecorder(),
				req: httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"login":"qwerty@example.ru","password":"123qwerty!"}`)),
			},
			expectedAnswer: nil,
			expectedStatus: http.StatusInternalServerError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &handlerHTTP{
				Logger:      sugar,
				UserManager: tt.fields.UserManager,
				JWTHelper:   tt.fields.JWTHelper,
			}
			h.RegisterUser(tt.args.w, tt.args.req)
			assert.Equal(t, tt.expectedStatus, tt.args.w.Code)
			assert.Equal(t, tt.expectedAnswer, tt.args.w.Body.Bytes())
		})
	}
}
