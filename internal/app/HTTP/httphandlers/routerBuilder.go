package httphandlers

import (
	"GophKeeper/internal/app/requiredInterfaces"
	"github.com/go-chi/chi"
	"go.uber.org/zap"
)

type handlerHTTP struct {
	Logger      *zap.SugaredLogger
	Storage     requiredInterfaces.Storage
	UserManager requiredInterfaces.UserManager
	JWTHelper   requiredInterfaces.JWTHelper
	KeyKeeper   requiredInterfaces.KeyKeeper
	Encryptor   requiredInterfaces.Encryptor
}

// todo: create a chi router builder
func NewChiRouter(logger *zap.SugaredLogger, um requiredInterfaces.UserManager, jh requiredInterfaces.JWTHelper) chi.Router {
	httphandler := handlerHTTP{
		Logger:      logger,
		UserManager: um,
		JWTHelper:   jh,
	}

	r := chi.NewRouter()

	r.Use()

	r.Post("/api/register", httphandler.RegisterUser)
	r.Get("api/login", httphandler.LogIn)

	return r
}
