package httphandlers

import (
	"GophKeeper/internal/app/HTTP/middlewares"
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

func NewChiRouter(logger *zap.SugaredLogger, um requiredInterfaces.UserManager,
	jh requiredInterfaces.JWTHelper, storage requiredInterfaces.Storage,
	keeper requiredInterfaces.KeyKeeper, encryptor requiredInterfaces.Encryptor) chi.Router {

	//create handler
	httphandler := handlerHTTP{
		Logger:      logger,
		Storage:     storage,
		UserManager: um,
		JWTHelper:   jh,
		KeyKeeper:   keeper,
		Encryptor:   encryptor,
	}

	r := chi.NewRouter()

	//set middlewares
	r.Use(middlewares.GetAuthMW(logger, jh))

	//set handlers
	r.Post("/api/register", httphandler.RegisterUser)
	r.Get("/api/login", httphandler.LogIn)
	r.Post("/api/bankcard", httphandler.BankCardSave)
	r.Get("/api/bankcard", httphandler.BankCardGet)
	r.Post("/api/loginandpassword", httphandler.LoginAndPasswordSave)
	r.Get("/api/loginandpassword", httphandler.PasswordGet)
	r.Post("/api/text", httphandler.TextDataSave)
	r.Get("/api/text", httphandler.TextDataGet)

	return r
}
