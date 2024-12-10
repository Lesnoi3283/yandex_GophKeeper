package handlers

import (
	"GophKeeper/config"
	"GophKeeper/internal/app/HTTP/middlewares"
	"GophKeeper/internal/app/required_interfaces"
	"github.com/go-chi/chi"
	"go.uber.org/zap"
)

type handlerHTTP struct {
	Logger      *zap.SugaredLogger
	Storage     required_interfaces.Storage
	UserManager required_interfaces.UserManager
	JWTHelper   required_interfaces.JWTHelper
	KeyKeeper   required_interfaces.KeyKeeper
	Encryptor   required_interfaces.Encryptor
	Conf        config.Config
}

func NewChiRouter(logger *zap.SugaredLogger, um required_interfaces.UserManager,
	jh required_interfaces.JWTHelper, storage required_interfaces.Storage,
	keeper required_interfaces.KeyKeeper, encryptor required_interfaces.Encryptor,
	conf config.Config) chi.Router {

	//create handler
	httphandler := handlerHTTP{
		Logger:      logger,
		Storage:     storage,
		UserManager: um,
		JWTHelper:   jh,
		KeyKeeper:   keeper,
		Encryptor:   encryptor,
		Conf:        conf,
	}

	r := chi.NewRouter()

	//set middlewares
	excludedPath := []string{"/api/register", "/api/login"}
	r.Use(middlewares.GetAuthMW(logger, jh, excludedPath))

	//set handlers
	r.Post("/api/register", httphandler.RegisterUser)
	r.Get("/api/login", httphandler.Login)
	r.Post("/api/bankcard", httphandler.BankCardSave)
	r.Get("/api/bankcard", httphandler.BankCardGet)
	r.Post("/api/loginandpassword", httphandler.LoginAndPasswordSave)
	r.Get("/api/loginandpassword", httphandler.PasswordGet)
	r.Post("/api/text", httphandler.SaveText)
	r.Get("/api/text", httphandler.GetText)

	return r
}
