package httphandlers

import (
	"GophKeeper/internal/app/requiredInterfaces"
	"go.uber.org/zap"
)

type handlerHTTP struct {
	Logger      *zap.SugaredLogger
	UserManager requiredInterfaces.UserManager
	JWTHelper   requiredInterfaces.JWTHelper
}

//todo: create a chi router builder
