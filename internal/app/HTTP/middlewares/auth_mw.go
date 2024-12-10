package middlewares

import (
	"GophKeeper/internal/app/requiredInterfaces"
	secureerrors "GophKeeper/pkg/secure/secureerrors"
	"context"
	"errors"
	"go.uber.org/zap"
	"net/http"
)

const JWTCookieName = "AuthJWT"

type UserIDContextKeyType string

const UserIDContextKey UserIDContextKeyType = "UserID"

func GetAuthMW(logger *zap.SugaredLogger, jh requiredInterfaces.JWTHelper, excludedPaths []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isExcluded(r.URL.Path, excludedPaths) {
				next.ServeHTTP(w, r)
				return
			} else {
				cookie, err := r.Cookie(JWTCookieName)
				if err != nil {
					logger.Warnf("cant get cookie: %v", err)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				userID, err := jh.GetUserID(cookie.Value)
				if errors.Is(err, secureerrors.NewErrorJWTIsNotValid()) {
					logger.Debug("token is not valid")
					w.WriteHeader(http.StatusUnauthorized)
					return
				} else if err != nil {
					logger.Warnf("cant get userID from JWT string, err: %v", err)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), UserIDContextKey, userID)))
			}
		})
	}
}

func isExcluded(path string, excludedPaths []string) bool {
	for _, excludedPath := range excludedPaths {
		if excludedPath == path {
			return true
		}
	}
	return false
}
