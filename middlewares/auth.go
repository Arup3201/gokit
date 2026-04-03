package middlewares

import (
	"context"
	"net/http"
	"slices"
)

const (
	SESSION_COOKIE_NAME_DEFAULT = "AUTH"
)

var (
	SessionCookieName = SESSION_COOKIE_NAME_DEFAULT
)

type UserIdGetter interface {
	/*
		Fetch user ID from session ID.

		Returns user ID as uint. In case of error, returns non-nil error.
	*/
	GetUserIdFromSession(context.Context, string) (uint, error)
}

type authMiddleware struct {
	getter UserIdGetter
}

func NewAuthMiddleware(getter UserIdGetter) *authMiddleware {
	return &authMiddleware{
		getter: getter,
	}
}

func (a *authMiddleware) WithSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var cookies = r.Cookies()

		sInd := slices.IndexFunc(cookies, func(c *http.Cookie) bool {
			return c.Name == SessionCookieName
		})
		if sInd == -1 {
			http.Error(w, "User not authenticated", http.StatusUnauthorized)
			return
		}

		sessionId := cookies[sInd].Value
		if sessionId == "" {
			http.Error(w, "User not authenticated", http.StatusUnauthorized)
			return
		}

		userId, err := a.getter.GetUserIdFromSession(r.Context(), sessionId)
		if err != nil {
			http.Error(w, "User not authenticated", http.StatusUnauthorized)
			return
		}

		reqWithCtx := r.WithContext(NewContext(r.Context(), userId))
		next.ServeHTTP(w, reqWithCtx)
	})

}
