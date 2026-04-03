package middlewares

import (
	"context"
	"crypto/rsa"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/Arup3201/gokit"
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

type sessionAuthenticator struct {
	getter UserIdGetter
}

func NewSessionAuthenticator(getter UserIdGetter) *sessionAuthenticator {
	return &sessionAuthenticator{
		getter: getter,
	}
}

func (a *sessionAuthenticator) WithSession(next http.Handler) http.Handler {
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

type jwtAuthenticator struct {
	publicKey *rsa.PublicKey
}

func NewJWTAuthenticator(publicKey *rsa.PublicKey) *jwtAuthenticator {
	return &jwtAuthenticator{
		publicKey: publicKey,
	}
}

func (a *jwtAuthenticator) WithJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := r.Header.Get("Authorization")
		if strings.Trim(bearer, " ") == "" {
			// empty token
			http.Error(w, "Authorization failure", http.StatusUnauthorized)
			return
		}

		bearerToken := strings.Fields(bearer)
		if bearerToken[0] != "Bearer" {
			// malformed token
			http.Error(w, "Authorization failure", http.StatusUnauthorized)
			return
		}

		claims, err := gokit.ClaimsFromToken(bearerToken[1], a.publicKey)
		if err != nil {
			// invalid token signature or expired jwt or invalid jwt format
			http.Error(w, "Authorization failure", http.StatusUnauthorized)
			return
		}

		userId, err := strconv.Atoi(claims.UserId)
		if err != nil {
			// string to int parse failed
			http.Error(w, "Authorization failure", http.StatusUnauthorized)
			return
		}
		reqWithCtx := r.WithContext(NewContext(r.Context(), uint(userId)))
		next.ServeHTTP(w, reqWithCtx)
	})
}
