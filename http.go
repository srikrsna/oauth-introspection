package introspection

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

const (
	discoveryPath = ".well-known/openid-configuration"
)

var (
	// ErrNoBearer is returned by FromContext function when no Bearer token was present
	ErrNoBearer = errors.New("no bearer")
	// ErrNoMiddleware is returned by FromContext when no value was set. It is due to the middleware not being called before this function.
	ErrNoMiddleware = errors.New("introspection middleware didn't execute")
)

// Introspection ...
func Introspection(endpoint string, opts ...Option) func(http.Handler) http.Handler {

	opt := makeOptions(endpoint, opts)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hd := r.Header.Get("Authorization")

			if !strings.HasPrefix(hd, "Bearer ") {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), resKey, &result{Err: ErrNoBearer})))
				return
			}

			token := hd[len("Bearer "):]

			res, err := introspectionResult(token, opt)
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), resKey, &result{res, err})))
		})
	}
}
