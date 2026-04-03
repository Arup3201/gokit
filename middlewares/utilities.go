package middlewares

import (
	"context"
)

const (
	USER_ID_KEY = "USER_ID"
)

// NewContext returns a new Context that carries value u.
func NewContext(ctx context.Context, u uint) context.Context {
	return context.WithValue(ctx, USER_ID_KEY, u)
}

// FromContext returns the User value stored in ctx, if any.
func FromContext(ctx context.Context) (uint, bool) {
	u, ok := ctx.Value(USER_ID_KEY).(uint)
	return u, ok
}
