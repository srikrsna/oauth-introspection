package introspection

import (
	"context"

	"github.com/grpc-ecosystem/go-grpc-middleware/auth"
)

// AuthFunc ...
func AuthFunc(endpoint string, opts ...Option) grpc_auth.AuthFunc {
	opt := makeOptions(endpoint, opts)

	return grpc_auth.AuthFunc(func(ctx context.Context) (context.Context, error) {
		token, err := grpc_auth.AuthFromMD(ctx, "bearer")
		if err != nil {
			return context.WithValue(ctx, resKey, &result{Err: ErrNoBearer}), nil
		}

		res, err := introspectionResult(token, opt)

		return context.WithValue(ctx, resKey, &result{res, err}), nil
	})
}
