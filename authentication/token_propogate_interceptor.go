package authentication

import (
	"context"

	"github.com/samber/lo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// WithCookieTokenPropagate создает interceptor,
// который извлекает access и refresh токены из HTTP cookies
// и помещает их в gRPC metadata.
//
// Access token помещается в metadata как:
//
//	authorization: Bearer <token>
//
// Refresh token помещается как:
//
//	refresh: <token>
//
// Это позволяет использовать cookie-аутентификацию
// так же, как если бы токены были переданы через HTTP заголовки.
func WithCookieTokenPropagate() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (
		resp any, err error,
	) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return handler(ctx, req)
		}

		cookieRawValue, ok := lo.First(md[cookieKey])
		if !ok {
			return handler(ctx, req)
		}

		accessToken, refreshToken, err := CookieRaw(cookieRawValue).Parse()
		if err != nil {
			return handler(ctx, req)
		}

		if accessToken != nil {
			md.Set(CookieAccessToken.MetadataKey(), "Bearer "+*accessToken)
		}

		if refreshToken != nil {
			md.Set(CookieRefreshToken.MetadataKey(), *refreshToken)
		}

		return handler(metadata.NewIncomingContext(ctx, md), req)
	}
}
