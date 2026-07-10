package authentication

import (
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

const (
	cookieKey    = "cookie"     // cookieKey — имя HTTP заголовка Cookie.
	setCookieKey = "set-cookie" // setCookieKey — имя HTTP заголовка Set-Cookie.
)

// OutgoingHeaderMatcher позволяет grpc-gateway
// корректно пробросить Set-Cookie из gRPC metadata
// в HTTP заголовок ответа.
//
// Без этого заголовок будет преобразован в:
//
//	Grpc-Metadata-Set-Cookie
func OutgoingHeaderMatcher(key string) (string, bool) {
	// nolint: gocritic
	switch key {
	case setCookieKey:
		return key, true
	}

	return runtime.DefaultHeaderMatcher(key)
}

// IncomingHeaderMatcher позволяет grpc-gateway
// передавать HTTP Cookie заголовок в gRPC metadata.
//
// Без этого заголовок будет преобразован в:
//
//	grpcgateway-cookie
func IncomingHeaderMatcher(key string) (string, bool) {
	// nolint: gocritic
	switch strings.ToLower(key) {
	case cookieKey:
		return key, true
	}

	return runtime.DefaultHeaderMatcher(key)
}
