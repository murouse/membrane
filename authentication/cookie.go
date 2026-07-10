package authentication

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/samber/lo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// CookieRaw представляет собой строку со значением заголовка Cookie.
// Например:
//
//	"access_token=ey...; refresh_token=abc..."
type CookieRaw string

// Parse извлекает access token и refresh token из строки Cookie.
// Возвращает указатели на значения токенов, если они присутствуют.
func (c CookieRaw) Parse() (accessToken *string, refreshToken *string, err error) {
	cookies, err := http.ParseCookie(string(c))
	if err != nil {
		return nil, nil, err
	}

	accessTokenCookie, ok := lo.Find(cookies, func(cookie *http.Cookie) bool {
		return cookie.Name == CookieAccessToken.Name()
	})
	if ok {
		accessToken = &accessTokenCookie.Value
	}

	refreshTokenCookie, ok := lo.Find(cookies, func(cookie *http.Cookie) bool {
		return cookie.Name == CookieRefreshToken.Name()
	})
	if ok {
		refreshToken = &refreshTokenCookie.Value
	}

	return
}

// CookieElem описывает cookie,
// которая должна быть отправлена клиенту через Set-Cookie.
type CookieElem struct {
	Cookie    Cookie
	Value     string
	ExpiresAt time.Time
}

// Cookie описывает тип cookie,
// используемой системой аутентификации.
type Cookie int

const (
	CookieAccessToken  Cookie = iota // CookieAccessToken хранит access JWT токен.
	CookieRefreshToken               // CookieRefreshToken хранит refresh токен.
)

var cookieNameMap = map[Cookie]string{
	CookieAccessToken:  "access_token",
	CookieRefreshToken: "refresh_token",
}

// Name возвращает имя cookie,
// используемое в HTTP заголовке Cookie / Set-Cookie.
func (c Cookie) Name() string {
	return cookieNameMap[c]
}

var cookieMetadataKeyMap = map[Cookie]string{
	CookieAccessToken:  "authorization",
	CookieRefreshToken: "refresh",
}

// MetadataKey возвращает ключ metadata,
// под которым значение cookie передается в gRPC.
func (c Cookie) MetadataKey() string {
	return cookieMetadataKeyMap[c]
}

// toHttpCookie конвертирует CookieElem в http.Cookie.
//
// Если значение токена пустое, cookie помечается как удаленная.
func (cd CookieElem) toHttpCookie(secure bool) *http.Cookie {
	expires := cd.ExpiresAt
	maxAge := 0

	if cd.Value == "" { // если токен пуст (произошел logout)
		maxAge = -1               // удалить сразу
		expires = time.Unix(0, 0) // устаревшее время
	}

	return &http.Cookie{
		Name:     cd.Cookie.Name(),
		Value:    cd.Value,
		HttpOnly: true,
		Secure:   secure, // для https поменять на true!
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
		MaxAge:   maxAge,
	}
}

// extractValueFromMetadata извлекает значение из gRPC metadata.
func extractValueFromMetadata(ctx context.Context, key string) (string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}

	values := md.Get(key)
	if len(values) == 0 {
		return "", false
	}

	return values[0], true
}

// ExtractRefreshTokenFromMetadata извлекает refresh token из metadata.
func ExtractRefreshTokenFromMetadata(ctx context.Context) (string, bool) {
	return extractValueFromMetadata(ctx, CookieRefreshToken.MetadataKey())
}

// ExtractBearerTokenFromMetadata извлекает access token из metadata.
// Ожидается значение в формате:
//
//	Authorization: Bearer <token>
func ExtractBearerTokenFromMetadata(ctx context.Context) (string, bool) {
	return extractValueFromMetadata(ctx, CookieAccessToken.MetadataKey())
}

// SetCookieToMetadata добавляет cookies в gRPC metadata,
// которые затем будут преобразованы grpc-gateway в HTTP заголовок Set-Cookie.
func SetCookieToMetadata(ctx context.Context, cookies []CookieElem, secure bool) error {
	for _, cookie := range cookies {
		md := metadata.Pairs(setCookieKey, cookie.toHttpCookie(secure).String())

		if err := grpc.SetHeader(ctx, md); err != nil {
			return fmt.Errorf("grpc send header: %w", err)
		}
	}

	return nil
}
