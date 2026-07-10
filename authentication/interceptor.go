/*
Package authentication реализует аутентификацию и авторизацию пользователей
для gRPC сервиса с поддержкой grpc-gateway и HTTP-only cookies.

Основные возможности пакета:

1. Авторизация через access token (Bearer):
  - Access token извлекается из metadata gRPC ("authorization").
  - Проверяется через интерфейс Authenticator.
  - После успешной проверки пользователь помещается в context через WithActor.

2. Аутентификация через cookies:
  - HTTP-only cookies (access_token, refresh_token) конвертируются в metadata через
    interceptor WithCookieTokenPropagate.
  - Access token помещается в metadata как "authorization: Bearer <token>".
  - Refresh token помещается в metadata как "refresh: <token>".

3. Обновление и удаление токенов:
  - Методы Login и Refresh создают новые токены и отправляют их клиенту через Set-Cookie.
  - Метод Logout очищает cookies, чтобы удалить токены на клиенте.
  - OutgoingHeaderMatcher конвертирует metadata "set-cookie" обратно в HTTP Set-Cookie.

4. Пропуск аутентификации для публичных методов:
  - Методы вроде AuthService/Login, AuthService/SendCode игнорируются в WithAuthentication.

5. Поток запроса (pipeline):

	HTTP Request
	     │
	     ▼
	gRPC-Gateway
	     ├─ IncomingHeaderMatcher (Cookie → metadata)
	     │
	     ▼
	WithCookieTokenPropagate (cookie → metadata access/refresh)
	     │
	     ▼
	WithAuthentication (metadata access → проверка токена через Authenticator)
	     │
	     ▼
	Context + Actor (текущий пользователь в context)
	     │
	     ▼
	Handler (доступ к ctx с пользователем через auth.Actor)
	     │
	     ▼
	SetCookieToMetadata (новые токены → metadata)
	     │
	     ▼
	OutgoingHeaderMatcher (metadata → HTTP Set-Cookie)
	     │
	     ▼
	HTTP Response

6. Основные принципы безопасности:
  - Cookies HttpOnly и Secure для защиты от XSS.
  - SameSite=Lax для уменьшения риска CSRF.
  - Access token проверяется централизованно через interceptor.
  - Refresh token используется только для обновления access token.
*/
package authentication

import (
	"context"
	"strings"

	"github.com/murouse/golgi/attr"
	"google.golang.org/grpc"
)

// UnaryServerInterceptor создает gRPC interceptor,
// который извлекает access token из metadata и выполняет аутентификацию.
//
// Токен может быть передан:
//   - через HTTP заголовок Authorization Bearer
//   - через HTTP cookie (если используется WithCookieTokenPropagate)
//
// После успешной аутентификации пользователь добавляется в context.
func (a *Authenticator[T]) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (
		resp interface{}, err error,
	) {
		// Извлекаем токен из метадаты
		token, ok := ExtractBearerTokenFromMetadata(ctx)
		if ok {
			token = strings.TrimPrefix(token, "Bearer ") // если токен есть, тримим
		} else {
			return handler(ctx, req) // если токена нет, выходим без инжекции
		}

		// Проводим аутентификацию
		user, err := a.authProvider.Authenticate(token)
		if err != nil {
			a.logger.Debug("authenticate failed", attr.Error(err))

			return handler(ctx, req) // если ошибка, выходим без инжекции
		}

		// инжектируем
		ctx = a.actorInjector.With(ctx, user)

		return handler(ctx, req)
	}
}
