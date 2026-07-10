# membrane 🛡️

**Membrane** — это библиотека для декларативной аутентификации и гибкой (RBAC) авторизации в gRPC-сервисах на Go. Проект поддерживает как чистый gRPC-клиент, так и интеграцию с `grpc-gateway` через HTTP-only Cookies.

## Основные фичи

* **Secure by Default**: Если метод gRPC не размечен явно политикой, он закрыт для неавторизованных пользователей.
* **Гибкие правила (AND / OR)**: Поддержка сложных булевых деревьев для проверки ролей (включая глубокую вложенность `nested_any_of` и `nested_all_of`).
* **Высокая производительность**: Парсинг `.proto` аннотаций через рефлексию происходит ровно один раз при первом gRPC-запросе (`sync.Once`), далее проверки выполняются за $O(1)$ в памяти.
* **Cookie Propagation**: Прозрачный перенос сессионных токенов из HTTP-only Cookies в gRPC Metadata.
* **Типобезопасность**: Использование Go Generics позволяет гибко задавать тип идентификатора пользователя (`userID` типа `any`).

## Архитектура потока данных (Pipeline)

```text
  HTTP Request (Cookies: access_token, refresh_token)
       │
       ▼
  gRPC-Gateway (IncomingHeaderMatcher прокидывает заголовок Cookie)
       │
       ▼
  WithCookieTokenPropagate Interceptor (Конвертирует Cookie в Metadata authorization: Bearer)
       │
       ▼
  Authenticator Interceptor (Валидирует токен -> Инжектирует Актора в Context)
       │
       ▼
  Authorizer Interceptor (Проверяет роли актора по дереву правил Rule из .proto)
       │
       ▼
  gRPC Handler (Бизнес-логика с безопасным контекстом)
```

## Быстрый старт

### 1. Описание политик в `.proto`

Импортируйте расширение `membrane` и задайте правила для RPC-методов:

```protobuf
syntax = "proto3";

package myservice.v1;

import "murouse/membrane/v1/membrane.proto";

service CatalogService {
  // Доступно абсолютно всем (даже анонимам)
  rpc GetProducts (GetProductsRequest) returns (GetProductsResponse) {
    option (murouse.membrane.v1.policy) = {
      allow_unauthenticated: true
    };
  }

  // Требуется роль USER ИЛИ ADMIN
  rpc CreateReview (CreateReviewRequest) returns (CreateReviewResponse) {
    option (murouse.membrane.v1.policy) = {
      rule: {
        any_of: [ROLE_USER, ROLE_ADMIN]
      }
    };
  }
}
```

### 2. Подключение Интерцепторов в Go

```go
package main

import (
	"google.golang.org/grpc"
	"github.com/murouse/membrane/authentication"
	"github.com/murouse/membrane/authorization"
)

func main() {
	// 1. Инициализируем аутентификатор (например, с ID пользователя в виде int64)
	authenticator := authentication.New[int64](authProvider, actorInjector)

	// 2. Инициализируем авторизатор
	authorizer := authorization.New[int64](actorExtractor, roleProvider)

	// 3. Регистрируем цепочку интерцепторов на сервере
	server := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			authentication.WithCookieTokenPropagate(), // 1. Извлекаем куки в метадату
			authenticator.UnaryServerInterceptor(),     // 2. Проверяем токен, кладем юзера в ctx
			authorizer.UnaryServerInterceptor(),        // 3. Сверяем роли с .proto политикой
		),
	)
    
	// ... регистрация сервисов и запуск
}
```

## Настройка gRPC-Gateway

Для работы с HTTP-only cookies, при инициализации `runtime.NewServeMux` обязательно зарегистрируйте матчеры заголовков:

```go
mux := runtime.NewServeMux(
    runtime.WithIncomingHeaderMatcher(authentication.IncomingHeaderMatcher),
    runtime.WithOutgoingHeaderMatcher(authentication.OutgoingHeaderMatcher),
)
```