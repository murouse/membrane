package authentication

import (
	"context"
	"log/slog"
)

// Provider описывает сервис аутентификации,
// который проверяет access token и возвращает публичную модель пользователя.
type Provider[T any] interface {
	Authenticate(accessToken string) (T, error)
}

// ActorInjector отвечает за внедрение пользователя (actor)
// в context для дальнейшего использования в обработчиках.
type ActorInjector[T any] interface {
	With(ctx context.Context, user T) context.Context
}
type Authenticator[T any] struct {
	authProvider  Provider[T]
	actorInjector ActorInjector[T]

	logger *slog.Logger
}

func New[T any](authProvider Provider[T], actorInjector ActorInjector[T], opts ...Option[T]) *Authenticator[T] {
	a := &Authenticator[T]{
		authProvider:  authProvider,
		actorInjector: actorInjector,

		logger: slog.New(slog.DiscardHandler),
	}

	for _, opt := range opts {
		opt(a)
	}

	return a
}

type Option[T any] func(*Authenticator[T])

func WithLogger[T any](logger *slog.Logger) Option[T] {
	return func(m *Authenticator[T]) {
		m.logger = logger
	}
}
