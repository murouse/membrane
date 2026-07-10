package authorization

import (
	"context"
	"log/slog"
	"sync"

	mapset "github.com/deckarep/golang-set/v2"
	healthpbv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/reflect/protoreflect"

	pb "github.com/murouse/membrane/pkg/api/murouse/membrane/v1"
)

type ActorExtractor[T any] interface {
	FromContext(ctx context.Context) (T, bool)
}

type RoleProvider[T any] interface {
	ListRoles(ctx context.Context, id T) ([]int32, error)
}

type Authorizer[T any] struct {
	actorExtractor ActorExtractor[T]
	roleProvider   RoleProvider[T]

	logger                *slog.Logger
	ignoreMethods         mapset.Set[string]
	permissionDeniedError error // нет прав
	notAuthorizedError    error // нет токена
	policyExtension       protoreflect.ExtensionType

	methodPolicies  map[string]Policy
	methodRulesOnce sync.Once
}

func New[T any](actorExtractor ActorExtractor[T], roleProvider RoleProvider[T], opts ...Option[T]) *Authorizer[T] {
	a := &Authorizer[T]{
		actorExtractor: actorExtractor,
		roleProvider:   roleProvider,

		logger: slog.New(slog.DiscardHandler),
		ignoreMethods: mapset.NewSet(
			healthpbv1.Health_Check_FullMethodName,
		),
		permissionDeniedError: ErrPermissionDenied,
		notAuthorizedError:    ErrNotAuthorized,
		policyExtension:       pb.E_Policy,
	}

	for _, opt := range opts {
		opt(a)
	}

	return a
}

type Option[T any] func(*Authorizer[T])

func WithLogger[T any](logger *slog.Logger) Option[T] {
	return func(m *Authorizer[T]) {
		m.logger = logger
	}
}

func WithIgnoreMethods[T any](ms ...string) Option[T] {
	return func(m *Authorizer[T]) {
		m.ignoreMethods.Append(ms...)
	}
}

func WithResetIgnoreMethods[T any](ms ...string) Option[T] {
	return func(m *Authorizer[T]) {
		m.ignoreMethods.Clear()
		m.ignoreMethods.Append(ms...)
	}
}

func WithPermissionDeniedError[T any](err error) Option[T] {
	return func(m *Authorizer[T]) {
		m.permissionDeniedError = err
	}
}

func WithNotAuthorizedError[T any](err error) Option[T] {
	return func(m *Authorizer[T]) {
		m.notAuthorizedError = err
	}
}

// WithPolicyExtension используеся, если при копировании прото-расширения изменили номер опции,
// и требуется зарегитрировать новый объект
func WithPolicyExtension[T any](ext protoreflect.ExtensionType) Option[T] {
	return func(m *Authorizer[T]) {
		m.policyExtension = ext
	}
}
