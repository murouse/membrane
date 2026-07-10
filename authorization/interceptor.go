package authorization

import (
	"context"
	"fmt"
	"log/slog"

	mapset "github.com/deckarep/golang-set/v2"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	pb "github.com/murouse/membrane/pkg/api/murouse/membrane/v1"
)

func (m *Authorizer[T]) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (
		any, error,
	) {
		// Проверяем, находится ли метод в списке игнорируемых (например, /grpc.health.v1.Health/Check)
		if m.ignoreMethods.Contains(info.FullMethod) {
			return handler(ctx, req)
		}

		// Получаем политику метода
		policy, hasPolicy := m.getMethodPolicy()[info.FullMethod]
		if hasPolicy && policy.AllowUnauthenticated {
			return handler(ctx, req) // // Если метод размечен как публичный, сразу идем дальше
		}

		// Достаем идентификатор пользователя (актора) из контекста
		userID, ok := m.actorExtractor.FromContext(ctx)
		if !ok {
			return nil, m.notAuthorizedError
		}

		// Если политики нет или в ней не заданы требования по ролям - аутентификации достаточно, идем дальше
		if policy.Rule == nil {
			return handler(ctx, req)
		}

		// Запрашиваем роли пользователя через провайдер
		userRoles, err := m.roleProvider.ListRoles(ctx, userID)
		if err != nil {
			return nil, err
		}

		// Проверяем роли на соответствие булеву дереву правил
		if allow := policy.Rule.Evaluate(mapset.NewSet(userRoles...)); !allow {
			return nil, m.permissionDeniedError
		}

		// Роли соответствуют
		return handler(ctx, req)
	}
}

func (m *Authorizer[T]) getMethodPolicy() map[string]Policy {
	m.methodRulesOnce.Do(m.loadMethodPolicies)
	return m.methodPolicies
}

// loadMethodPolicies один раз рефлексией проходимся и сохраняем в память опции методов
func (m *Authorizer[T]) loadMethodPolicies() {
	files := protoregistry.GlobalFiles
	policiesMap := make(map[string]Policy)

	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		for i := 0; i < fd.Services().Len(); i++ {
			service := fd.Services().Get(i)

			for j := 0; j < service.Methods().Len(); j++ {
				method := service.Methods().Get(j)
				fullMethodName := fmt.Sprintf("/%s/%s", service.FullName(), method.Name())

				options := method.Options().(*descriptorpb.MethodOptions)
				if options == nil || !proto.HasExtension(options, m.policyExtension) {
					continue
				}

				extension := proto.GetExtension(options, m.policyExtension)
				if policy, ok := extension.(*pb.Policy); ok {
					policiesMap[fullMethodName] = PolicyToModel(policy)
				}
			}
		}

		return true
	})

	m.methodPolicies = policiesMap
	m.logger.Debug("loaded methods policies", slog.Int("count", len(policiesMap)))
}
