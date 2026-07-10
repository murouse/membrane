package authorization

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	ErrPermissionDenied = status.New(codes.PermissionDenied, "permission denied").Err()
	ErrNotAuthorized    = status.New(codes.Unauthenticated, "not authorized").Err()
)
