package interceptors

import (
	"GophKeeper/internal/app/required_interfaces"
	secureerrors "GophKeeper/pkg/secure/secureerrors"
	"context"
	"errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"strconv"
)

type UserIDKey string

const ContextUserIDKey UserIDKey = "userID"
const mdJWTKey = "jwt"

func AuthInterceptor(logger *zap.SugaredLogger, JWTHelper required_interfaces.JWTHelper) grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := stream.Context()

		// Get JWT from metadata
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			logger.Debugf("metadata wasn't found")
			return status.Errorf(codes.Unauthenticated, "metadata is not provided. JWT required")
		}
		jwts := md.Get(mdJWTKey)
		if len(jwts) == 0 {
			logger.Debugf("JWT wasn't found")
			return status.Errorf(codes.Unauthenticated, "JWT is missing in metadata")
		}

		// Parse JWT
		userID, err := JWTHelper.GetUserID(jwts[0])
		if errors.Is(err, secureerrors.NewErrorJWTIsNotValid()) {
			logger.Debug("token is not valid")
			return status.Errorf(codes.Unauthenticated, "token is not valid")
		} else if err != nil {
			logger.Debugf("JWT parsing error: %v", err)
			return status.Errorf(codes.Unauthenticated, "bad JWT")
		}

		// CreateUser a new context with the user ID
		newCtx := context.WithValue(ctx, ContextUserIDKey, strconv.Itoa(userID))

		// Wrap the stream to inject the new context
		wrappedStream := &wrappedServerStream{
			ServerStream: stream,
			ctx:          newCtx,
		}

		return handler(srv, wrappedStream)
	}
}

// wrappedServerStream is necessary to override the Context function.
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context func returns a context.
func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}
