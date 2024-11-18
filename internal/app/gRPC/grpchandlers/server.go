package grpchandlers

import (
	"GophKeeper/internal/app/gRPC/proto"
	"GophKeeper/internal/app/requiredInterfaces"
	"go.uber.org/zap"
)

type GophKeeperServer struct {
	proto.UnimplementedGophKeeperServiceServer

	storage   requiredInterfaces.Storage
	keyKeeper requiredInterfaces.KeyKeeper
	logger    zap.SugaredLogger
}
