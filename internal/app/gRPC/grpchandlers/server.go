package grpchandlers

import (
	"GophKeeper/internal/app/gRPC/proto"
	"GophKeeper/internal/app/requiredInterfaces"
	"go.uber.org/zap"
)

type GophKeeperServer struct {
	proto.UnimplementedGophKeeperServiceServer

	storage            requiredInterfaces.Storage
	keyKeeper          requiredInterfaces.KeyKeeper
	logger             *zap.SugaredLogger
	encryptionRWFabric requiredInterfaces.EncryptionWriterReaderFabric
	// maxBinDataChunkSize - in bytes.
	maxBinDataChunkSize int
}

func NewGophKeeperServer(
	storage requiredInterfaces.Storage, keeper requiredInterfaces.KeyKeeper,
	logger *zap.SugaredLogger, encryptionRWFabric requiredInterfaces.EncryptionWriterReaderFabric,
	maxBinDataChunkSize int) *GophKeeperServer {
	return &GophKeeperServer{
		storage:             storage,
		keyKeeper:           keeper,
		encryptionRWFabric:  encryptionRWFabric,
		maxBinDataChunkSize: maxBinDataChunkSize,
		logger:              logger,
	}
}
