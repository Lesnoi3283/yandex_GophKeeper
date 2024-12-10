package grpchandlers

import (
	"GophKeeper/internal/app/gRPC/proto"
	"GophKeeper/internal/app/required_interfaces"
	"go.uber.org/zap"
)

type GophKeeperServer struct {
	proto.UnimplementedGophKeeperServiceServer

	storage            required_interfaces.Storage
	keyKeeper          required_interfaces.KeyKeeper
	logger             *zap.SugaredLogger
	encryptionRWFabric required_interfaces.EncryptionWriterReaderFabric
	// maxBinDataChunkSize - in bytes.
	maxBinDataChunkSize int
}

func NewGophKeeperServer(
	storage required_interfaces.Storage, keeper required_interfaces.KeyKeeper,
	logger *zap.SugaredLogger, encryptionRWFabric required_interfaces.EncryptionWriterReaderFabric,
	maxBinDataChunkSize int) *GophKeeperServer {
	return &GophKeeperServer{
		storage:             storage,
		keyKeeper:           keeper,
		encryptionRWFabric:  encryptionRWFabric,
		maxBinDataChunkSize: maxBinDataChunkSize,
		logger:              logger,
	}
}
