package grpchandlers

import (
	"GophKeeper/internal/app/gRPC/interceptors"
	"GophKeeper/internal/app/gRPC/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"io"
)

//todo: создать EncryptionWriter, EncryptionReader, и EncryptionFileFabric.
// EncryptionWriter будет использовать ChaCha20-Poly1305 и записывать в переданный ему в конструкторе файл чанки байт
// (шифруя по переданному ему ключу). Write.
// EncryptionFileFabric будет иметь единственную функцию CreateNewEncryptionWriter и создавать EncryptionFileFabric
// (аналогично с ридером). Файл и ключ шифрования передаются в функцию фабрики и хранятся в полях райтера и ридера.
// У райтера должны быть фукнции write и read соответственно, должны соответствовать интерфейсу io.Reader и io.Writer.

// SaveBinData encrypts and saves a bin data into a file.
func (s *GophKeeperServer) SaveBinData(stream proto.GophKeeperService_SaveBinDataServer) (*emptypb.Empty, error) {
	//get userID
	userID := stream.Context().Value(interceptors.ContextUserIDKey)
	if userID == nil {
		s.logger.Debug("no userID in context")
		return nil, status.Error(codes.Unauthenticated, "Authentication required")
	}
	userIDInt, ok := userID.(int64)
	if !ok {
		s.logger.Error("userID not int")
		return nil, status.Error(codes.Internal, "Internal server error")
	}

	//create file

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			//todo: завершить сохранение файла и вернуть ответ
		}
		if err != nil {
			s.logger.Errorf("error while reading stream, err: %v", err)
			return nil, status.Error(codes.Internal, "Internal server error")
		}

		if len(req.DataName) > 0 {
			//first request, we should create a file.
		}
	}

}
